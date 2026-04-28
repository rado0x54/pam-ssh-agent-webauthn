//! Integration test: full WebAuthn roundtrip with a mock SSH agent.
//!
//! Creates a mock agent that listens on a Unix socket, serves a WebAuthn SK key,
//! and produces valid WebAuthn ECDSA signatures. Verifies the full authenticate flow.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use p256::ecdsa::{signature::Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const TEST_KEY_BYTES: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    0x1f, 0x20,
];
const APPLICATION: &str = "https://shellwatch.example.com";
const WEBAUTHN_SK_ALGO: &str = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Build the WebAuthn SK key blob in SSH wire format.
fn make_webauthn_key_blob(signing_key: &SigningKey) -> Vec<u8> {
    let verifying_key = signing_key.verifying_key();
    let ec_point = verifying_key.to_encoded_point(false);
    let ec_bytes = ec_point.as_bytes();

    let mut blob = Vec::new();
    write_ssh_string(&mut blob, WEBAUTHN_SK_ALGO.as_bytes());
    write_ssh_string(&mut blob, b"nistp256");
    write_ssh_string(&mut blob, ec_bytes);
    write_ssh_string(&mut blob, APPLICATION.as_bytes());
    blob
}

/// Build a WebAuthn-style SSH signature blob with the default flags
/// (UP + UV set). Convenience wrapper over [`build_webauthn_signature_with_flags`].
fn build_webauthn_signature(signing_key: &SigningKey, challenge: &[u8]) -> Vec<u8> {
    build_webauthn_signature_with_flags(signing_key, challenge, 0x05)
}

/// Build a WebAuthn-style SSH signature blob with explicit authenticator
/// flags. Used by the UV-enforcement tests to produce a UP-only (no UV)
/// signature without disturbing the other tests' assumptions.
fn build_webauthn_signature_with_flags(
    signing_key: &SigningKey,
    challenge: &[u8],
    flags: u8,
) -> Vec<u8> {
    let counter: u32 = 42;

    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64}","origin":"{APPLICATION}","crossOrigin":false}}"#
    );

    let extensions: &[u8] = &[];

    // signed_data = SHA256(application) || flags || counter || extensions || SHA256(clientDataJSON)
    let app_hash = Sha256::digest(APPLICATION.as_bytes());
    let msg_hash = Sha256::digest(client_data_json.as_bytes());

    let mut signed_data = Vec::with_capacity(32 + 1 + 4 + 32);
    signed_data.extend(&app_hash);
    signed_data.push(flags);
    signed_data.extend(&counter.to_be_bytes());
    signed_data.extend(extensions);
    signed_data.extend(&msg_hash);

    let ecdsa_sig: p256::ecdsa::Signature = signing_key.sign(&signed_data);
    let (r, s) = ecdsa_sig.split_bytes();

    let mut ecdsa_blob = Vec::new();
    write_ssh_mpint(&mut ecdsa_blob, &r);
    write_ssh_mpint(&mut ecdsa_blob, &s);

    let algo = b"sk-ecdsa-sha2-nistp256@openssh.com";

    let mut blob = Vec::new();
    write_ssh_string(&mut blob, algo);
    write_ssh_string(&mut blob, &ecdsa_blob);
    blob.push(flags);
    blob.extend(&counter.to_be_bytes());
    write_ssh_string(&mut blob, APPLICATION.as_bytes());
    write_ssh_string(&mut blob, client_data_json.as_bytes());
    write_ssh_string(&mut blob, extensions);

    blob
}

/// Mock SSH agent that serves WebAuthn SK keys.
fn run_mock_agent(
    listener: UnixListener,
    signing_key: SigningKey,
    key_blob: Vec<u8>,
    stop: Arc<AtomicBool>,
    corrupt_challenge: bool,
) {
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking failed");

    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();

                // Read request
                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).is_err() {
                    continue;
                }
                let msg_len = u32::from_be_bytes(len_buf) as usize;
                let mut msg = vec![0u8; msg_len];
                if stream.read_exact(&mut msg).is_err() {
                    continue;
                }

                match msg[0] {
                    SSH_AGENTC_REQUEST_IDENTITIES => {
                        // Build IDENTITIES_ANSWER
                        let mut response = Vec::new();
                        response.push(SSH_AGENT_IDENTITIES_ANSWER);
                        response.extend(&1u32.to_be_bytes()); // nkeys = 1
                        write_ssh_string(&mut response, &key_blob);
                        write_ssh_string(&mut response, b"test-webauthn-key");

                        let len = (response.len() as u32).to_be_bytes();
                        stream.write_all(&len).unwrap();
                        stream.write_all(&response).unwrap();
                        stream.flush().unwrap();
                    }
                    SSH_AGENTC_SIGN_REQUEST => {
                        // Parse: key_blob_len + key_blob + data_len + data + flags
                        let mut reader: &[u8] = &msg[1..];
                        let _key = read_ssh_bytes(&mut reader);
                        let data = read_ssh_bytes(&mut reader).unwrap_or(b"");

                        let challenge = if corrupt_challenge {
                            b"wrong-challenge-data".as_slice()
                        } else {
                            data
                        };
                        let sig_blob = build_webauthn_signature(&signing_key, challenge);

                        // Build SIGN_RESPONSE
                        let mut response = Vec::new();
                        response.push(SSH_AGENT_SIGN_RESPONSE);
                        write_ssh_string(&mut response, &sig_blob);

                        let len = (response.len() as u32).to_be_bytes();
                        stream.write_all(&len).unwrap();
                        stream.write_all(&response).unwrap();
                        stream.flush().unwrap();
                    }
                    _ => {}
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

fn read_ssh_bytes<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    *buf = &buf[4..];
    if buf.len() < len {
        return None;
    }
    let data = &buf[..len];
    *buf = &buf[len..];
    Some(data)
}

fn write_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend(&(data.len() as u32).to_be_bytes());
    buf.extend(data);
}

fn write_ssh_mpint(buf: &mut Vec<u8>, data: &[u8]) {
    let data = match data.iter().position(|&b| b != 0) {
        Some(pos) => &data[pos..],
        None => &[0u8],
    };
    if !data.is_empty() && data[0] & 0x80 != 0 {
        buf.extend(&((data.len() + 1) as u32).to_be_bytes());
        buf.push(0);
    } else {
        buf.extend(&(data.len() as u32).to_be_bytes());
    }
    buf.extend(data);
}

struct TestSetup {
    socket_path: PathBuf,
    key_file: PathBuf,
    stop: Arc<AtomicBool>,
    _thread: std::thread::JoinHandle<()>,
}

impl Drop for TestSetup {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = std::fs::remove_file(&self.socket_path);
        let _ = std::fs::remove_file(&self.key_file);
    }
}

static TEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn setup(corrupt_challenge: bool) -> TestSetup {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let signing_key =
        SigningKey::from_bytes(&TEST_KEY_BYTES.into()).expect("Failed to create signing key");
    let key_blob = make_webauthn_key_blob(&signing_key);

    // Write authorized_keys file
    let key_file = std::env::temp_dir().join(format!(
        "pam_webauthn_test_keys_{}_{id}.pub",
        std::process::id()
    ));
    let b64 = BASE64_STANDARD.encode(&key_blob);
    let key_line = format!("{WEBAUTHN_SK_ALGO} {b64} test-key\n");
    std::fs::write(&key_file, &key_line).unwrap();

    // Start mock agent
    let socket_path = std::env::temp_dir().join(format!(
        "pam_webauthn_test_agent_{}_{id}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    let thread = std::thread::spawn(move || {
        run_mock_agent(listener, signing_key, key_blob, stop_clone, corrupt_challenge);
    });

    // Give agent time to start
    std::thread::sleep(std::time::Duration::from_millis(50));

    TestSetup {
        socket_path,
        key_file,
        stop,
        _thread: thread,
    }
}

#[test]
fn test_webauthn_roundtrip() {
    let setup = setup(false);

    let result = pam_ssh_agent_webauthn::authenticate(&setup.socket_path, &setup.key_file);
    assert!(result.is_ok(), "authenticate should succeed: {result:?}");
    assert!(result.unwrap(), "should return true for valid key");
}

#[test]
fn test_webauthn_wrong_challenge() {
    let setup = setup(true);

    // With multi-key iteration, a key whose signature fails verification is
    // treated as "this key didn't authenticate" and the loop continues. Here
    // we only have one matching key, so all matches are exhausted and we get
    // Ok(false) — auth failed, but cleanly (so PAM falls through to the next
    // module rather than reporting a service error).
    let result = pam_ssh_agent_webauthn::authenticate(&setup.socket_path, &setup.key_file);
    assert!(matches!(result, Ok(false)), "expected Ok(false), got {result:?}");
}

/// Mock SSH agent that serves two WebAuthn keys; signing the first always
/// returns SSH_AGENT_FAILURE (simulating a user-denied prompt), signing the
/// second returns a valid signature. Used to verify that the PAM module
/// iterates past a denied key instead of giving up after the first match.
fn run_skip_first_agent(
    listener: UnixListener,
    fail_key_blob: Vec<u8>,
    succeed_signing_key: SigningKey,
    succeed_key_blob: Vec<u8>,
    sign_count: Arc<std::sync::atomic::AtomicUsize>,
    stop: Arc<AtomicBool>,
) {
    listener.set_nonblocking(true).expect("set_nonblocking failed");

    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();

                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).is_err() {
                    continue;
                }
                let msg_len = u32::from_be_bytes(len_buf) as usize;
                let mut msg = vec![0u8; msg_len];
                if stream.read_exact(&mut msg).is_err() {
                    continue;
                }

                match msg[0] {
                    SSH_AGENTC_REQUEST_IDENTITIES => {
                        let mut response = Vec::new();
                        response.push(SSH_AGENT_IDENTITIES_ANSWER);
                        response.extend(&2u32.to_be_bytes());
                        write_ssh_string(&mut response, &fail_key_blob);
                        write_ssh_string(&mut response, b"deny-key");
                        write_ssh_string(&mut response, &succeed_key_blob);
                        write_ssh_string(&mut response, b"allow-key");

                        let len = (response.len() as u32).to_be_bytes();
                        stream.write_all(&len).unwrap();
                        stream.write_all(&response).unwrap();
                        stream.flush().unwrap();
                    }
                    SSH_AGENTC_SIGN_REQUEST => {
                        sign_count.fetch_add(1, Ordering::Relaxed);
                        let mut reader: &[u8] = &msg[1..];
                        let requested_key = read_ssh_bytes(&mut reader).unwrap_or(b"");
                        let data = read_ssh_bytes(&mut reader).unwrap_or(b"");

                        let response = if requested_key == fail_key_blob.as_slice() {
                            // Simulate user-denied prompt → SSH_AGENT_FAILURE
                            vec![5u8] // SSH_AGENT_FAILURE
                        } else {
                            let sig_blob = build_webauthn_signature(&succeed_signing_key, data);
                            let mut r = Vec::new();
                            r.push(SSH_AGENT_SIGN_RESPONSE);
                            write_ssh_string(&mut r, &sig_blob);
                            r
                        };

                        let len = (response.len() as u32).to_be_bytes();
                        stream.write_all(&len).unwrap();
                        stream.write_all(&response).unwrap();
                        stream.flush().unwrap();
                    }
                    _ => {}
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

#[test]
fn test_skip_failing_key_then_succeed() {
    // Two keys both authorized; the first returns SSH_AGENT_FAILURE on sign
    // (user denied), the second signs successfully. PAM should iterate past
    // the failed key and authenticate via the second. Regression for the
    // case where pam_ssh_agent_webauthn previously returned PAM_AUTH_ERR after the
    // first matching key failed to sign. See ShellWatch #91.
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);

    let fail_key = SigningKey::from_bytes(&TEST_KEY_BYTES.into()).unwrap();
    let fail_blob = make_webauthn_key_blob(&fail_key);

    let succeed_key_bytes: [u8; 32] = [
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e,
        0x5f, 0x60,
    ];
    let succeed_key = SigningKey::from_bytes(&succeed_key_bytes.into()).unwrap();
    let succeed_blob = make_webauthn_key_blob(&succeed_key);

    let key_file = std::env::temp_dir().join(format!(
        "pam_webauthn_test_multi_keys_{}_{id}.pub",
        std::process::id()
    ));
    let line1 = format!("{WEBAUTHN_SK_ALGO} {} deny-key\n", BASE64_STANDARD.encode(&fail_blob));
    let line2 = format!("{WEBAUTHN_SK_ALGO} {} allow-key\n", BASE64_STANDARD.encode(&succeed_blob));
    std::fs::write(&key_file, format!("{line1}{line2}")).unwrap();

    let socket_path = std::env::temp_dir().join(format!(
        "pam_webauthn_test_multi_agent_{}_{id}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    let fail_blob_clone = fail_blob.clone();
    let succeed_blob_clone = succeed_blob.clone();
    let sign_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sign_count_clone = sign_count.clone();
    let thread = std::thread::spawn(move || {
        run_skip_first_agent(listener, fail_blob_clone, succeed_key, succeed_blob_clone, sign_count_clone, stop_clone);
    });
    std::thread::sleep(std::time::Duration::from_millis(50));

    let result = pam_ssh_agent_webauthn::authenticate(&socket_path, &key_file);

    stop.store(true, Ordering::Relaxed);
    let _ = thread.join();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&key_file);

    assert!(matches!(result, Ok(true)), "expected Ok(true), got {result:?}");
    assert_eq!(
        sign_count.load(Ordering::Relaxed),
        2,
        "expected 2 sign requests (1 denied + 1 accepted)"
    );
}

#[test]
fn test_transport_error_bubbles_up() {
    // The agent socket doesn't exist. Transport-level failures (broken
    // socket, malformed reply, etc.) must surface as Err instead of being
    // silently converted to Ok(false) — otherwise operators can't tell
    // "agent is down" from "no key matched." See review of #91.
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let bogus_socket = std::env::temp_dir().join(format!(
        "pam_webauthn_test_nonexistent_{}_{id}.sock",
        std::process::id()
    ));
    // Build a valid authorized_keys file so the code reaches the agent step.
    let signing_key = SigningKey::from_bytes(&TEST_KEY_BYTES.into()).unwrap();
    let key_blob = make_webauthn_key_blob(&signing_key);
    let key_file = std::env::temp_dir().join(format!(
        "pam_webauthn_test_transport_keys_{}_{id}.pub",
        std::process::id()
    ));
    let line = format!("{WEBAUTHN_SK_ALGO} {} test-key\n", BASE64_STANDARD.encode(&key_blob));
    std::fs::write(&key_file, &line).unwrap();

    let result = pam_ssh_agent_webauthn::authenticate(&bogus_socket, &key_file);
    let _ = std::fs::remove_file(&key_file);

    assert!(result.is_err(), "expected transport Err, got {result:?}");
}

#[test]
fn test_no_matching_key() {
    let setup = setup(false);

    // Write a different key to the authorized_keys file
    let other_key_bytes: [u8; 32] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
        0x3d, 0x3e, 0x3f, 0x40,
    ];
    let other_signing_key = SigningKey::from_bytes(&other_key_bytes.into()).unwrap();
    let other_blob = make_webauthn_key_blob(&other_signing_key);
    let b64 = BASE64_STANDARD.encode(&other_blob);
    let key_line = format!("{WEBAUTHN_SK_ALGO} {b64} other-key\n");
    std::fs::write(&setup.key_file, &key_line).unwrap();

    let result = pam_ssh_agent_webauthn::authenticate(&setup.socket_path, &setup.key_file);
    assert!(result.is_ok());
    assert!(!result.unwrap(), "should return false when no key matches");
}

/// Mock agent that advertises two keys (both denying via SSH_AGENT_FAILURE)
/// and counts how many sign requests it has serviced.
fn run_counting_deny_agent(
    listener: UnixListener,
    key_blobs: Vec<Vec<u8>>,
    sign_count: Arc<std::sync::atomic::AtomicUsize>,
    stop: Arc<AtomicBool>,
) {
    listener.set_nonblocking(true).expect("set_nonblocking failed");

    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();

                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).is_err() {
                    continue;
                }
                let msg_len = u32::from_be_bytes(len_buf) as usize;
                let mut msg = vec![0u8; msg_len];
                if stream.read_exact(&mut msg).is_err() {
                    continue;
                }

                match msg[0] {
                    SSH_AGENTC_REQUEST_IDENTITIES => {
                        let mut response = Vec::new();
                        response.push(SSH_AGENT_IDENTITIES_ANSWER);
                        response.extend(&(key_blobs.len() as u32).to_be_bytes());
                        for (i, blob) in key_blobs.iter().enumerate() {
                            write_ssh_string(&mut response, blob);
                            let comment = format!("deny-key-{i}");
                            write_ssh_string(&mut response, comment.as_bytes());
                        }

                        let len = (response.len() as u32).to_be_bytes();
                        stream.write_all(&len).unwrap();
                        stream.write_all(&response).unwrap();
                        stream.flush().unwrap();
                    }
                    SSH_AGENTC_SIGN_REQUEST => {
                        sign_count.fetch_add(1, Ordering::Relaxed);
                        // Always refuse — we want to verify the cap stops the
                        // module from issuing more sign requests, not whether
                        // it picks the "right" key.
                        let response = vec![5u8]; // SSH_AGENT_FAILURE

                        let len = (response.len() as u32).to_be_bytes();
                        stream.write_all(&len).unwrap();
                        stream.write_all(&response).unwrap();
                        stream.flush().unwrap();
                    }
                    _ => {}
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

#[test]
fn test_max_attempts_caps_sign_requests() {
    // Two matching keys, both refusing. With cap=1 the module must stop after
    // a single sign request — the cap counts attempts (not just refusals), so
    // a hostile agent advertising N matching keys cannot force N touch
    // prompts. Mirrors OpenSSH MaxAuthTries semantics.
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);

    let key_a = SigningKey::from_bytes(&TEST_KEY_BYTES.into()).unwrap();
    let blob_a = make_webauthn_key_blob(&key_a);

    let key_b_bytes: [u8; 32] = [
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90,
    ];
    let key_b = SigningKey::from_bytes(&key_b_bytes.into()).unwrap();
    let blob_b = make_webauthn_key_blob(&key_b);

    let key_file = std::env::temp_dir().join(format!(
        "pam_webauthn_test_cap_keys_{}_{id}.pub",
        std::process::id()
    ));
    let line_a = format!("{WEBAUTHN_SK_ALGO} {} key-a\n", BASE64_STANDARD.encode(&blob_a));
    let line_b = format!("{WEBAUTHN_SK_ALGO} {} key-b\n", BASE64_STANDARD.encode(&blob_b));
    std::fs::write(&key_file, format!("{line_a}{line_b}")).unwrap();

    let socket_path = std::env::temp_dir().join(format!(
        "pam_webauthn_test_cap_agent_{}_{id}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let sign_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sign_count_clone = sign_count.clone();

    let blobs = vec![blob_a.clone(), blob_b.clone()];
    let thread = std::thread::spawn(move || {
        run_counting_deny_agent(listener, blobs, sign_count_clone, stop_clone);
    });
    std::thread::sleep(std::time::Duration::from_millis(50));

    let result = pam_ssh_agent_webauthn::authenticate_with_max_attempts(
        &socket_path,
        &key_file,
        1,
    );
    let observed = sign_count.load(Ordering::Relaxed);

    stop.store(true, Ordering::Relaxed);
    let _ = thread.join();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&key_file);

    assert!(matches!(result, Ok(false)), "expected Ok(false), got {result:?}");
    assert_eq!(observed, 1, "cap=1 must produce exactly 1 sign request, got {observed}");
}

#[test]
fn test_cap_not_hit_when_match_succeeds_within_limit() {
    // Two matching keys; the first is denied, the second signs successfully.
    // With cap=2 we still authenticate cleanly — the cap is a ceiling, not a
    // floor, and must not interfere with normal multi-key iteration.
    // Reuses run_skip_first_agent: first matched key returns SSH_AGENT_FAILURE,
    // second produces a valid signature.
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);

    let fail_key = SigningKey::from_bytes(&TEST_KEY_BYTES.into()).unwrap();
    let fail_blob = make_webauthn_key_blob(&fail_key);

    let succeed_key_bytes: [u8; 32] = [
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe,
        0xbf, 0xc0,
    ];
    let succeed_key = SigningKey::from_bytes(&succeed_key_bytes.into()).unwrap();
    let succeed_blob = make_webauthn_key_blob(&succeed_key);

    let key_file = std::env::temp_dir().join(format!(
        "pam_webauthn_test_cap_succeed_keys_{}_{id}.pub",
        std::process::id()
    ));
    let line1 = format!("{WEBAUTHN_SK_ALGO} {} deny-key\n", BASE64_STANDARD.encode(&fail_blob));
    let line2 = format!("{WEBAUTHN_SK_ALGO} {} allow-key\n", BASE64_STANDARD.encode(&succeed_blob));
    std::fs::write(&key_file, format!("{line1}{line2}")).unwrap();

    let socket_path = std::env::temp_dir().join(format!(
        "pam_webauthn_test_cap_succeed_agent_{}_{id}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    let fail_blob_clone = fail_blob.clone();
    let succeed_blob_clone = succeed_blob.clone();
    let sign_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sign_count_clone = sign_count.clone();
    let thread = std::thread::spawn(move || {
        run_skip_first_agent(listener, fail_blob_clone, succeed_key, succeed_blob_clone, sign_count_clone, stop_clone);
    });
    std::thread::sleep(std::time::Duration::from_millis(50));

    let result = pam_ssh_agent_webauthn::authenticate_with_max_attempts(
        &socket_path,
        &key_file,
        2,
    );

    stop.store(true, Ordering::Relaxed);
    let _ = thread.join();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&key_file);

    assert!(matches!(result, Ok(true)), "expected Ok(true), got {result:?}");
    assert_eq!(sign_count.load(Ordering::Relaxed), 2, "expected 2 sign requests");
}

#[test]
fn test_cap_blocks_otherwise_succeeding_key() {
    // Two matched keys: the first is denied (SSH_AGENT_FAILURE), the second
    // *would* sign successfully if reached. With cap=1 the module must stop
    // after the denied first attempt — proving the cap is doing security
    // work (actively preventing an auth that would otherwise succeed) rather
    // than just shortening iteration over already-failing keys.
    //
    // This is the pathological case the cap is designed for: a hostile agent
    // controlling identity order can DoS a legitimate user at cap=1 by
    // fronting a non-signing identity ahead of the real one. See the README
    // caveat on raising the cap above 1 if this pattern shows up in syslog.
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);

    let fail_key = SigningKey::from_bytes(&TEST_KEY_BYTES.into()).unwrap();
    let fail_blob = make_webauthn_key_blob(&fail_key);

    let succeed_key_bytes: [u8; 32] = [
        0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee,
        0xef, 0xf0,
    ];
    let succeed_key = SigningKey::from_bytes(&succeed_key_bytes.into()).unwrap();
    let succeed_blob = make_webauthn_key_blob(&succeed_key);

    let key_file = std::env::temp_dir().join(format!(
        "pam_webauthn_test_cap_blocks_keys_{}_{id}.pub",
        std::process::id()
    ));
    let line1 = format!("{WEBAUTHN_SK_ALGO} {} deny-key\n", BASE64_STANDARD.encode(&fail_blob));
    let line2 = format!("{WEBAUTHN_SK_ALGO} {} allow-key\n", BASE64_STANDARD.encode(&succeed_blob));
    std::fs::write(&key_file, format!("{line1}{line2}")).unwrap();

    let socket_path = std::env::temp_dir().join(format!(
        "pam_webauthn_test_cap_blocks_agent_{}_{id}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let sign_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sign_count_clone = sign_count.clone();

    let fail_blob_clone = fail_blob.clone();
    let succeed_blob_clone = succeed_blob.clone();
    let thread = std::thread::spawn(move || {
        run_skip_first_agent(listener, fail_blob_clone, succeed_key, succeed_blob_clone, sign_count_clone, stop_clone);
    });
    std::thread::sleep(std::time::Duration::from_millis(50));

    let result = pam_ssh_agent_webauthn::authenticate_with_max_attempts(
        &socket_path,
        &key_file,
        1,
    );
    let observed = sign_count.load(Ordering::Relaxed);

    stop.store(true, Ordering::Relaxed);
    let _ = thread.join();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&key_file);

    assert!(matches!(result, Ok(false)), "expected Ok(false), got {result:?}");
    assert_eq!(
        observed, 1,
        "cap=1 must stop iteration after 1 sign request even though the second key would have signed; got {observed}"
    );
}

/// Mock agent that signs every request with `signing_flags` (typically
/// 0x01 — UP only, no UV). Used to drive the UV-enforcement tests:
/// regardless of what the policy demands, this agent never asserts UV.
fn run_fixed_flags_agent(
    listener: UnixListener,
    signing_key: SigningKey,
    key_blob: Vec<u8>,
    signing_flags: u8,
    sign_count: Arc<std::sync::atomic::AtomicUsize>,
    stop: Arc<AtomicBool>,
) {
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking failed");

    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();

                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).is_err() {
                    continue;
                }
                let msg_len = u32::from_be_bytes(len_buf) as usize;
                let mut msg = vec![0u8; msg_len];
                if stream.read_exact(&mut msg).is_err() {
                    continue;
                }

                match msg[0] {
                    SSH_AGENTC_REQUEST_IDENTITIES => {
                        let mut response = Vec::new();
                        response.push(SSH_AGENT_IDENTITIES_ANSWER);
                        response.extend(&1u32.to_be_bytes());
                        write_ssh_string(&mut response, &key_blob);
                        write_ssh_string(&mut response, b"uv-test-key");

                        let len = (response.len() as u32).to_be_bytes();
                        stream.write_all(&len).unwrap();
                        stream.write_all(&response).unwrap();
                        stream.flush().unwrap();
                    }
                    SSH_AGENTC_SIGN_REQUEST => {
                        sign_count.fetch_add(1, Ordering::Relaxed);
                        let mut reader: &[u8] = &msg[1..];
                        let _key = read_ssh_bytes(&mut reader);
                        let data = read_ssh_bytes(&mut reader).unwrap_or(b"");
                        let sig_blob = build_webauthn_signature_with_flags(
                            &signing_key,
                            data,
                            signing_flags,
                        );

                        let mut response = Vec::new();
                        response.push(SSH_AGENT_SIGN_RESPONSE);
                        write_ssh_string(&mut response, &sig_blob);

                        let len = (response.len() as u32).to_be_bytes();
                        stream.write_all(&len).unwrap();
                        stream.write_all(&response).unwrap();
                        stream.flush().unwrap();
                    }
                    _ => {}
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

/// Builds the scaffolding for a UV-enforcement test: an agent that signs
/// with `signing_flags`, plus an `authorized_keys` file written from
/// `key_options` (the leading options block, comma-separated, OpenSSH-
/// canonical form — empty string for "no options"). Returns the paths,
/// the sign-count, and the join handle.
fn setup_uv_test(
    signing_flags: u8,
    key_options: &str,
) -> (
    PathBuf,
    PathBuf,
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);

    let signing_key = SigningKey::from_bytes(&TEST_KEY_BYTES.into()).unwrap();
    let key_blob = make_webauthn_key_blob(&signing_key);

    let key_file = std::env::temp_dir().join(format!(
        "pam_webauthn_test_uv_keys_{}_{id}.pub",
        std::process::id()
    ));
    let b64 = BASE64_STANDARD.encode(&key_blob);
    let line = if key_options.is_empty() {
        format!("{WEBAUTHN_SK_ALGO} {b64} uv-test-key\n")
    } else {
        format!("{key_options} {WEBAUTHN_SK_ALGO} {b64} uv-test-key\n")
    };
    std::fs::write(&key_file, &line).unwrap();

    let socket_path = std::env::temp_dir().join(format!(
        "pam_webauthn_test_uv_agent_{}_{id}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let sign_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sign_count_clone = sign_count.clone();
    let key_blob_clone = key_blob.clone();

    let thread = std::thread::spawn(move || {
        run_fixed_flags_agent(
            listener,
            signing_key,
            key_blob_clone,
            signing_flags,
            sign_count_clone,
            stop_clone,
        );
    });
    std::thread::sleep(std::time::Duration::from_millis(50));

    (socket_path, key_file, sign_count, stop, thread)
}

#[test]
fn test_uv_required_per_key_rejects_up_only_signature() {
    // End-to-end UV enforcement: the agent signs with flags=0x01 (UP only,
    // no UV bit). The authorized_keys line carries `verify-required`, so
    // validate_flags must reject the assertion. The module treats this as
    // "this key didn't authenticate" and exhausts matches → Ok(false).
    // Locks in the OR-combine wiring at the integration level: the per-key
    // option flows from authorized_keys → WebAuthnPublicKey.verify_required
    // → try_authenticate's merged uv_required → validate_flags.
    let (socket_path, key_file, sign_count, stop, thread) =
        setup_uv_test(0x01, "verify-required");

    let result = pam_ssh_agent_webauthn::authenticate(&socket_path, &key_file);
    let observed = sign_count.load(Ordering::Relaxed);

    stop.store(true, Ordering::Relaxed);
    let _ = thread.join();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&key_file);

    assert!(
        matches!(result, Ok(false)),
        "expected Ok(false) when UV-required key meets a UP-only signature, got {result:?}"
    );
    assert_eq!(
        observed, 1,
        "agent should have been asked to sign exactly once before UV verification rejected the result"
    );
}

#[test]
fn test_uv_not_required_default_accepts_up_only_signature() {
    // Positive control for the test above: same signature shape (UP only,
    // no UV), but no `verify-required` option on the key. Default policy
    // is permissive, so this MUST succeed. Without this control, the
    // negative test alone wouldn't prove the UV bit was the cause of
    // failure (could be agent setup, key blob mismatch, etc.).
    let (socket_path, key_file, sign_count, stop, thread) = setup_uv_test(0x01, "");

    let result = pam_ssh_agent_webauthn::authenticate(&socket_path, &key_file);
    let observed = sign_count.load(Ordering::Relaxed);

    stop.store(true, Ordering::Relaxed);
    let _ = thread.join();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&key_file);

    assert!(
        matches!(result, Ok(true)),
        "default-permissive UV policy must accept a UP-only signature, got {result:?}"
    );
    assert_eq!(observed, 1);
}

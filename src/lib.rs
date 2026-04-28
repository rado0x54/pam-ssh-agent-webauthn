//! pam_ssh_agent_webauthn — PAM module for WebAuthn passkey-protected sudo.
//!
//! Authenticates via a forwarded SSH agent that holds WebAuthn SK ECDSA keys.
//! Only supports `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`.
//!
//! ## PAM configuration
//!
//! ```text
//! auth sufficient pam_ssh_agent_webauthn.so file=/etc/security/authorized_keys
//! ```
//!
//! Module arguments:
//! * `file=PATH` — authorized_keys path (default `/etc/security/authorized_keys`).
//! * `socket=PATH` — override `$SSH_AUTH_SOCK`.
//! * `strict_modes=yes|no` — walk ancestor dir chain checking ownership and
//!   modes; default `yes`. Mirrors OpenSSH `StrictModes`.
//! * `max_attempts=N` — cap on sign requests issued per `pam_authenticate`
//!   call; default `6`. Mirrors OpenSSH `MaxAuthTries`. Bounds the user-
//!   visible touch prompts a hostile agent can force by advertising many
//!   identities whose blobs match `authorized_keys`.
//!
//! ## How it works
//!
//! 1. Reads authorized WebAuthn public keys from the configured file
//! 2. Connects to `$SSH_AUTH_SOCK` (forwarded through SSH)
//! 3. Lists agent identities, matches against authorized keys (raw blob comparison)
//! 4. Generates a 32-byte random challenge
//! 5. Sends SIGN_REQUEST to agent with matched key blob
//! 6. Parses WebAuthn signature (origin, clientDataJSON, extensions)
//! 7. Validates challenge is embedded in clientDataJSON
//! 8. Constructs signed_data (incl. extensions), verifies ECDSA P-256 signature
//! 9. Returns PAM_SUCCESS or PAM_AUTH_ERR

pub mod agent;
pub mod authfile;
pub mod keys;
pub mod webauthn;

use log::{debug, error, info, warn};
use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use std::ffi::CStr;
use std::io;
use std::path::Path;

const CHALLENGE_SIZE: usize = 32;
const DEFAULT_KEY_FILE: &str = "/etc/security/authorized_keys";
/// Default cap on sign requests issued per authenticate call. Mirrors
/// OpenSSH's `MaxAuthTries` default. Bounds the touch prompts a hostile
/// agent can force by advertising many identities whose blobs match
/// `authorized_keys`. Tunable per PAM config via `max_attempts=N`.
const DEFAULT_MAX_SIGN_ATTEMPTS: usize = 6;

struct PamSshWebauthn;
pam::pam_hooks!(PamSshWebauthn);

impl PamHooks for PamSshWebauthn {
    fn sm_authenticate(handle: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        init_logging();

        let config = match parse_args(&args) {
            Ok(c) => c,
            Err(e) => {
                error!("pam_ssh_agent_webauthn: invalid config: {e}");
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        match do_authenticate(&config, handle) {
            Ok(()) => {
                info!("pam_ssh_agent_webauthn: authentication successful");
                PamResultCode::PAM_SUCCESS
            }
            Err(e) => {
                let code = e.pam_code();
                // Service errors and UserUnknown get error!; everything else
                // is info!. The distinction matters because admins triaging
                // a syslog stream should see broken-config / malformed-
                // protocol issues — and a calling app that failed to set
                // PAM_USER before pam_authenticate (UserUnknown) is the same
                // class of "module was called wrong" — separately from the
                // expected "user denied the touch" / "no agent forwarded"
                // events.
                if matches!(e, AuthError::Service(_) | AuthError::UserUnknown) {
                    error!("pam_ssh_agent_webauthn: {e}");
                } else {
                    info!("pam_ssh_agent_webauthn: {e}");
                }
                code
            }
        }
    }

    fn sm_setcred(_handle: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        // This module performs authentication only; it issues no credential
        // material (no Kerberos tickets, AFS tokens, session keyrings, etc.)
        // and does not manage uid/gid context — that is the calling
        // application's job. So sm_setcred is genuinely a no-op for us.
        //
        // The strictly-correct return for a no-op setcred would be PAM_IGNORE,
        // but doas treats anything other than PAM_SUCCESS as failure and emits
        // `doas: pam_setcred(?, PAM_REINITIALIZE_CRED): Permission denied`.
        // Returning SUCCESS interoperates with sudo, login, sshd, and doas
        // alike. Other auth-only modules (pam_google_authenticator, upstream
        // pam-ssh-agent) make the same choice for the same reason.
        PamResultCode::PAM_SUCCESS
    }
}

/// Categorizes auth failures by the PAM return code they should map to.
/// The discrimination matters for PAM stacks composed with
/// `[success=done default=ignore]` and similar patterns: admins need to
/// distinguish "this module is broken" from "this user isn't authorized"
/// from "this module needs information it doesn't have."
#[derive(Debug)]
enum AuthError {
    /// Module is misconfigured or saw a corrupted protocol message.
    /// Maps to `PAM_SERVICE_ERR`.
    Service(String),
    /// Information needed to authenticate isn't available — no agent
    /// socket, no keys configured, agent unreachable. The module itself
    /// is fine; PAM stacks should be able to fall through cleanly.
    /// Maps to `PAM_AUTHINFO_UNAVAIL`.
    InfoUnavailable(String),
    /// User genuinely failed to prove possession (no matching key,
    /// signature didn't verify, user denied the touch prompt).
    /// Maps to `PAM_AUTH_ERR`.
    AuthFail(String),
    /// PAM did not supply the user identity. Maps to `PAM_USER_UNKNOWN`.
    UserUnknown,
}

impl AuthError {
    fn pam_code(&self) -> PamResultCode {
        match self {
            Self::Service(_) => PamResultCode::PAM_SERVICE_ERR,
            Self::InfoUnavailable(_) => PamResultCode::PAM_AUTHINFO_UNAVAIL,
            Self::AuthFail(_) => PamResultCode::PAM_AUTH_ERR,
            Self::UserUnknown => PamResultCode::PAM_USER_UNKNOWN,
        }
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Service(msg) => write!(f, "service error: {msg}"),
            Self::InfoUnavailable(msg) => write!(f, "auth info unavailable: {msg}"),
            Self::AuthFail(msg) => write!(f, "authentication failed: {msg}"),
            Self::UserUnknown => write!(f, "PAM did not supply user identity"),
        }
    }
}

/// Classify an `io::Error` from the agent path into an `AuthError`.
/// `InvalidData` indicates a malformed wire-format response (the agent
/// is broken, not unreachable); everything else is treated as a transport
/// problem — `InfoUnavailable` so PAM stacks can fall through.
fn classify_io_err(e: io::Error, ctx: &str) -> AuthError {
    if e.kind() == io::ErrorKind::InvalidData {
        AuthError::Service(format!("{ctx}: malformed agent protocol: {e}"))
    } else {
        AuthError::InfoUnavailable(format!("{ctx}: {e}"))
    }
}

/// Classify an `authfile::OpenError` into an `AuthError`.
///
/// Most variants represent genuine misconfigurations (file owned by the
/// wrong user, world-writable, on a per-user mount point, etc.) and map to
/// `Service`. `Io` is delegated to `classify_io_err` so that benign cases
/// like `NotFound` (host has not been provisioned with any keys yet) and
/// `PermissionDenied` (e.g. an SELinux policy blocking the read) map to
/// `InfoUnavailable` and let PAM stacks compose with `default=ignore` /
/// `authinfo_unavail=ignore` cleanly. Without this, a missing
/// `authorized_keys` file would be a hard lockout under the README's
/// recommended stack.
fn classify_open_err(e: authfile::OpenError) -> AuthError {
    match e {
        authfile::OpenError::Io(io_err) => classify_io_err(io_err, "read authorized_keys"),
        other => AuthError::Service(format!("read authorized_keys: {other}")),
    }
}

#[derive(Debug)]
struct Config {
    key_file: String,
    socket_path: Option<String>,
    strict_modes: bool,
    max_attempts: usize,
}

fn parse_args(args: &[&CStr]) -> Result<Config, String> {
    let mut key_file = DEFAULT_KEY_FILE.to_string();
    let mut socket_path = None;
    let mut strict_modes = true;
    let mut max_attempts = DEFAULT_MAX_SIGN_ATTEMPTS;

    for arg in args {
        let s = arg.to_str().map_err(|e| format!("Invalid arg: {e}"))?;
        if let Some(path) = s.strip_prefix("file=") {
            key_file = path.to_string();
        } else if let Some(path) = s.strip_prefix("socket=") {
            socket_path = Some(path.to_string());
        } else if let Some(value) = s.strip_prefix("strict_modes=") {
            strict_modes = match value {
                "yes" | "true" | "1" => true,
                "no" | "false" | "0" => false,
                other => return Err(format!("Invalid strict_modes value: {other}")),
            };
        } else if let Some(value) = s.strip_prefix("max_attempts=") {
            // Reject 0 explicitly: a cap of 0 would never call the agent at
            // all, turning the module into an unconditional auth failure.
            // That's almost certainly a config mistake, so refuse it loudly
            // rather than silently locking everyone out.
            let n: usize = value
                .parse()
                .map_err(|_| format!("Invalid max_attempts value: {value}"))?;
            if n == 0 {
                return Err(format!("Invalid max_attempts value: {value} (must be >= 1)"));
            }
            max_attempts = n;
        } else {
            // Refuse unknown args rather than silently dropping them: a typo
            // like `strictmodes=no` instead of `strict_modes=no` would
            // otherwise leave the user thinking they had disabled a check.
            return Err(format!("Unknown argument: {s}"));
        }
    }

    Ok(Config {
        key_file,
        socket_path,
        strict_modes,
        max_attempts,
    })
}

/// Outcome of a single sign-and-verify attempt. Distinguishes soft failures
/// (try the next matching key) from hard failures (propagate).
enum TryAuthOutcome {
    /// Agent rejected the sign request — user denied the prompt, key not
    /// loaded, agent policy refused.
    Refused(String),
    /// Agent signed but the signature didn't verify under our public key.
    /// Try the next matching identity in case the agent presented the
    /// wrong key.
    VerifyFailed(String),
    /// Transport-level I/O failure or malformed agent reply.
    /// Caller maps via `classify_io_err` to either Service or InfoUnavailable.
    Transport(io::Error),
    /// Failed to generate a fresh random challenge — system entropy issue.
    /// Maps to Service.
    Random(String),
}

fn do_authenticate(config: &Config, handle: &mut PamHandle) -> Result<(), AuthError> {
    let user = handle
        .get_user(None)
        .map_err(|_| AuthError::UserUnknown)?;
    info!("pam_ssh_agent_webauthn: authenticating user '{user}'");

    // Read authorized_keys under the OpenSSH-style safety ladder:
    // refuse non-absolute paths, refuse user-writable roots, open with
    // O_NOFOLLOW|O_NONBLOCK, fstat for owner/mode, walk ancestor chain.
    let opts = authfile::Opts {
        strict_modes: config.strict_modes,
        ..Default::default()
    };
    let content = authfile::open_secure(Path::new(&config.key_file), &opts)
        .map_err(classify_open_err)?;
    let authorized_keys = keys::parse_authorized_keys_str(&content);
    if authorized_keys.is_empty() {
        // The file exists, passed all safety checks, but contains no WebAuthn
        // SK lines. Treat this the same as the file not existing at all:
        // there is no credential to verify against, but the module is fine.
        return Err(AuthError::InfoUnavailable(format!(
            "no WebAuthn keys found in {}",
            config.key_file
        )));
    }
    info!(
        "Loaded {} WebAuthn key(s) from {}",
        authorized_keys.len(),
        config.key_file
    );

    // Get SSH_AUTH_SOCK from config override or environment.
    //
    // Security note: this path is read from the unprivileged caller's
    // environment without ownership/symlink/socket-type validation. That is
    // intentional and matches OpenSSH's own behavior. The agent is only a
    // signing oracle — it can produce signatures, but only with private keys
    // it actually holds. Authorization is gated by the EC point + application
    // pinned in `authorized_keys` (see `keys.rs`), so an attacker pointing
    // this at a hostile agent cannot forge auth without already controlling a
    // key listed in the (root-owned) authorized_keys file. The trust root is
    // that file's integrity, not this socket path.
    let socket_path = match &config.socket_path {
        Some(path) => path.clone(),
        None => std::env::var("SSH_AUTH_SOCK").map_err(|_| {
            AuthError::InfoUnavailable("SSH_AUTH_SOCK not set".into())
        })?,
    };
    let socket = Path::new(&socket_path);

    // List agent identities. An empty list is `InfoUnavailable` (the user
    // has not loaded their credential into ssh-agent — fall through cleanly)
    // rather than `AuthFail`. The asymmetry with the `tried == 0` case below
    // is deliberate: "no keys at all" is a missing precondition, while "keys
    // present but none match the authorized set" is a real authentication
    // failure ("you have the wrong credential for this server").
    let agent_identities = agent::list_webauthn_identities(socket)
        .map_err(|e| classify_io_err(e, "list agent identities"))?;
    if agent_identities.is_empty() {
        return Err(AuthError::InfoUnavailable(
            "no WebAuthn keys in agent".into(),
        ));
    }
    info!("Found {} WebAuthn key(s) in agent", agent_identities.len());

    // Materialize the set of (agent identity × authorized key) matches up
    // front so we can both enforce a cap on attempts and report the total
    // match count when the cap is hit. Both inputs are bounded (the agent
    // wire format caps the IDENTITIES_ANSWER message at 1 MiB, and
    // authorized_keys is a root-owned file), so this allocation is small.
    let matched = matched_pairs(&agent_identities, &authorized_keys);

    // Iterate matches in order, capped at config.max_attempts. A soft failure
    // on one key (user denied the prompt, signature invalid, agent returned
    // SSH_AGENT_FAILURE) is logged and skipped — only a transport/protocol
    // failure or hitting the cap / exhausting matches produces an Err.
    // Mirrors standard ssh-client behavior of trying each available identity,
    // with a cap analogous to OpenSSH's MaxAuthTries.
    let cap = config.max_attempts;
    match iter_attempts(socket, &matched, cap)? {
        AttemptOutcome::Succeeded => Ok(()),
        AttemptOutcome::CapHit { tried } => {
            // A hostile agent advertising N>cap identities matching
            // authorized_keys would otherwise force N user-presence prompts;
            // record what we saw so operators can spot the pattern in syslog.
            warn!(
                "pam_ssh_agent_webauthn: sign-attempt cap reached: \
                 agent_identities={}, matched_pairs={}, attempts={}",
                agent_identities.len(),
                matched.len(),
                tried
            );
            Err(AuthError::AuthFail(format!(
                "sign-attempt cap of {cap} reached; tried {tried} of {} match(es)",
                matched.len()
            )))
        }
        // Both branches are AuthFail: the agent presented WebAuthn keys but
        // the user could not (or chose not to) prove possession of one that's
        // listed in authorized_keys. Contrast with the empty-agent_identities
        // branch above, which is InfoUnavailable.
        AttemptOutcome::Exhausted { tried: 0 } => Err(AuthError::AuthFail(
            "no agent key matched authorized_keys".into(),
        )),
        AttemptOutcome::Exhausted { tried } => Err(AuthError::AuthFail(format!(
            "all {tried} matching key(s) failed to authenticate"
        ))),
    }
}

/// Build the cartesian product of (agent identity × authorized key) pairs
/// whose key blobs match exactly. Centralized so both the PAM hook path and
/// the bundled `authenticate` helper apply the same matching rule —
/// canonicalization changes (e.g. application-string normalization) only
/// need updating in one place.
fn matched_pairs<'a>(
    agent_identities: &'a [agent::AgentIdentity],
    authorized_keys: &'a [keys::WebAuthnPublicKey],
) -> Vec<(&'a agent::AgentIdentity, &'a keys::WebAuthnPublicKey)> {
    agent_identities
        .iter()
        .flat_map(|aid| {
            authorized_keys
                .iter()
                .filter(move |ak| ak.key_blob == aid.key_blob)
                .map(move |ak| (aid, ak))
        })
        .collect()
}

/// Outcome of iterating matched (agent ↔ authorized_keys) pairs up to a cap.
/// Encoded as an enum so the three terminal states (signed, cap reached,
/// matches exhausted) are mutually exclusive at the type level — the call
/// site reads as an exhaustive `match` rather than two sequential `if`s.
enum AttemptOutcome {
    /// One of the attempts produced a verified signature. The attempt count
    /// is not carried — the caller's only job on success is to return
    /// `PAM_SUCCESS` / `Ok(true)`, and no log message currently consumes it.
    Succeeded,
    /// Iteration stopped because the cap was reached before all matches
    /// could be tried.
    CapHit { tried: usize },
    /// Every available match was tried (or there were none); none succeeded.
    Exhausted { tried: usize },
}

/// Iterate matched pairs, sending sign requests until one succeeds, the cap
/// is reached, or the matches are exhausted. Transport / random-source
/// failures bubble up as `AuthError`.
fn iter_attempts(
    socket: &Path,
    matched: &[(&agent::AgentIdentity, &keys::WebAuthnPublicKey)],
    cap: usize,
) -> Result<AttemptOutcome, AuthError> {
    let mut tried = 0;
    for (agent_id, auth_key) in matched.iter() {
        if tried >= cap {
            return Ok(AttemptOutcome::CapHit { tried });
        }
        tried += 1;
        debug!(
            "Trying matched key: {} (app: {})",
            auth_key.comment, auth_key.application
        );
        match try_authenticate(socket, auth_key, &agent_id.key_blob) {
            Ok(()) => return Ok(AttemptOutcome::Succeeded),
            Err(TryAuthOutcome::Refused(msg)) => {
                warn!(
                    "pam_ssh_agent_webauthn: key '{}' refused, trying next: {msg}",
                    auth_key.comment
                );
            }
            Err(TryAuthOutcome::VerifyFailed(msg)) => {
                warn!(
                    "pam_ssh_agent_webauthn: key '{}' verification failed, trying next: {msg}",
                    auth_key.comment
                );
            }
            Err(TryAuthOutcome::Transport(e)) => {
                return Err(classify_io_err(
                    e,
                    &format!("agent sign for key '{}'", auth_key.comment),
                ));
            }
            Err(TryAuthOutcome::Random(msg)) => {
                return Err(AuthError::Service(format!(
                    "challenge generation: {msg}"
                )));
            }
        }
    }
    Ok(AttemptOutcome::Exhausted { tried })
}

fn try_authenticate(
    socket: &Path,
    key: &keys::WebAuthnPublicKey,
    key_blob: &[u8],
) -> Result<(), TryAuthOutcome> {
    // Generate random challenge
    let mut challenge = [0u8; CHALLENGE_SIZE];
    getrandom::fill(&mut challenge)
        .map_err(|e| TryAuthOutcome::Random(e.to_string()))?;

    // Sign via agent
    let raw_sig = match agent::sign_raw(socket, key_blob, &challenge) {
        Ok(sig) => sig,
        Err(agent::SignError::Refused(msg)) => {
            return Err(TryAuthOutcome::Refused(msg));
        }
        Err(agent::SignError::Transport(e)) => {
            return Err(TryAuthOutcome::Transport(e));
        }
    };

    // Verify WebAuthn signature
    webauthn::verify_webauthn_sk(key, &challenge, &raw_sig)
        .map_err(|e| TryAuthOutcome::VerifyFailed(e.to_string()))?;

    Ok(())
}

fn init_logging() {
    // Try syslog for production, fall back silently
    let _ = syslog::init(
        syslog::Facility::LOG_AUTH,
        log::LevelFilter::Info,
        Some("pam_ssh_agent_webauthn"),
    );
}

/// Standalone authentication helper for the bundled examples and integration
/// tests. **Not for production use.**
///
/// This function reads `key_file` directly with `fs::read_to_string` — it
/// **bypasses** the OpenSSH-style safety ladder applied by the PAM hook
/// (`authfile::open_secure`). That is deliberate: the integration tests use
/// scratch paths under `/tmp` that the ladder rejects on purpose. The PAM
/// entry point (`sm_authenticate`) is the only path that should ever run as
/// root, and it always goes through `open_secure`.
///
/// If you are embedding this crate outside the PAM hook, do not call this
/// function with attacker-influenceable paths. Use [`authfile::open_secure`]
/// + [`keys::parse_authorized_keys_str`] yourself.
///
/// `#[doc(hidden)]`: kept `pub` for the bundled examples and `tests/`
/// integration crate, but not part of the supported API surface.
#[doc(hidden)]
pub fn authenticate(
    socket_path: &Path,
    key_file: &Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    authenticate_with_max_attempts(socket_path, key_file, DEFAULT_MAX_SIGN_ATTEMPTS)
}

/// Like [`authenticate`] but with a caller-supplied cap on how many sign
/// requests are issued to the agent. Used by integration tests to exercise
/// the cap behavior; production callers should use the PAM hook, which
/// reads the cap from the `max_attempts=N` module argument.
///
/// Returns `Ok(false)` when the cap is hit without a successful signature.
///
/// `#[doc(hidden)]`: same caveat as [`authenticate`] — test helper, not
/// part of the supported API surface.
#[doc(hidden)]
pub fn authenticate_with_max_attempts(
    socket_path: &Path,
    key_file: &Path,
    max_attempts: usize,
) -> Result<bool, Box<dyn std::error::Error>> {
    if max_attempts == 0 {
        return Err("max_attempts must be >= 1".into());
    }
    let authorized_keys = keys::parse_authorized_keys(key_file)?;
    if authorized_keys.is_empty() {
        return Ok(false);
    }

    let agent_identities = agent::list_webauthn_identities(socket_path)?;
    if agent_identities.is_empty() {
        return Ok(false);
    }

    let matched = matched_pairs(&agent_identities, &authorized_keys);

    // See `do_authenticate` for the rationale behind iterating all matches.
    // Transport errors bubble up; protocol refusals / verification failures
    // fall through to the next match. Cap on attempts mirrors the PAM hook.
    for (agent_id, auth_key) in matched.iter().take(max_attempts) {
        match try_authenticate(socket_path, auth_key, &agent_id.key_blob) {
            Ok(()) => return Ok(true),
            Err(TryAuthOutcome::Transport(e)) => return Err(Box::new(e)),
            Err(TryAuthOutcome::Random(msg)) => return Err(msg.into()),
            Err(TryAuthOutcome::Refused(_)) | Err(TryAuthOutcome::VerifyFailed(_)) => continue,
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn cstrs(args: &[&str]) -> Vec<CString> {
        args.iter().map(|s| CString::new(*s).unwrap()).collect()
    }

    fn parse(args: &[&str]) -> Result<Config, String> {
        let owned = cstrs(args);
        let refs: Vec<&CStr> = owned.iter().map(|c| c.as_c_str()).collect();
        parse_args(&refs)
    }

    #[test]
    fn parse_args_defaults() {
        let cfg = parse(&[]).unwrap();
        assert_eq!(cfg.key_file, DEFAULT_KEY_FILE);
        assert!(cfg.socket_path.is_none());
        assert!(cfg.strict_modes);
        assert_eq!(cfg.max_attempts, DEFAULT_MAX_SIGN_ATTEMPTS);
    }

    #[test]
    fn parse_args_known_keys() {
        let cfg = parse(&["file=/x", "socket=/y", "strict_modes=no", "max_attempts=3"]).unwrap();
        assert_eq!(cfg.key_file, "/x");
        assert_eq!(cfg.socket_path.as_deref(), Some("/y"));
        assert!(!cfg.strict_modes);
        assert_eq!(cfg.max_attempts, 3);
    }

    #[test]
    fn parse_args_max_attempts_overrides_default() {
        let cfg = parse(&["max_attempts=1"]).unwrap();
        assert_eq!(cfg.max_attempts, 1);
        let cfg = parse(&["max_attempts=42"]).unwrap();
        assert_eq!(cfg.max_attempts, 42);
    }

    #[test]
    fn parse_args_rejects_invalid_max_attempts() {
        // Zero would silently turn the module into an unconditional fail —
        // refuse it. Negatives and non-numerics are typos and equally bad.
        for bad in ["max_attempts=0", "max_attempts=-1", "max_attempts=abc", "max_attempts="] {
            let err = parse(&[bad]).expect_err(&format!("expected error for {bad}"));
            assert!(err.contains("max_attempts"), "wrong error for {bad}: {err}");
        }
    }

    #[test]
    fn parse_args_rejects_unknown_arg() {
        // Common typos must be rejected, not silently dropped.
        for bad in ["strictmodes=no", "strict-modes=no", "strict_mode=no", "garbage"] {
            let err = parse(&[bad]).expect_err(&format!("expected error for {bad}"));
            assert!(err.contains("Unknown argument"), "wrong error for {bad}: {err}");
        }
    }

    #[test]
    fn parse_args_rejects_invalid_strict_modes_value() {
        let err = parse(&["strict_modes=maybe"]).unwrap_err();
        assert!(err.contains("strict_modes"), "got: {err}");
    }

    #[test]
    fn auth_error_pam_codes() {
        assert_eq!(
            AuthError::Service("x".into()).pam_code(),
            PamResultCode::PAM_SERVICE_ERR
        );
        assert_eq!(
            AuthError::InfoUnavailable("x".into()).pam_code(),
            PamResultCode::PAM_AUTHINFO_UNAVAIL
        );
        assert_eq!(
            AuthError::AuthFail("x".into()).pam_code(),
            PamResultCode::PAM_AUTH_ERR
        );
        assert_eq!(
            AuthError::UserUnknown.pam_code(),
            PamResultCode::PAM_USER_UNKNOWN
        );
    }

    #[test]
    fn classify_io_err_routes_invalid_data_to_service() {
        let e = io::Error::new(io::ErrorKind::InvalidData, "bad");
        assert!(matches!(
            classify_io_err(e, "ctx"),
            AuthError::Service(_)
        ));
    }

    #[test]
    fn classify_io_err_routes_other_kinds_to_info_unavailable() {
        for kind in [
            io::ErrorKind::NotFound,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::TimedOut,
            io::ErrorKind::UnexpectedEof,
        ] {
            let e = io::Error::new(kind, "x");
            assert!(
                matches!(classify_io_err(e, "ctx"), AuthError::InfoUnavailable(_)),
                "kind {kind:?} should map to InfoUnavailable"
            );
        }
    }

    #[test]
    fn classify_io_err_routes_agent_failure_to_info_unavailable() {
        // `agent::list_webauthn_identities` wraps SSH_AGENT_FAILURE responses
        // as `io::Error::other("Agent failure")`, which produces an error
        // whose kind is implementation-defined (currently `Uncategorized`).
        // Pin the contract so that classification doesn't accidentally land
        // such errors in `Service`: a malfunctioning agent should let PAM
        // stacks fall through, not lock the user out.
        let e = io::Error::other("Agent failure");
        assert!(
            matches!(classify_io_err(e, "ctx"), AuthError::InfoUnavailable(_)),
            "io::Error::other must classify as InfoUnavailable"
        );
    }

    #[test]
    fn classify_open_err_missing_file_is_info_unavailable() {
        // Regression: a host with no /etc/security/authorized_keys yet
        // (typical fresh install before any users are enrolled) must NOT
        // produce PAM_SERVICE_ERR — that would turn the README's
        // recommended stack into a hard lockout. NotFound and
        // PermissionDenied both fall through to InfoUnavailable.
        for kind in [io::ErrorKind::NotFound, io::ErrorKind::PermissionDenied] {
            let err = authfile::OpenError::Io(io::Error::new(kind, "x"));
            assert!(
                matches!(classify_open_err(err), AuthError::InfoUnavailable(_)),
                "OpenError::Io({kind:?}) should map to InfoUnavailable"
            );
        }
    }

    #[test]
    fn classify_open_err_misconfig_variants_are_service() {
        use std::path::PathBuf;
        let cases: Vec<authfile::OpenError> = vec![
            authfile::OpenError::NotAbsolute(PathBuf::from("rel")),
            authfile::OpenError::UnderUserWritableRoot {
                path: PathBuf::from("/tmp/x"),
                root: "/tmp/",
            },
            authfile::OpenError::NotRegularFile(PathBuf::from("/x")),
            authfile::OpenError::BadOwner {
                path: PathBuf::from("/x"),
                actual: 1000,
                expected: 0,
            },
            authfile::OpenError::BadMode {
                path: PathBuf::from("/x"),
                mode: 0o664,
            },
        ];
        for err in cases {
            let label = format!("{err:?}");
            assert!(
                matches!(classify_open_err(err), AuthError::Service(_)),
                "{label} should map to Service"
            );
        }
    }

    #[test]
    fn classify_open_err_invalid_data_io_is_service() {
        // E.g. canonicalize hitting a corrupted symlink chain on a broken
        // filesystem — that's a Service-level concern, not info-missing.
        let err = authfile::OpenError::Io(io::Error::new(io::ErrorKind::InvalidData, "x"));
        assert!(matches!(classify_open_err(err), AuthError::Service(_)));
    }
}

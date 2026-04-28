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
                // Service errors get error!; everything else is info!. The
                // distinction matters because admins triaging a syslog stream
                // should see broken-config / malformed-protocol issues
                // separately from "user denied the touch."
                if matches!(e, AuthError::Service(_)) {
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
/// `[success=ok default=ignore]` and similar patterns: admins need to
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

#[derive(Debug)]
struct Config {
    key_file: String,
    socket_path: Option<String>,
    strict_modes: bool,
}

fn parse_args(args: &[&CStr]) -> Result<Config, String> {
    let mut key_file = DEFAULT_KEY_FILE.to_string();
    let mut socket_path = None;
    let mut strict_modes = true;

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
        .map_err(|e| AuthError::Service(format!("read authorized_keys: {e}")))?;
    let authorized_keys = keys::parse_authorized_keys_str(&content);
    if authorized_keys.is_empty() {
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

    // List agent identities
    let agent_identities = agent::list_webauthn_identities(socket)
        .map_err(|e| classify_io_err(e, "list agent identities"))?;
    if agent_identities.is_empty() {
        return Err(AuthError::InfoUnavailable(
            "no WebAuthn keys in agent".into(),
        ));
    }
    info!("Found {} WebAuthn key(s) in agent", agent_identities.len());

    // Iterate every (agent identity × authorized key) match and try them in
    // order. A soft failure on one key (user denied the prompt, signature
    // invalid, agent returned SSH_AGENT_FAILURE) is logged and skipped — only
    // a transport/protocol failure or all-matches-exhausted produces an Err.
    // Mirrors standard ssh-client behavior of trying each available identity.
    let mut tried = 0;
    for agent_id in &agent_identities {
        for auth_key in &authorized_keys {
            if agent_id.key_blob != auth_key.key_blob {
                continue;
            }
            tried += 1;
            debug!(
                "Trying matched key: {} (app: {})",
                auth_key.comment, auth_key.application
            );
            match try_authenticate(socket, auth_key, &agent_id.key_blob) {
                Ok(()) => return Ok(()),
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
    }

    if tried == 0 {
        Err(AuthError::AuthFail(
            "no agent key matched authorized_keys".into(),
        ))
    } else {
        Err(AuthError::AuthFail(format!(
            "all {tried} matching key(s) failed to authenticate"
        )))
    }
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
pub fn authenticate(
    socket_path: &Path,
    key_file: &Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    let authorized_keys = keys::parse_authorized_keys(key_file)?;
    if authorized_keys.is_empty() {
        return Ok(false);
    }

    let agent_identities = agent::list_webauthn_identities(socket_path)?;
    if agent_identities.is_empty() {
        return Ok(false);
    }

    // See `do_authenticate` for the rationale behind iterating all matches.
    // Transport errors bubble up; protocol refusals / verification failures
    // fall through to the next match.
    for agent_id in &agent_identities {
        for auth_key in &authorized_keys {
            if agent_id.key_blob != auth_key.key_blob {
                continue;
            }
            match try_authenticate(socket_path, auth_key, &agent_id.key_blob) {
                Ok(()) => return Ok(true),
                Err(TryAuthOutcome::Transport(e)) => return Err(Box::new(e)),
                Err(TryAuthOutcome::Random(msg)) => return Err(msg.into()),
                Err(TryAuthOutcome::Refused(_)) | Err(TryAuthOutcome::VerifyFailed(_)) => continue,
            }
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
    }

    #[test]
    fn parse_args_known_keys() {
        let cfg = parse(&["file=/x", "socket=/y", "strict_modes=no"]).unwrap();
        assert_eq!(cfg.key_file, "/x");
        assert_eq!(cfg.socket_path.as_deref(), Some("/y"));
        assert!(!cfg.strict_modes);
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
}

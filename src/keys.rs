// SPDX-License-Identifier: MIT

//! Parse WebAuthn SK public keys from authorized_keys files.
//!
//! Only handles `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` keys.
//! Extracts the EC point (P-256, uncompressed) and application string
//! directly from the SSH wire format — no dependency on the ssh-key crate.
//!
//! ## Trust model
//!
//! `authorized_keys` is the trust root for this PAM module. Each line binds
//! both the EC point AND the `application` (RP-ID) string into a single
//! credential identity — both are pinned at the moment an admin writes the
//! line. This is a property of the SK key format, not a runtime config:
//!
//! * A signature only verifies if the authenticator holds the private key
//!   matching the EC point in the file, AND signs over `SHA256(application)`
//!   from that same line. So a passkey registered for a different RP cannot
//!   be repurposed: its `application` won't match, its EC point won't match,
//!   or both.
//! * Therefore there is no separate runtime "RP-ID allowlist" to configure.
//!   Pinning happens at registration; the verifier just checks the math.
//! * Likewise, the ssh-agent socket needs no validation — it is a signing
//!   oracle that can only produce signatures with keys it actually holds, and
//!   those won't satisfy this file unless they are already authorized.
//!
//! The single load-bearing protection is the integrity of the file itself
//! (root-owned, not group/world-writable, ancestors likewise). Future audits
//! that flag "no RP-ID pinning" or "no socket validation" as separate issues
//! are misframing the threat model — both collapse into "protect this file."

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use std::fs;
use std::io;
use std::path::Path;

use crate::agent::read_ssh_bytes;

const WEBAUTHN_SK_ALGO: &str = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";

/// A parsed WebAuthn SK ECDSA P-256 public key.
#[derive(Debug, Clone)]
pub struct WebAuthnPublicKey {
    /// The raw key blob as it appears in the agent identity listing.
    /// Used for matching agent identities against authorized keys.
    pub key_blob: Vec<u8>,
    /// Uncompressed EC point (65 bytes: 0x04 || x || y).
    pub ec_point: Vec<u8>,
    /// The application/relying party ID (e.g. the ShellWatch domain).
    pub application: String,
    /// Optional comment from the authorized_keys line.
    pub comment: String,
    /// Per-key `verify-required` option from the authorized_keys options
    /// field. When true, the WebAuthn assertion for this key must carry the
    /// UV (User Verification) flag — independent of the module-wide setting,
    /// which is OR-ed in at the call site.
    pub verify_required: bool,
}

/// Parse all WebAuthn SK public keys from an authorized_keys file.
pub fn parse_authorized_keys(path: &Path) -> io::Result<Vec<WebAuthnPublicKey>> {
    let content = fs::read_to_string(path)?;
    Ok(parse_authorized_keys_str(&content))
}

/// Parse WebAuthn SK public keys from authorized_keys content.
pub fn parse_authorized_keys_str(content: &str) -> Vec<WebAuthnPublicKey> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            parse_authorized_key_line(line)
        })
        .collect()
}

/// Parse a single authorized_keys line for a webauthn-sk-ecdsa key.
///
/// Format: `[options] webauthn-sk-ecdsa-sha2-nistp256@openssh.com <base64> [comment]`
///
/// Tokenisation matches OpenSSH's `authorized_keys(5)` grammar (see
/// `sshkey_advance_past_options` in OpenSSH's authfile module): the
/// options block, if present, ends at the first **unquoted** whitespace,
/// with `\"` recognised as the only escape inside `"..."`. This matters
/// because option values can carry embedded spaces or commas
/// (`command="ls -la"`, `from="a,b"`) which a naïve whitespace split
/// would mishandle.
///
/// Of the recognised flag options, only `verify-required` is acted on; the
/// rest (`cert-authority`, `command="..."`, `from="..."`, `principals=`,
/// etc.) are silently tolerated as today. Lines whose options block is
/// malformed (e.g. unterminated quote, multiple whitespace-separated tokens
/// before the algorithm — not legal per OpenSSH) are skipped.
fn parse_authorized_key_line(line: &str) -> Option<WebAuthnPublicKey> {
    let line = line.trim_start();

    // Either the line begins with the algorithm (no options) or with an
    // options block followed by whitespace and then the algorithm.
    let (options, after_options) = if line_starts_with_algo(line) {
        ("", line)
    } else {
        let opts_end = advance_past_options(line)?;
        (&line[..opts_end], line[opts_end..].trim_start())
    };

    let after_algo = after_options.strip_prefix(WEBAUTHN_SK_ALGO)?;
    // The algorithm token must be terminated by whitespace (or end of
    // line); otherwise we've matched a prefix of some other longer token.
    if !matches!(
        after_algo.as_bytes().first().copied(),
        None | Some(b' ') | Some(b'\t')
    ) {
        return None;
    }

    let mut rest = after_algo.split_whitespace();
    let b64 = rest.next()?;
    let comment = rest.collect::<Vec<_>>().join(" ");

    let key_blob = match BASE64_STANDARD.decode(b64) {
        Ok(blob) => blob,
        Err(e) => {
            log::debug!("Failed to decode base64 key: {e}");
            return None;
        }
    };

    let verify_required = options_have_verify_required(options);

    match parse_webauthn_key_blob(&key_blob) {
        Some((ec_point, application)) => Some(WebAuthnPublicKey {
            key_blob,
            ec_point,
            application,
            comment,
            verify_required,
        }),
        None => {
            log::debug!("Failed to parse key blob");
            None
        }
    }
}

/// True iff `line` begins with the WebAuthn SK algorithm followed by
/// whitespace or end-of-string. Lets the parser skip the options block
/// entirely on lines that have no options, without mistaking the algorithm
/// name for a prefix of some longer string.
fn line_starts_with_algo(line: &str) -> bool {
    line.strip_prefix(WEBAUTHN_SK_ALGO).is_some_and(|tail| {
        matches!(
            tail.as_bytes().first().copied(),
            None | Some(b' ') | Some(b'\t')
        )
    })
}

/// Advance past an authorized_keys options block, mirroring OpenSSH's
/// `sshkey_advance_past_options`: the block ends at the first **unquoted**
/// whitespace, with `\"` as the only escape inside `"..."`. Returns the
/// byte offset where the block ends, or `None` if quotes are unterminated.
fn advance_past_options(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut quoted = false;
    while i < bytes.len() {
        let b = bytes[i];
        if !quoted && (b == b' ' || b == b'\t') {
            return Some(i);
        }
        if b == b'\\' && bytes.get(i + 1).copied() == Some(b'"') {
            i += 2;
            continue;
        }
        if b == b'"' {
            quoted = !quoted;
        }
        i += 1;
    }
    if quoted {
        None
    } else {
        Some(i)
    }
}

/// Returns true iff the comma-separated authorized_keys options block
/// `opts` contains a `verify-required` flag option, with quote awareness
/// per OpenSSH's `opt_dequote`: inside `"..."`, commas are literal and
/// `\"` is the only escape. Option names are matched case-insensitively
/// (`strncasecmp` in OpenSSH).
///
/// Quote awareness matters because an option like
/// `from="a,verify-required,b"` embeds commas in its quoted value — a
/// naïve `split(',')` would falsely pull `verify-required` out of that
/// value.
///
/// Scope: this function only looks for `verify-required`. Per the project
/// proposal, every other option (recognised by OpenSSH or not) is
/// tolerated — including malformed shapes like leading/double commas or
/// unknown option names. OpenSSH's option loop tolerates empty segments
/// at the loop level too (its rejections come from the surrounding
/// "unknown option" / "trailing comma" checks, which are out of scope
/// here). All ways a malformed line can mis-parse are fail-safe: the
/// worst outcome is UV gets enforced when the operator didn't intend it,
/// not the other way around.
fn options_have_verify_required(opts: &str) -> bool {
    let bytes = opts.as_bytes();
    let mut start = 0;
    let mut i = 0;
    let mut quoted = false;
    while i < bytes.len() {
        let b = bytes[i];
        if quoted {
            if b == b'\\' && bytes.get(i + 1).copied() == Some(b'"') {
                i += 2;
                continue;
            }
            if b == b'"' {
                quoted = false;
            }
            i += 1;
        } else if b == b'"' {
            quoted = true;
            i += 1;
        } else if b == b',' {
            if opts[start..i].eq_ignore_ascii_case("verify-required") {
                return true;
            }
            i += 1;
            start = i;
        } else {
            i += 1;
        }
    }
    opts[start..].eq_ignore_ascii_case("verify-required")
}

/// Parse the wire format of a webauthn-sk-ecdsa key blob.
///
/// Wire format:
/// ```text
/// string  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
/// string  "nistp256"
/// string  ec_point (65 bytes: 0x04 || x || y)
/// string  application
/// ```
fn parse_webauthn_key_blob(blob: &[u8]) -> Option<(Vec<u8>, String)> {
    let mut reader: &[u8] = blob;

    // Algorithm string
    let algo = read_ssh_bytes(&mut reader).ok()?;
    if algo != WEBAUTHN_SK_ALGO.as_bytes() {
        return None;
    }

    // Curve identifier ("nistp256")
    let _curve = read_ssh_bytes(&mut reader).ok()?;

    // EC point
    let ec_point = read_ssh_bytes(&mut reader).ok()?.to_vec();
    if ec_point.len() != 65 || ec_point[0] != 0x04 {
        log::debug!(
            "Invalid EC point: expected 65 bytes starting with 0x04, got {} bytes",
            ec_point.len()
        );
        return None;
    }

    // Application string (relying party ID — must be non-empty)
    let app_bytes = read_ssh_bytes(&mut reader).ok()?;
    if app_bytes.is_empty() {
        log::debug!("Empty application string in key blob");
        return None;
    }
    let application = String::from_utf8(app_bytes.to_vec()).ok()?;

    Some((ec_point, application))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid webauthn-sk-ecdsa key blob for testing.
    fn make_test_key_blob(application: &str) -> Vec<u8> {
        let mut blob = Vec::new();
        write_ssh_string(&mut blob, WEBAUTHN_SK_ALGO.as_bytes());
        write_ssh_string(&mut blob, b"nistp256");
        // 65-byte uncompressed EC point (0x04 + 32 bytes x + 32 bytes y)
        let mut ec_point = vec![0x04];
        ec_point.extend([0x01u8; 32]); // x
        ec_point.extend([0x02u8; 32]); // y
        write_ssh_string(&mut blob, &ec_point);
        write_ssh_string(&mut blob, application.as_bytes());
        blob
    }

    fn write_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend(&(data.len() as u32).to_be_bytes());
        buf.extend(data);
    }

    #[test]
    fn test_parse_key_blob() {
        let blob = make_test_key_blob("https://example.com");
        let (ec_point, app) = parse_webauthn_key_blob(&blob).unwrap();
        assert_eq!(ec_point.len(), 65);
        assert_eq!(ec_point[0], 0x04);
        assert_eq!(app, "https://example.com");
    }

    #[test]
    fn test_parse_authorized_key_line() {
        let blob = make_test_key_blob("localhost");
        let b64 = BASE64_STANDARD.encode(&blob);
        let line = format!("{WEBAUTHN_SK_ALGO} {b64} my-key-comment");

        let key = parse_authorized_key_line(&line).unwrap();
        assert_eq!(key.application, "localhost");
        assert_eq!(key.comment, "my-key-comment");
        assert_eq!(key.ec_point.len(), 65);
        // Default: no per-key verify-required option.
        assert!(!key.verify_required);
    }

    #[test]
    fn test_parse_authorized_key_line_verify_required_token() {
        let blob = make_test_key_blob("localhost");
        let b64 = BASE64_STANDARD.encode(&blob);
        let line = format!("verify-required {WEBAUTHN_SK_ALGO} {b64} my-key");

        let key = parse_authorized_key_line(&line).unwrap();
        assert!(key.verify_required);
        assert_eq!(key.comment, "my-key");
    }

    #[test]
    fn test_parse_authorized_key_line_verify_required_in_comma_options() {
        // OpenSSH's canonical form packs options into a single comma-separated
        // token. Other options sit alongside `verify-required` and must not
        // mask it.
        let blob = make_test_key_blob("localhost");
        let b64 = BASE64_STANDARD.encode(&blob);
        let line = format!("cert-authority,verify-required {WEBAUTHN_SK_ALGO} {b64}");

        let key = parse_authorized_key_line(&line).unwrap();
        assert!(key.verify_required);
    }

    #[test]
    fn test_parse_authorized_key_line_verify_required_case_insensitive() {
        // OpenSSH option names are case-insensitive — match that.
        let blob = make_test_key_blob("localhost");
        let b64 = BASE64_STANDARD.encode(&blob);
        let line = format!("Verify-Required {WEBAUTHN_SK_ALGO} {b64}");

        let key = parse_authorized_key_line(&line).unwrap();
        assert!(key.verify_required);
    }

    #[test]
    fn test_parse_authorized_key_line_other_options_do_not_set_uv() {
        // Unrelated options must not flip the flag.
        let blob = make_test_key_blob("localhost");
        let b64 = BASE64_STANDARD.encode(&blob);
        let line = format!("cert-authority {WEBAUTHN_SK_ALGO} {b64}");

        let key = parse_authorized_key_line(&line).unwrap();
        assert!(!key.verify_required);
    }

    #[test]
    fn test_parse_authorized_key_line_quoted_comma_is_not_a_separator() {
        // OpenSSH's opt_dequote treats commas inside "..." as literal.
        // A `from=` value carrying the literal substring "verify-required"
        // between commas must NOT trigger UV enforcement — that comma is
        // part of the value, not an option separator.
        let blob = make_test_key_blob("localhost");
        let b64 = BASE64_STANDARD.encode(&blob);
        let line = format!(r#"from="a,verify-required,b" {WEBAUTHN_SK_ALGO} {b64}"#);

        let key = parse_authorized_key_line(&line).unwrap();
        assert!(
            !key.verify_required,
            "comma inside quoted from= value must not be treated as an option separator"
        );
    }

    #[test]
    fn test_parse_authorized_key_line_quoted_space_in_option_value() {
        // command="ls -la" carries a space inside the quoted value. The
        // options block ends at the first UNQUOTED whitespace, so the
        // algorithm token still parses correctly.
        let blob = make_test_key_blob("localhost");
        let b64 = BASE64_STANDARD.encode(&blob);
        let line = format!(r#"command="ls -la",verify-required {WEBAUTHN_SK_ALGO} {b64} c"#);

        let key = parse_authorized_key_line(&line).unwrap();
        assert!(key.verify_required);
        assert_eq!(key.comment, "c");
    }

    #[test]
    fn test_parse_authorized_key_line_rejects_whitespace_separated_options() {
        // OpenSSH's authorized_keys grammar requires options to be a single
        // comma-separated token; whitespace ENDS the options block. So
        // `verify-required cert-authority webauthn-sk-...` is malformed —
        // OpenSSH would treat `verify-required` as the entire options
        // block and then try to parse `cert-authority` as the algorithm,
        // failing. Match that — skip the line cleanly instead of silently
        // honouring a non-canonical form.
        let blob = make_test_key_blob("localhost");
        let b64 = BASE64_STANDARD.encode(&blob);
        let line = format!("verify-required cert-authority {WEBAUTHN_SK_ALGO} {b64}");

        assert!(parse_authorized_key_line(&line).is_none());
    }

    #[test]
    fn test_parse_authorized_key_line_rejects_unterminated_quote() {
        // A line with an unterminated quote in its options block is
        // malformed; advance_past_options returns None and we skip the line.
        let blob = make_test_key_blob("localhost");
        let b64 = BASE64_STANDARD.encode(&blob);
        let line = format!(r#"from="oops {WEBAUTHN_SK_ALGO} {b64}"#);

        assert!(parse_authorized_key_line(&line).is_none());
    }

    #[test]
    fn test_parse_authorized_key_line_tolerates_empty_segments() {
        // Pin the scope decision documented on `options_have_verify_required`:
        // empty segments (leading comma, double comma) are tolerated and do
        // not change behavior. OpenSSH's option loop is similarly permissive
        // about empty segments per se. Both inputs below contain a real
        // `verify-required` token, so they must enable UV.
        let blob = make_test_key_blob("localhost");
        let b64 = BASE64_STANDARD.encode(&blob);

        // leading comma
        let leading = format!(",verify-required {WEBAUTHN_SK_ALGO} {b64}");
        assert!(parse_authorized_key_line(&leading).unwrap().verify_required);

        // double comma between known options
        let middle = format!("cert-authority,,verify-required {WEBAUTHN_SK_ALGO} {b64}");
        assert!(parse_authorized_key_line(&middle).unwrap().verify_required);
    }

    #[test]
    fn test_parse_authorized_key_line_escaped_quote_inside_value() {
        // \" inside "..." is the only recognised escape per opt_dequote;
        // the embedded quote must not toggle quoted state. Comma-after-
        // closing-quote splits the option list normally.
        let blob = make_test_key_blob("localhost");
        let b64 = BASE64_STANDARD.encode(&blob);
        let line = format!(r#"command="echo \"hi\"",verify-required {WEBAUTHN_SK_ALGO} {b64}"#);

        let key = parse_authorized_key_line(&line).unwrap();
        assert!(key.verify_required);
    }

    #[test]
    fn test_parse_authorized_keys_str() {
        let blob = make_test_key_blob("localhost");
        let b64 = BASE64_STANDARD.encode(&blob);
        let content = format!(
            "# comment line\n\
             {WEBAUTHN_SK_ALGO} {b64} key1\n\
             \n\
             ssh-ed25519 AAAA... other-key\n\
             {WEBAUTHN_SK_ALGO} {b64} key2\n"
        );

        let keys = parse_authorized_keys_str(&content);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].comment, "key1");
        assert_eq!(keys[1].comment, "key2");
    }

    #[test]
    fn test_rejects_wrong_algo() {
        let mut blob = Vec::new();
        write_ssh_string(&mut blob, b"sk-ecdsa-sha2-nistp256@openssh.com");
        write_ssh_string(&mut blob, b"nistp256");
        let mut ec_point = vec![0x04];
        ec_point.extend([0x01u8; 32]);
        ec_point.extend([0x02u8; 32]);
        write_ssh_string(&mut blob, &ec_point);
        write_ssh_string(&mut blob, b"ssh:");
        assert!(parse_webauthn_key_blob(&blob).is_none());
    }

    #[test]
    fn test_rejects_invalid_ec_point() {
        let mut blob = Vec::new();
        write_ssh_string(&mut blob, WEBAUTHN_SK_ALGO.as_bytes());
        write_ssh_string(&mut blob, b"nistp256");
        // Wrong length EC point
        write_ssh_string(&mut blob, &[0x04, 0x01, 0x02]);
        write_ssh_string(&mut blob, b"localhost");
        assert!(parse_webauthn_key_blob(&blob).is_none());
    }
}

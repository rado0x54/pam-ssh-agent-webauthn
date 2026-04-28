# pam-ssh-agent-webauthn

A PAM module that authenticates users via WebAuthn passkeys through a forwarded SSH agent. It verifies `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` signatures — the key type produced when a FIDO2/WebAuthn authenticator is used as an SSH key with a non-`ssh:` relying party ID.

This module is **standalone** and has **no dependency on ShellWatch** or any other specific SSH agent implementation. It works with any SSH agent that:

1. Holds keys of type `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`
2. Produces WebAuthn-format signatures (with `origin`, `clientDataJSON`, and `extensions` fields) in response to `SSH_AGENTC_SIGN_REQUEST`

## Scope and relationship to `pam-ssh-agent`

This module **only** supports the `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` key type — i.e. ssh-agent backed authentication for WebAuthn passkeys / `webauthn-sk` keys. Standard SSH key types (RSA, Ed25519, ECDSA) and standard FIDO2 SK keys (`sk-ecdsa-sha2-nistp256@openssh.com` with `application=ssh:`) are **not** supported here — use [`nresare/pam-ssh-agent`](https://github.com/nresare/pam-ssh-agent) for those.

This project **should ideally be fully integrated into [`nresare/pam-ssh-agent`](https://github.com/nresare/pam-ssh-agent)** so a single PAM module can handle both classic SSH-key and WebAuthn-passkey authentication. However, the WebAuthn flow is materially different from standard SSH-agent signature verification (extra wire format, `clientDataJSON` parsing, origin / RP-ID handling, flag and extensions checks) and integrating it would require significant changes upstream — see the existing exploration in [`rado0x54/pam-ssh-agent#1`](https://github.com/rado0x54/pam-ssh-agent/pull/1).

Until that upstream integration happens, this module ships separately and intentionally focuses on the WebAuthn case alone.

## What it does

When a user runs `sudo` (or any PAM-authenticated command), the module:

1. Reads authorized public keys from a configured file (default: `/etc/security/authorized_keys`)
2. Connects to the SSH agent at `$SSH_AUTH_SOCK`
3. Lists agent identities, filters for `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` keys
4. Matches agent keys against authorized keys by raw key blob comparison
5. Generates a 32-byte random challenge
6. Sends `SSH_AGENTC_SIGN_REQUEST` to the agent
7. Receives the signature with WebAuthn fields (origin, clientDataJSON, extensions)
8. Validates the challenge is base64url-encoded in `clientDataJSON`
9. Constructs `signed_data = SHA256(application) || flags || counter || SHA256(clientDataJSON)`
10. Verifies the ECDSA P-256 signature over `signed_data`
11. Returns `PAM_SUCCESS` or `PAM_AUTH_ERR`

## What it does NOT do

- Standard SSH key types (RSA, Ed25519, ECDSA) — use [pam-ssh-agent](https://github.com/nresare/pam-ssh-agent) for those
- Standard FIDO2 SK keys (`sk-ecdsa-sha2-nistp256@openssh.com` with `application=ssh:`)
- Ed25519 SK keys
- SSH certificates
- `authorized_keys_command` execution

Non-webauthn keys in the authorized keys file are silently ignored.

## Trust model

- **Trusted**: authenticator hardware, browser origin check, this PAM verifier
- **Transport only**: the SSH agent forwarder (e.g. ShellWatch, or any agent forwarding mechanism) cannot forge signatures — it can only deny or delay them
- **Verified on target**: ECDSA P-256 signature over a fresh challenge, checked against the public key in the authorized keys file

## Build

Requires Rust 1.70+ and PAM development headers.

```bash
# Install PAM headers (Linux)
sudo apt install libpam0g-dev    # Debian/Ubuntu
sudo dnf install pam-devel       # Fedora/RHEL

# Build the shared library
cargo build --release

# The PAM module is at:
# target/release/libpam_ssh_agent_webauthn.so  (Linux)
# target/release/libpam_ssh_agent_webauthn.dylib  (macOS)
```

### FIPS / OpenSSL backend

By default, ECDSA verification uses the pure Rust `p256` crate. For environments requiring OpenSSL (e.g. FIPS compliance):

```bash
cargo build --release --features native-crypto
```

This requires OpenSSL development headers (`libssl-dev` / `openssl-devel`).

## Setup on target machine

### 1. Install the PAM module

```bash
# Linux
sudo cp target/release/libpam_ssh_agent_webauthn.so /usr/lib/x86_64-linux-gnu/security/pam_ssh_agent_webauthn.so

# macOS (for testing)
sudo cp target/release/libpam_ssh_agent_webauthn.dylib /usr/lib/pam/pam_ssh_agent_webauthn.so
```

### 2. Add authorized keys

Create `/etc/security/authorized_keys` with WebAuthn public keys:

```
webauthn-sk-ecdsa-sha2-nistp256@openssh.com AAAA... user-comment
```

The key must be the exact key blob the SSH agent presents — same EC point and same application/relying party ID. Standard SSH keys and other key types in this file are ignored.

### 3. Configure PAM

Add to `/etc/pam.d/sudo` (before other auth lines):

```
auth sufficient pam_ssh_agent_webauthn.so
```

Or with a custom key file path:

```
auth sufficient pam_ssh_agent_webauthn.so file=/path/to/authorized_keys
```

To override the agent socket path (instead of `$SSH_AUTH_SOCK`):

```
auth sufficient pam_ssh_agent_webauthn.so socket=/path/to/agent.sock
```

To cap how many sign requests are issued per `pam_authenticate` call (mirrors OpenSSH's `MaxAuthTries`; default `6`):

```
auth sufficient pam_ssh_agent_webauthn.so max_attempts=1
```

This bounds the number of user-presence prompts a misbehaving or hostile ssh-agent can force by advertising many identities whose key blobs match `authorized_keys`. Raise it for users with many enrolled credentials. Must be `>= 1`.

**Note on `max_attempts=1`:** the agent controls the order of identities returned in `IDENTITIES_ANSWER`. With a cap of `1`, a buggy or hostile agent that fronts a matching-but-non-signing identity ahead of the real one will cause legitimate auths to fail (the real key is never reached). The default of `6` self-heals because iteration continues past denied keys. If you see `sign-attempt cap of 1 reached` in syslog while users hold valid credentials, raise this value.

### Authorized-keys file protection

`authorized_keys` is the trust root: each line binds an EC point and an `application` (RP-ID) string into a credential identity that root pinned at registration time. The module enforces an OpenSSH-style ladder before reading the file:

* Path must be absolute and not under any user-writable root (`/home/`, `/tmp/`, `/var/tmp/`, `/run/user/`, `/Users/`). Per-user files are not supported.
* File is opened with `O_NOFOLLOW | O_NONBLOCK | O_RDONLY` — leaf symlinks and FIFOs are refused.
* `fstat` on the open fd requires a regular file owned by root with no group/world write bits set.
* By default (`strict_modes=yes`) every ancestor directory up to `/` must also be root-owned and not group/world-writable. Disable with `strict_modes=no` for unusual filesystems:

```
auth sufficient pam_ssh_agent_webauthn.so strict_modes=no
```

### User Verification (UV) enforcement

WebAuthn assertions carry both a UP bit (User Presence — touch) and a UV bit (User Verification — PIN or biometric). UP is always required by this module; UV is opt-in because not every authenticator supports it.

Two independent knobs control UV enforcement, both off by default:

- **Module-wide**, applies to every key:
  ```
  auth sufficient pam_ssh_agent_webauthn.so verify_required=yes
  ```
- **Per-key**, as an option in `/etc/security/authorized_keys`:
  ```
  verify-required webauthn-sk-ecdsa-sha2-nistp256@openssh.com AAAA... user@host
  ```
  The option may also appear inside a comma-separated options list (e.g. `cert-authority,verify-required …`), matching OpenSSH's `authorized_keys(5)` grammar.

UV is enforced if **either** says so — whichever rule is stricter wins. With both off (the default), the UV bit is ignored, preserving compatibility with authenticators that do not support PIN/biometric prompts. When UV is required but the assertion lacks the bit, authentication fails with `PAM_AUTH_ERR`.

These are the same two surfaces OpenSSH exposes for SK keys (`PubkeyAuthOptions verify-required` in `sshd_config` and the `verify-required` `authorized_keys` option) — except the global form lives on the PAM module line, since this module never sees `sshd_config`.

### PAM return codes

The module distinguishes failure modes so PAM stacks can route on them:

| Return code | Condition |
|---|---|
| `PAM_SUCCESS` | A matching key signed the challenge and the signature verified. |
| `PAM_AUTH_ERR` | No agent key matched `authorized_keys`, or every matched key was refused / failed verification (user denied the touch, agent rejected, etc.). |
| `PAM_AUTHINFO_UNAVAIL` | `SSH_AUTH_SOCK` not set, agent socket unreachable, agent advertises no WebAuthn keys, or `authorized_keys` is empty. The module is fine — the info needed to authenticate just isn't present. |
| `PAM_SERVICE_ERR` | Module misconfiguration (bad arg, unreadable / unsafe `authorized_keys`), or the agent returned a malformed protocol message. |

This lets you compose stacks like:

```
auth [success=done auth_err=die authinfo_unavail=ignore default=ignore] \
     pam_ssh_agent_webauthn.so
auth requisite pam_unix.so
```

— "if WebAuthn auth succeeded, accept and stop (`success=done`); if the user actively failed, deny; if the user has no agent forwarded or no keys configured, fall through to passwords."

### 4. Preserve SSH_AUTH_SOCK for sudo

```bash
# /etc/sudoers.d/ssh-auth-sock
Defaults env_keep += "SSH_AUTH_SOCK"
```

## Testing locally

The included `authenticator` example runs the full authentication flow without PAM:

```bash
# Set up the agent socket (from your SSH agent forwarder)
export SSH_AUTH_SOCK=/path/to/agent.sock

# Run against a key file
cargo run --example authenticator -- /path/to/authorized_keys
```

The `list_keys` example shows decoded key blobs from the agent:

```bash
export SSH_AUTH_SOCK=/path/to/agent.sock
cargo run --example list_keys
```

## Wire formats

### Key blob (`webauthn-sk-ecdsa-sha2-nistp256@openssh.com`)

```
string  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
string  "nistp256"
string  ec_point        (65 bytes: 0x04 || x || y, uncompressed P-256)
string  application     (relying party ID, e.g. "localhost", "example.com")
```

### Signature blob (WebAuthn variant)

```
string  algorithm       ("sk-ecdsa-sha2-nistp256@openssh.com" or "webauthn-...")
string  ecdsa_signature (mpint R || mpint S)
byte    flags
uint32  counter
string  origin          (WebAuthn origin URL)
string  clientDataJSON  (contains base64url-encoded challenge)
string  extensions      (CBOR, typically empty)
```

### Verification

```
signed_data = SHA256(application) || flags || counter || extensions || SHA256(clientDataJSON)
```

ECDSA P-256 signature is verified over `signed_data` using the public key from the authorized keys file.

### Validation checks

The following checks are performed, matching OpenSSH's `webauthn_check_prepare_hash`:

- **Algorithm**: Must be `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` or `sk-ecdsa-sha2-nistp256@openssh.com`
- **User Presence (UP)**: Flag bit 0x01 must be set
- **Attested Credential Data (AD)**: Flag bit 0x40 must NOT be set (this is an assertion, not a registration)
- **Extension Data (ED)**: Flag bit 0x80 must be consistent with extensions presence
- **Origin**: Must not contain quote characters (prevents JSON injection); must match between signature blob and clientDataJSON
- **clientDataJSON type**: Must be `"webauthn.get"`
- **clientDataJSON challenge**: Must match the base64url-encoded challenge sent to the agent
- **clientDataJSON origin**: Must match the origin from the signature blob
- **Trailing data**: Rejected — no extra bytes allowed after the extensions field

### Limitations

- **No counter/replay protection**: The WebAuthn counter is integrity-protected (included in signed_data) but not checked for monotonic increase. Counter validation requires persistent state (tracking the last-seen counter per key), which is not appropriate for a stateless PAM module. This means a captured signature cannot be replayed (the challenge is fresh each time), but a cloned authenticator with a reset counter would not be detected.
- **User Verification (UV) is opt-in**: The default is permissive (UP only) so that authenticators without PIN/biometric support keep working. Operators who want to enforce UV have two independent knobs — a module-wide arg and a per-key option — see [User Verification (UV) enforcement](#user-verification-uv-enforcement) below. UP (User Presence) is always required.

## Logging

Logs to syslog facility `AUTH` as `pam_ssh_agent_webauthn`. Set log level via PAM or syslog configuration.

## Troubleshooting

**`SSH_AUTH_SOCK not set`** — The module reads `$SSH_AUTH_SOCK` from the environment. For sudo, this must be preserved:

```bash
# /etc/sudoers.d/ssh-auth-sock
Defaults env_keep += "SSH_AUTH_SOCK"
```

**Agent timeout** — The module waits up to 60 seconds for the agent to respond. This is generous because the sign request may require user interaction (e.g. tapping a passkey in the browser). If the agent is unresponsive, authentication fails with a timeout error after 60s.

**No matching key** — Key matching is done by raw blob comparison, which includes the application/relying party ID. If the key in `authorized_keys` was generated with a different RP ID than the one the agent holds, they will not match even if the underlying EC key material is identical. Use the `list_keys` example to inspect the agent's key blobs:

```bash
SSH_AUTH_SOCK=/path/to/agent.sock cargo run --example list_keys
```

**Silent failures** — Enable debug logging to see detailed matching and verification steps. The module logs to syslog facility `AUTH`.

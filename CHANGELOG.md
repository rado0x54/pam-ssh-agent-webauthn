# Changelog

## v0.2.1 (2026-04-28)

- fix(pam): tolerate pam_get_user failure to work around pam-bindings release-build bug ([#15](https://github.com/rado0x54/pam-ssh-agent-webauthn/pull/15))
- chore(release): rename .so artifacts to pam_ssh_agent_webauthn-VERSION-ARCH.so so the base name matches the PAM install target ([#13](https://github.com/rado0x54/pam-ssh-agent-webauthn/pull/13))
- chore(ci): bump JS-based actions to Node 24 majors (checkout v6, upload-artifact v7, download-artifact v8) ([#12](https://github.com/rado0x54/pam-ssh-agent-webauthn/pull/12))

## v0.2.0 (2026-04-28)

- feat(webauthn): reject non-canonical ECDSA signature wire encoding ([#11](https://github.com/rado0x54/pam-ssh-agent-webauthn/pull/11))
- feat(agent): tighten agent message size cap from 1 MiB to 256 KiB to match OpenSSH ([#10](https://github.com/rado0x54/pam-ssh-agent-webauthn/pull/10))
- feat: cap sign attempts per pam_authenticate ([#3](https://github.com/rado0x54/pam-ssh-agent-webauthn/pull/3)) ([#9](https://github.com/rado0x54/pam-ssh-agent-webauthn/pull/9))
- feat(pam): distinguish service errors from auth failures in PAM return codes ([#8](https://github.com/rado0x54/pam-ssh-agent-webauthn/pull/8))
- feat: harden authorized_keys access with OpenSSH-style safety ladder ([#7](https://github.com/rado0x54/pam-ssh-agent-webauthn/pull/7))
- docs: codify trust model rationale to prevent re-flagging in future audits ([#6](https://github.com/rado0x54/pam-ssh-agent-webauthn/pull/6))
- fix(ci): insert new CHANGELOG entry below '# Changelog' title

## v0.1.0 (2026-04-27)

- Initial release

## v0.0.2 (2026-04-13)

- fix: iterate matching keys instead of giving up after the first failed sign ([#91](https://github.com/rado0x54/ShellWatch/issues/91)) ([#92](https://github.com/rado0x54/ShellWatch/pull/92))
- fix: distinguish protocol refusal (`SSH_AGENT_FAILURE`) from transport errors so "agent is down" surfaces instead of masquerading as "no key matched" ([#92](https://github.com/rado0x54/ShellWatch/pull/92))

## v0.0.1 (2026-04-10)

- feat: dedicated pam_ssh_webauthn module ([#65](https://github.com/rado0x54/ShellWatch/pull/65)) ([#66](https://github.com/rado0x54/ShellWatch/pull/66))

// SPDX-License-Identifier: MIT

//! Secure open of the authorized_keys file.
//!
//! This PAM module's trust root is the authorized_keys file: each line binds an
//! EC point and an `application` (RP-ID) string into a credential identity
//! that root pinned at registration time. The integrity of that file therefore
//! gates every authentication this module performs.
//!
//! The pattern below mirrors OpenSSH's `safe_path` / `safe_path_fd` ladder
//! (`misc.c:2319` / `misc.c:2388`) adapted for our Model 1 deployment:
//! `/etc/security/authorized_keys`, root-owned, read by the privileged PAM
//! module which is *also* root. We do not implement the
//! `temporarily_use_uid`/per-user dance because we explicitly do not support
//! per-user authorized_keys files — see `forbidden_roots`.
//!
//! Sequence:
//!   1. Reject non-absolute path.
//!   2. Reject configured path under known user-writable roots (`/home`,
//!      `/tmp`, ...) — cheap pre-check.
//!   3. `open(path, O_RDONLY|O_NOFOLLOW|O_NONBLOCK)` — refuses leaf symlinks
//!      and prevents blocking on FIFOs. Intermediate symlinks ARE still
//!      followed; the canonical-path recheck below catches those.
//!   4. `fstat` on the open fd — defeats TOCTOU between the path lookup and
//!      the stat. Require regular file, expected uid, no group/world write.
//!   5. Canonicalize and re-check against `forbidden_roots` (unconditional —
//!      independent of `strict_modes`, since this is a location check, not a
//!      mode/ownership check). Catches intermediate symlinks like
//!      `/etc/security -> /private/tmp/...`.
//!   6. (Strict modes) Walk every ancestor of the canonical path up to `/`
//!      requiring same uid + mode rules as the leaf.
//!   7. Read content.

use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Default user-writable path prefixes to refuse outright. A path under any of
/// these indicates a Model 2 (per-user) deployment, which this module does not
/// support — the necessary `seteuid` machinery is not implemented and the file
/// would be readable+writable by a non-root user.
///
/// Both the configured path AND its post-canonicalize form are checked, so the
/// `/private/...` entries are needed for macOS where `/tmp`, `/var/tmp`, and
/// `/var/folders` are symlinks: a configured `/etc/foo → /tmp/...` symlink
/// would slip past the leaf check otherwise. The `/private/...` prefixes are
/// harmless on Linux (no production deployment uses them).
pub const DEFAULT_FORBIDDEN_ROOTS: &[&str] = &[
    "/home/",
    "/tmp/",
    "/var/tmp/",
    "/run/user/",
    "/Users/",
    "/private/tmp/",
    "/private/var/tmp/",
    "/private/var/folders/",
];

/// Configuration for [`open_secure`].
#[derive(Debug, Clone)]
pub struct Opts {
    /// Walk the canonicalized path's ancestor chain and require each
    /// directory be owned by `expected_uid` and not group/world-writable.
    /// Default: `true` (matches OpenSSH `StrictModes yes`).
    pub strict_modes: bool,
    /// UID required for the file and (with `strict_modes`) every ancestor.
    /// Production: `0` (root). Tests pass the test process's uid.
    pub expected_uid: u32,
    /// Path prefixes refused before opening. Default: [`DEFAULT_FORBIDDEN_ROOTS`].
    /// Tests pass an empty slice so they can use `/tmp`-based scratch dirs.
    pub forbidden_roots: &'static [&'static str],
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            strict_modes: true,
            expected_uid: 0,
            forbidden_roots: DEFAULT_FORBIDDEN_ROOTS,
        }
    }
}

#[derive(Debug)]
pub enum OpenError {
    NotAbsolute(PathBuf),
    UnderUserWritableRoot {
        path: PathBuf,
        root: &'static str,
    },
    NotRegularFile(PathBuf),
    BadOwner {
        path: PathBuf,
        actual: u32,
        expected: u32,
    },
    BadMode {
        path: PathBuf,
        mode: u32,
    },
    Io(io::Error),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAbsolute(p) => {
                write!(f, "authorized_keys path is not absolute: {}", p.display())
            }
            Self::UnderUserWritableRoot { path, root } => write!(
                f,
                "authorized_keys path {} is under user-writable root {root} \
                 (per-user mode is not supported)",
                path.display()
            ),
            Self::NotRegularFile(p) => {
                write!(f, "authorized_keys is not a regular file: {}", p.display())
            }
            Self::BadOwner {
                path,
                actual,
                expected,
            } => write!(
                f,
                "authorized_keys {} owner uid={actual} (expected uid={expected})",
                path.display()
            ),
            Self::BadMode { path, mode } => write!(
                f,
                "authorized_keys {} is group/world-writable (mode={:o})",
                path.display(),
                mode
            ),
            Self::Io(e) => write!(f, "authorized_keys I/O error: {e}"),
        }
    }
}

impl std::error::Error for OpenError {}

impl From<io::Error> for OpenError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Open the authorized_keys file under the OpenSSH-style safety ladder and
/// return its contents. See module-level docs for the full check sequence.
pub fn open_secure(path: &Path, opts: &Opts) -> Result<String, OpenError> {
    if !path.is_absolute() {
        return Err(OpenError::NotAbsolute(path.to_path_buf()));
    }

    if let Some(root) = matched_forbidden_root(path, opts.forbidden_roots) {
        return Err(OpenError::UnderUserWritableRoot {
            path: path.to_path_buf(),
            root,
        });
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;

    let meta = file.metadata()?;

    if !meta.file_type().is_file() {
        return Err(OpenError::NotRegularFile(path.to_path_buf()));
    }
    if meta.uid() != opts.expected_uid {
        return Err(OpenError::BadOwner {
            path: path.to_path_buf(),
            actual: meta.uid(),
            expected: opts.expected_uid,
        });
    }
    if meta.mode() & 0o022 != 0 {
        return Err(OpenError::BadMode {
            path: path.to_path_buf(),
            mode: meta.mode() & 0o777,
        });
    }

    // The canonical-path recheck is location-based, orthogonal to the
    // mode/ownership ancestor walk gated by strict_modes. It runs
    // unconditionally so an intermediate-symlink config like
    // `file=/etc/security/keys` where `/etc/security -> /private/tmp/...`
    // can't slip past with strict_modes=no. (O_NOFOLLOW only protects the
    // leaf, so intermediate symlinks are followed at open time.)
    let canonical = std::fs::canonicalize(path)?;
    if let Some(root) = matched_forbidden_root(&canonical, opts.forbidden_roots) {
        return Err(OpenError::UnderUserWritableRoot {
            path: canonical,
            root,
        });
    }

    if opts.strict_modes {
        // Walk ancestors, skipping the leaf which fstat already covered.
        for ancestor in canonical.ancestors().skip(1) {
            let m = std::fs::symlink_metadata(ancestor)?;
            if m.uid() != opts.expected_uid {
                return Err(OpenError::BadOwner {
                    path: ancestor.to_path_buf(),
                    actual: m.uid(),
                    expected: opts.expected_uid,
                });
            }
            if m.mode() & 0o022 != 0 {
                return Err(OpenError::BadMode {
                    path: ancestor.to_path_buf(),
                    mode: m.mode() & 0o777,
                });
            }
        }
    }

    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

fn matched_forbidden_root(
    path: &Path,
    forbidden_roots: &'static [&'static str],
) -> Option<&'static str> {
    forbidden_roots
        .iter()
        .copied()
        .find(|root| path.starts_with(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    fn current_uid() -> u32 {
        // SAFETY: getuid is async-signal-safe and always succeeds.
        unsafe { libc::getuid() }
    }

    /// Test scratch dir under target/ rather than /tmp so we don't have to
    /// fight DEFAULT_FORBIDDEN_ROOTS in tests that exercise it.
    fn scratch_dir(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-authfile")
            .join(format!("{name}-{}-{}", std::process::id(), unique()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn unique() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        N.fetch_add(1, Ordering::Relaxed)
    }

    fn test_opts() -> Opts {
        Opts {
            strict_modes: false,
            expected_uid: current_uid(),
            forbidden_roots: &[],
        }
    }

    fn write_file(path: &Path, content: &str, mode: u32) {
        fs::write(path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn happy_path() {
        let dir = scratch_dir("happy");
        let f = dir.join("keys");
        write_file(&f, "key contents\n", 0o600);

        let content = open_secure(&f, &test_opts()).unwrap();
        assert_eq!(content, "key contents\n");
    }

    #[test]
    fn rejects_non_absolute() {
        let err = open_secure(Path::new("relative/path"), &test_opts()).unwrap_err();
        assert!(matches!(err, OpenError::NotAbsolute(_)), "got {err:?}");
    }

    #[test]
    fn rejects_group_writable_file() {
        let dir = scratch_dir("group-w");
        let f = dir.join("keys");
        write_file(&f, "k\n", 0o620);

        let err = open_secure(&f, &test_opts()).unwrap_err();
        assert!(
            matches!(err, OpenError::BadMode { mode: 0o620, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_world_writable_file() {
        let dir = scratch_dir("world-w");
        let f = dir.join("keys");
        write_file(&f, "k\n", 0o602);

        let err = open_secure(&f, &test_opts()).unwrap_err();
        assert!(
            matches!(err, OpenError::BadMode { mode: 0o602, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_wrong_owner() {
        let dir = scratch_dir("owner");
        let f = dir.join("keys");
        write_file(&f, "k\n", 0o600);

        let opts = Opts {
            expected_uid: current_uid().wrapping_add(1),
            ..test_opts()
        };
        let err = open_secure(&f, &opts).unwrap_err();
        assert!(matches!(err, OpenError::BadOwner { .. }), "got {err:?}");
    }

    #[test]
    fn rejects_symlink_at_leaf() {
        let dir = scratch_dir("symlink");
        let real = dir.join("real");
        let link = dir.join("link");
        write_file(&real, "k\n", 0o600);
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // O_NOFOLLOW yields ELOOP at open time; surfaces as Io error.
        let err = open_secure(&link, &test_opts()).unwrap_err();
        assert!(matches!(err, OpenError::Io(_)), "got {err:?}");
    }

    #[test]
    fn rejects_fifo() {
        let dir = scratch_dir("fifo");
        let f = dir.join("pipe");
        let cstr = std::ffi::CString::new(f.to_str().unwrap()).unwrap();
        // SAFETY: cstr is valid for the duration of the call.
        let rc = unsafe { libc::mkfifo(cstr.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed: {}", io::Error::last_os_error());

        let err = open_secure(&f, &test_opts()).unwrap_err();
        // Either NotRegularFile (if O_NONBLOCK lets us open it) or Io with
        // ENXIO (if the kernel refuses an O_RDONLY|O_NONBLOCK on a fifo with
        // no writer). Both are valid rejections.
        assert!(
            matches!(err, OpenError::NotRegularFile(_) | OpenError::Io(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_unix_socket() {
        let dir = scratch_dir("sock");
        let f = dir.join("agent.sock");
        let _listener = UnixListener::bind(&f).unwrap();

        let err = open_secure(&f, &test_opts()).unwrap_err();
        assert!(
            matches!(err, OpenError::NotRegularFile(_) | OpenError::Io(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_path_under_default_forbidden_root() {
        // Use the production DEFAULT_FORBIDDEN_ROOTS to verify the prefix check.
        // The path doesn't have to exist — the check fires before open(2).
        let opts = Opts {
            forbidden_roots: DEFAULT_FORBIDDEN_ROOTS,
            ..test_opts()
        };
        let err = open_secure(Path::new("/home/alice/.ssh/authorized_keys"), &opts).unwrap_err();
        match err {
            OpenError::UnderUserWritableRoot { root, .. } => assert_eq!(root, "/home/"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn forbidden_root_recheck_runs_even_with_strict_modes_off() {
        // Regression: the post-canonicalize forbidden-root recheck must fire
        // independent of strict_modes. Otherwise an intermediate-symlink
        // config (e.g. `/etc/security -> /private/tmp/...`) slips past with
        // strict_modes=no.
        let dir = scratch_dir("symlink-into-forbidden");
        let real = dir.join("real");
        fs::create_dir_all(&real).unwrap();
        let f = real.join("keys");
        write_file(&f, "k\n", 0o600);
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Pretend the canonical target's parent is a forbidden root.
        // We can't actually make a symlink chain into /tmp here without
        // owning a root-mode file in /tmp, so we steer the forbidden-roots
        // list at our scratch tree to exercise the same code path.
        let real_prefix: &'static str = Box::leak(format!("{}/", real.display()).into_boxed_str());
        let forbidden: &'static [&'static str] = Box::leak(Box::new([real_prefix]));

        let opts = Opts {
            strict_modes: false,
            forbidden_roots: forbidden,
            ..test_opts()
        };
        // Configured path goes through the symlink, so the pre-open string
        // check doesn't match `<scratch>/real/`. Canonical does.
        let configured = link.join("keys");
        let err = open_secure(&configured, &opts).unwrap_err();
        match err {
            OpenError::UnderUserWritableRoot { path, root } => {
                assert_eq!(root, real_prefix);
                assert!(path.starts_with(&real), "canonical path was {path:?}");
            }
            other => panic!("expected UnderUserWritableRoot, got {other:?}"),
        }
    }

    #[test]
    fn rejects_macos_canonical_tmp_paths() {
        // On macOS /tmp, /var/tmp, /var/folders are symlinks into /private/.
        // Both the configured-path and post-canonicalize check must catch
        // these forms — otherwise an intermediate-symlink config could slip
        // past the leaf check.
        let opts = Opts {
            forbidden_roots: DEFAULT_FORBIDDEN_ROOTS,
            ..test_opts()
        };
        for (path, expected_root) in [
            ("/private/tmp/x/keys", "/private/tmp/"),
            ("/private/var/tmp/x/keys", "/private/var/tmp/"),
            ("/private/var/folders/ab/cd/keys", "/private/var/folders/"),
        ] {
            let err = open_secure(Path::new(path), &opts).unwrap_err();
            match err {
                OpenError::UnderUserWritableRoot { root, .. } => {
                    assert_eq!(root, expected_root, "wrong root matched for {path}")
                }
                other => panic!("expected forbidden-root rejection for {path}, got {other:?}"),
            }
        }
    }

    #[test]
    fn strict_modes_fails_on_user_owned_chain_into_tmp() {
        // /tmp is world-writable (1777) on Linux — strict_modes must reject any
        // path whose canonical chain passes through it.
        let dir = scratch_dir("strict-fail");
        let f = dir.join("keys");
        write_file(&f, "k\n", 0o600);

        let opts = Opts {
            strict_modes: true,
            forbidden_roots: &[],
            ..test_opts()
        };
        let err = open_secure(&f, &opts).unwrap_err();
        assert!(
            matches!(err, OpenError::BadMode { .. } | OpenError::BadOwner { .. }),
            "got {err:?}"
        );
    }
}

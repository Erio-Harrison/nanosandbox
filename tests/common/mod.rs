//! Helpers shared by the test binaries.

/// Ubuntu 23.10+ confines a fresh user namespace created by an unprivileged,
/// unconfined process to AppArmor's `unprivileged_userns` profile, which
/// denies the capabilities nanosandbox needs inside it (mounting, bringing up
/// a network namespace's loopback). Mirrors the library's own check, which
/// then refuses rootfs/mount/tmpfs and allow_network at build(), and skips
/// the private /proc.
///
/// Prints why and returns true when that applies, so a test that needs
/// those can return early instead of failing on the environment.
#[allow(dead_code)]
pub fn skip_without_userns_privileges() -> bool {
    #[cfg(target_os = "linux")]
    {
        let restricted =
            std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
                .is_ok_and(|v| v.trim() == "1");
        let unconfined = std::fs::read_to_string("/proc/self/attr/apparmor/current")
            .or_else(|_| std::fs::read_to_string("/proc/self/attr/current"))
            .map_or(true, |label| label.trim() == "unconfined");
        if restricted && unconfined && unsafe { libc::geteuid() } != 0 {
            eprintln!(
                "skipping: kernel.apparmor_restrict_unprivileged_userns=1 denies capabilities \
                 in the sandbox's user namespace"
            );
            return true;
        }
    }
    false
}

/// A temp directory the sandbox can use even when the caller is root, whose
/// sandbox runs as `nobody` (see `host_uid`): `tempfile` makes it mode 0700,
/// owned by the caller, which nobody can't enter, let alone write to.
#[allow(dead_code)]
pub fn sandbox_tempdir_in(parent: impl AsRef<std::path::Path>) -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir_in(parent).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    dir
}

#[allow(dead_code)]
pub fn sandbox_tempdir() -> tempfile::TempDir {
    sandbox_tempdir_in(std::env::temp_dir())
}

/// A root caller's sandbox runs as `nobody`, which can't enter a directory
/// unless every ancestor allows "others" to traverse it -- not so for a
/// checkout under a 0750 home, or for `/root`. Prints why and returns true
/// when that applies, so a test that needs the sandbox to reach `path` can
/// return early instead of failing on the environment. Never true for a
/// non-root caller, whose sandbox runs as itself.
#[allow(dead_code)]
pub fn skip_if_unreachable_by_nobody(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } != 0 {
        return false;
    }
    for ancestor in path.ancestors() {
        let Ok(meta) = std::fs::metadata(ancestor) else {
            continue;
        };
        if meta.permissions().mode() & 0o001 == 0 {
            eprintln!(
                "skipping: running as root, whose sandbox runs as nobody, which can't traverse {}",
                ancestor.display()
            );
            return true;
        }
    }
    false
}

//! Helpers shared by the test binaries.

/// `Sandbox::builder()` for tests not about the network; on Windows it opts into the host
/// network, the only one available without the one-time install.
#[allow(dead_code)]
pub fn builder() -> nanosandbox::SandboxBuilder {
    let builder = nanosandbox::Sandbox::builder();
    if cfg!(windows) {
        builder.host_network()
    } else {
        builder
    }
}

/// True (after printing why) on Ubuntu 23.10+, where AppArmor confines unprivileged userns and
/// denies mounts and netns loopback. Tests needing those return early.
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

/// A temp dir the sandbox can use even as root: its `nobody` can't enter tempfile's 0700 dir (see `host_uid`).
#[cfg(unix)]
#[allow(dead_code)]
pub fn sandbox_tempdir_in(parent: impl AsRef<std::path::Path>) -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir_in(parent).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    dir
}

#[cfg(unix)]
#[allow(dead_code)]
pub fn sandbox_tempdir() -> tempfile::TempDir {
    sandbox_tempdir_in(std::env::temp_dir())
}

/// True (after printing why) when a root caller's `nobody` sandbox can't traverse to `path`
/// (e.g. a 0750 home, `/root`). Tests needing it return early.
#[cfg(unix)]
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

/// World-writable, so the sandbox's user can write only where allowed.
#[cfg(unix)]
#[allow(dead_code)]
pub fn chmod_open(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).unwrap();
}

//! Helpers shared by the test binaries.

/// Ubuntu 23.10+ confines a fresh user namespace created by an unprivileged,
/// unconfined process to AppArmor's `unprivileged_userns` profile, which
/// denies mounting inside it. Mirrors the library's own check, which then
/// refuses rootfs/mount/tmpfs at build() and skips the private /proc.
///
/// Prints why and returns true when that applies, so a test that needs
/// mounts can return early instead of failing on the environment.
#[allow(dead_code)]
pub fn skip_without_mounts() -> bool {
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
                "skipping: kernel.apparmor_restrict_unprivileged_userns=1 denies mounts in the \
                 sandbox's user namespace"
            );
            return true;
        }
    }
    false
}

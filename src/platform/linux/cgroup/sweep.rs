//! Sweeps cgroup leaves, scopes and lock files left by processes that never ran `Drop`
//! (killed, `std::process::exit`), plus the flock bookkeeping that proves a pid's owner is gone.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::CGROUP_ROOT;
use super::scope::user_app_slice;

/// Period of the re-sweep in long-lived processes, beyond the first-use sweep. Cheap, so short.
const SWEEP_INTERVAL: Duration = Duration::from_secs(300);

/// Best-effort removal of entries under `dir` whose pid (from `pid_of`) `owner_is_gone`.
pub(super) fn sweep_stale_leaves(
    dir: &Path,
    pid_of: impl Fn(&str) -> Option<&str>,
    owner_is_gone: impl Fn(u32) -> bool,
    kill: impl Fn(&Path),
) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name.to_str().and_then(&pid_of) else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if pid == std::process::id() || !owner_is_gone(pid) {
            continue;
        }
        let leaf = entry.path();
        kill(&leaf);
        let _ = fs::remove_dir(&leaf);
    }
}

/// Reaps sibling `nanosandbox-<pid>-<nonce>.scope` units under `target` whose owner is gone.
/// Killing empties the cgroup; systemd collects the unit itself, so we don't `rmdir` it.
fn sweep_stale_scopes(target: &Path) {
    let Ok(entries) = fs::read_dir(target) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name
            .to_str()
            .and_then(|n| n.strip_prefix("nanosandbox-"))
            .and_then(|n| n.strip_suffix(".scope"))
            .and_then(|n| n.split('-').next())
        else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if pid == std::process::id() || !owner_is_gone(pid) {
            continue;
        }
        kill_cgroup_atomically(&entry.path());
    }
}

/// True if `SWEEP_INTERVAL` has passed since the last true, atomically claiming that sweep.
fn sweep_due(last: &std::sync::Mutex<Option<Instant>>) -> bool {
    // Poison ignored: housekeeping only, stale state is safe to read.
    let mut last = last.lock().unwrap_or_else(|e| e.into_inner());
    let due = match *last {
        Some(t) => t.elapsed() >= SWEEP_INTERVAL,
        None => true,
    };
    if due {
        *last = Some(Instant::now());
    }
    due
}

/// Periodic re-sweep of sibling scopes and supervisor leaves, from every `ensure_base`, so a
/// long-lived process picks up leftovers from processes that died after its first sweep.
pub(super) fn sweep_scope_neighbors_if_due(own: &Path) {
    static LAST_SWEPT: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    if !sweep_due(&LAST_SWEPT) {
        return;
    }
    let uid = unsafe { libc::getuid() };
    sweep_stale_scopes(&user_app_slice(CGROUP_ROOT, uid));
    sweep_stale_leaves(
        own,
        |name| {
            name.strip_prefix("nanosandbox-supervisor-")
                .and_then(|s| s.split('-').next())
        },
        owner_is_gone,
        kill_cgroup_atomically,
    );
}

/// Same idea as `sweep_scope_neighbors_if_due`, for the lock directory.
pub(super) fn sweep_locks_if_due() {
    static LAST_SWEPT: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    if !sweep_due(&LAST_SWEPT) {
        return;
    }
    if let Some(dir) = lock_dir() {
        sweep_stale_locks(&dir);
    }
}

/// Holds an exclusive `flock` on `$XDG_RUNTIME_DIR/nanosandbox-<pid>.lock` for this
/// process's lifetime; the kernel releases it however we end. Used instead of `/proc/<pid>`,
/// which can't tell a recycled pid in another pid namespace or an orphaned child from ours.
pub(super) fn hold_instance_lock() {
    let Some(dir) = lock_dir() else { return };
    static LOCK: std::sync::OnceLock<Option<std::fs::File>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| lock_file(&dir, std::process::id()));
}

/// `$XDG_RUNTIME_DIR`, or for root (no systemd user session) a root-owned dir under `/run`.
fn lock_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Some(PathBuf::from(dir));
    }
    if super::is_root() {
        let dir = PathBuf::from("/run/nanosandbox-locks");
        fs::create_dir_all(&dir).ok()?;
        return Some(dir);
    }
    None
}

/// Opens `dir`'s lock file for `pid` and non-blockingly `flock`s it.
fn lock_file(dir: &Path, pid: u32) -> Option<std::fs::File> {
    use std::os::unix::io::AsRawFd;
    let file = std::fs::File::create(dir.join(format!("nanosandbox-{pid}.lock"))).ok()?;
    (unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0).then_some(file)
}

/// Whether `pid`'s lock file in `dir` is confirmed released. A missing file counts as not
/// gone: better to miss a cleanup than kill what we can't confirm is ours.
fn owner_is_gone_in(dir: &Path, pid: u32) -> bool {
    use std::os::unix::io::AsRawFd;
    let Ok(file) = std::fs::File::open(dir.join(format!("nanosandbox-{pid}.lock"))) else {
        return false;
    };
    let fd = file.as_raw_fd();
    let acquired = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if acquired {
        unsafe { libc::flock(fd, libc::LOCK_UN) };
    }
    acquired
}

pub(super) fn owner_is_gone(pid: u32) -> bool {
    match lock_dir() {
        Some(dir) => owner_is_gone_in(&dir, pid),
        None => false,
    }
}

/// Removes lock files in `dir` whose owner is gone; no other sweep revisits them.
fn sweep_stale_locks(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name
            .to_str()
            .and_then(|n| n.strip_prefix("nanosandbox-"))
            .and_then(|n| n.strip_suffix(".lock"))
        else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if pid != std::process::id() && owner_is_gone_in(dir, pid) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Kills every process in `dir` via `cgroup.kill` (kernel >= 5.14, no fork race) and waits.
pub(super) fn kill_cgroup_atomically(dir: &Path) {
    if fs::write(dir.join("cgroup.kill"), "1").is_err() {
        return;
    }
    super::wait_until_empty(dir, Duration::from_millis(500));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_is_gone_reflects_whether_the_lock_is_held() {
        let locks = tempfile::tempdir().unwrap();
        let pid = 424_242;

        assert!(
            !owner_is_gone_in(locks.path(), pid),
            "no lock file at all -> unknown, not gone"
        );

        let held = lock_file(locks.path(), pid).unwrap();
        assert!(
            !owner_is_gone_in(locks.path(), pid),
            "lock held -> not gone"
        );

        drop(held);
        assert!(owner_is_gone_in(locks.path(), pid), "lock released -> gone");
    }

    #[test]
    fn sweep_stale_locks_removes_only_released_locks() {
        let locks = tempfile::tempdir().unwrap();
        let (alive_pid, dead_pid) = (555_555, 424_242);

        let _held = lock_file(locks.path(), alive_pid).unwrap();
        drop(lock_file(locks.path(), dead_pid).unwrap());

        sweep_stale_locks(locks.path());

        assert!(
            locks
                .path()
                .join(format!("nanosandbox-{alive_pid}.lock"))
                .exists()
        );
        assert!(
            !locks
                .path()
                .join(format!("nanosandbox-{dead_pid}.lock"))
                .exists()
        );
    }

    #[test]
    fn sweep_removes_only_leaves_whose_owner_lock_is_released() {
        let dir = tempfile::tempdir().unwrap();
        let locks = tempfile::tempdir().unwrap();
        let (alive_pid, dead_pid, unknown_pid) = (555_555, 424_242, 999_999);

        let _held = lock_file(locks.path(), alive_pid).unwrap();
        drop(lock_file(locks.path(), dead_pid).unwrap()); // acquired then released

        let our_leaf = dir
            .path()
            .join(format!("nanosandbox-supervisor-{}", std::process::id()));
        let alive_leaf = dir
            .path()
            .join(format!("nanosandbox-supervisor-{alive_pid}"));
        let dead_leaf = dir
            .path()
            .join(format!("nanosandbox-supervisor-{dead_pid}"));
        let unknown_leaf = dir
            .path()
            .join(format!("nanosandbox-supervisor-{unknown_pid}"));
        let unrelated = dir.path().join("something-else");
        for p in [
            &our_leaf,
            &alive_leaf,
            &dead_leaf,
            &unknown_leaf,
            &unrelated,
        ] {
            fs::create_dir(p).unwrap();
        }

        sweep_stale_leaves(
            dir.path(),
            |name| name.strip_prefix("nanosandbox-supervisor-"),
            |pid| owner_is_gone_in(locks.path(), pid),
            |_| {}, // a plain directory has no cgroup.kill; writing one would fill it
        );

        assert!(our_leaf.exists(), "must not remove our own leaf");
        assert!(
            alive_leaf.exists(),
            "must not remove a leaf whose owner still holds its lock"
        );
        assert!(
            unknown_leaf.exists(),
            "no lock file at all must not be removed"
        );
        assert!(unrelated.exists(), "must not touch unrelated entries");
        assert!(
            !dead_leaf.exists(),
            "must remove a leaf whose owner's lock is released"
        );
    }

    #[test]
    fn sweep_matches_the_sandbox_leaf_naming_scheme_too() {
        let dir = tempfile::tempdir().unwrap();
        let locks = tempfile::tempdir().unwrap();
        let dead_pid = 424_242;
        drop(lock_file(locks.path(), dead_pid).unwrap());

        let our_leaf = dir.path().join(format!("{}-0", std::process::id()));
        let dead_leaf = dir.path().join(format!("{dead_pid}-0"));
        for p in [&our_leaf, &dead_leaf] {
            fs::create_dir(p).unwrap();
        }

        sweep_stale_leaves(
            dir.path(),
            |name| name.split('-').next(),
            |pid| owner_is_gone_in(locks.path(), pid),
            |_| {},
        );

        assert!(our_leaf.exists());
        assert!(!dead_leaf.exists());
    }
}

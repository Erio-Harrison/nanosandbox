//! `private_tmp(size)` where no tmpfs can be mounted at /tmp (macOS, and Linux under AppArmor's
//! userns restriction). A fresh dir per run, pointed to by `TMPDIR`, stands in: private,
//! removed afterwards, and killed if polled size exceeds `size` (no ENOSPC without a fs).
//! Writes to `/tmp` by name still hit the host's `/tmp`.
//!
//! Dirs of runs that died uncleanly are removed by a sweep. Each run holds a `flock` on its dir;
//! the kernel drops it when the holder dies. That, not the pid in the name (reusable, possibly in
//! another namespace), says the owner is gone. See `sweep_stale`.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

const PREFIX: &str = "nanosandbox-tmp-";

/// Younger dirs aren't swept: the creator may not have taken the lock yet.
const STALE_AFTER: Duration = Duration::from_secs(120);

/// How often a process sweeps, at most.
const SWEEP_EVERY: Duration = Duration::from_secs(300);

/// Size check interval; walking the dir is costly and precision isn't needed. Closer once the
/// last walk found it past 60% of the limit.
const CHECK_INTERVAL: Duration = Duration::from_millis(250);
const CLOSE_CHECK_INTERVAL: Duration = Duration::from_millis(100);

pub(crate) struct PrivateTmp {
    dir: PathBuf,
    limit: u64,
    last_check: Instant,
    last_usage: u64,
    /// Lock showing the run is alive; `None` where the fs can't lock (a sweep then skips it).
    _lease: Option<File>,
}

impl PrivateTmp {
    /// Creates a 0700-style dir under the host's temp directory.
    pub(crate) fn create(limit: u64) -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let name = format!(
                "{PREFIX}{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let dir = container_dir()?.join(name);
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {
                    let lease = match take_lease(&dir) {
                        Ok(lease) => lease,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(e) => return Err(e),
                    };
                    sweep_if_due();
                    return Ok(Self {
                        dir,
                        limit,
                        last_check: Instant::now(),
                        last_usage: 0,
                        _lease: lease,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.dir
    }

    /// When the next size check is due.
    pub(crate) fn due(&self) -> Instant {
        self.last_check
            + if self.last_usage > self.limit / 10 * 6 {
                CLOSE_CHECK_INTERVAL
            } else {
                CHECK_INTERVAL
            }
    }

    /// Whether the dir exceeds the limit; measures only once `due`.
    pub(crate) fn over_limit(&mut self) -> bool {
        let now = Instant::now();
        if now < self.due() {
            return false;
        }
        self.last_check = now;
        self.last_usage = disk_usage(&self.dir);
        self.last_usage > self.limit
    }
}

impl Drop for PrivateTmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Non-blocking exclusive `flock`. `Ok(None)`: fs has no locks; `Err(WouldBlock)`: held.
fn take_lease(dir: &Path) -> std::io::Result<Option<File>> {
    let file = File::open(dir)?;
    match try_flock(&file) {
        Ok(true) => Ok(Some(file)),
        Ok(false) => Err(std::io::ErrorKind::WouldBlock.into()),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOLCK | libc::EOPNOTSUPP)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// `Ok(false)` when another open file description holds the lock.
pub(crate) fn try_flock(file: &File) -> std::io::Result<bool> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(false)
    } else {
        Err(e)
    }
}

/// Starts a background sweep unless this process swept lately.
fn sweep_if_due() {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    {
        let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
        if last.is_some_and(|t| t.elapsed() < SWEEP_EVERY) {
            return;
        }
        *last = Some(Instant::now());
    }
    let _ = std::thread::Builder::new()
        .name("nanosandbox-tmp-sweep".into())
        .spawn(|| {
            let removed = clean_stale();
            if removed > 0 {
                tracing::debug!(
                    removed,
                    "removed private temp directories left by dead runs"
                );
            }
        });
}

/// Dir holding every run's private dir; no run may read or write it except its own entry, so
/// one sandbox can't reach another's `$TMPDIR`. Must be outside `/tmp` on Linux (Landlock grants
/// it whole): runtime dir, else `~/.cache`, else `/tmp` fallback. Mode 0700.
pub(crate) fn container_dir() -> std::io::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let dir = container_location();
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

pub(crate) fn container_location() -> PathBuf {
    let temp = std::env::temp_dir();
    let temp = temp.canonicalize().unwrap_or(temp);
    #[cfg(target_os = "macos")]
    {
        temp.join("nanosandbox-tmp")
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(run) = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|d| d.is_absolute() && d.is_dir())
        {
            return run.join("nanosandbox-tmp");
        }
        if let Some(home) = super::read_rules::home_dir().filter(|h| h.is_absolute()) {
            return home.join(".cache").join("nanosandbox-tmp");
        }
        temp.join(format!("nanosandbox-tmp-{}", unsafe { libc::geteuid() }))
    }
}

/// Temp dirs a dead run may have used: this process's, plus `/tmp` on Linux. Not macOS's
/// per-user default: `confstr(_CS_DARWIN_USER_TEMP_DIR)` got ~1 in 5 runs killed.
fn temp_roots() -> Vec<PathBuf> {
    let mut roots = vec![std::env::temp_dir()];
    #[cfg(not(target_os = "macos"))]
    roots.push(PathBuf::from("/tmp"));
    let mut seen = Vec::new();
    roots.retain(|r| {
        let key = std::fs::canonicalize(r).unwrap_or_else(|_| r.clone());
        let new = !seen.contains(&key);
        seen.push(key);
        new
    });
    roots
}

/// Sweeps every candidate temp dir; returns how many dirs were removed.
pub(crate) fn clean_stale() -> usize {
    #[cfg(target_os = "macos")]
    let markers = super::macos::run_marker::markers_dir()
        .map(|d| sweep_markers(&d, STALE_AFTER))
        .unwrap_or(0);
    #[cfg(not(target_os = "macos"))]
    let markers = 0;
    // Pre-0.3.4 private dirs sat in the temp dir itself.
    let own = container_location();
    let here = if own.is_dir() {
        sweep_stale(&own, STALE_AFTER)
    } else {
        0
    };
    here + temp_roots()
        .iter()
        .map(|r| {
            // Pre-0.3.3 markers sat in the temp dir itself.
            #[cfg(target_os = "macos")]
            let old_markers = sweep_markers(r, STALE_AFTER);
            #[cfg(not(target_os = "macos"))]
            let old_markers = 0;
            sweep_stale(r, STALE_AFTER) + old_markers
        })
        .sum::<usize>()
        + markers
}

/// Removes private dirs under `parent` whose owner is gone; returns the count. Conservative:
/// only real dirs named like ours, owned by this user, at least `min_age` old, with a takeable
/// `flock`. Leaving a dir costs disk; removing a live run's costs that run.
fn sweep_stale(parent: &Path, min_age: Duration) -> usize {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let me = unsafe { libc::geteuid() };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(PREFIX) {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() || meta.uid() != me {
            continue;
        }
        let old_enough = meta
            .modified()
            .ok()
            .and_then(|m| SystemTime::now().duration_since(m).ok())
            .is_some_and(|age| age >= min_age);
        if !old_enough {
            continue;
        }
        // Lock what we looked at, not what the name points to now.
        let Ok(dir) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&path)
        else {
            continue;
        };
        match dir.metadata() {
            Ok(m) if (m.dev(), m.ino()) == (meta.dev(), meta.ino()) => {}
            _ => continue,
        }
        if !matches!(try_flock(&dir), Ok(true)) {
            continue;
        }
        if std::fs::remove_dir_all(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Removes run markers (macOS) left by killed runs, killing their orphans first: a pair goes if
/// its `-in` lock can be taken; a lone `-out` goes once old enough.
#[cfg(target_os = "macos")]
fn sweep_markers(parent: &Path, min_age: Duration) -> usize {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    const MARKER: &str = "nanosandbox-run-";
    let me = unsafe { libc::geteuid() };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name
            .strip_prefix(MARKER)
            .and_then(|n| n.strip_suffix("-in").or_else(|| n.strip_suffix("-out")))
        else {
            continue;
        };
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        let old = meta
            .modified()
            .ok()
            .and_then(|m| SystemTime::now().duration_since(m).ok())
            .is_some_and(|age| age >= min_age);
        if !meta.is_file() || meta.uid() != me || !old {
            continue;
        }
        let in_path = parent.join(format!("{MARKER}{stem}-in"));
        let out_path = parent.join(format!("{MARKER}{stem}-out"));
        if name.ends_with("-out") && in_path.exists() {
            continue; // judged with its pair, via the `-in` entry
        }
        if name.ends_with("-in") {
            let Ok(file) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&in_path)
            else {
                continue;
            };
            match file.metadata() {
                Ok(m) if (m.dev(), m.ino()) == (meta.dev(), meta.ino()) => {}
                _ => continue,
            }
            if !matches!(try_flock(&file), Ok(true)) {
                continue;
            }
            // Host gone: orphans are only findable via these files, so kill them first.
            let killed = super::macos::run_marker::kill_orphans(&in_path, &out_path);
            if killed > 0 {
                tracing::debug!(killed, "killed processes a dead run left behind");
            }
            if std::fs::remove_file(&in_path).is_ok() {
                removed += 1;
            }
        }
        if std::fs::remove_file(&out_path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Disk bytes under `dir` as a tmpfs counts them (sparse files by blocks); no symlinks.
fn disk_usage(dir: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let mut total = 0;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            total += meta.blocks() * 512;
            if meta.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_tmp_is_private_measured_and_removed() {
        let mut tmp = PrivateTmp::create(64 * 1024).unwrap();
        let dir = tmp.path().to_path_buf();
        assert!(dir.is_dir());
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }

        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/big"), vec![1u8; 256 * 1024]).unwrap();
        tmp.last_check -= CHECK_INTERVAL;
        assert!(tmp.over_limit());
        assert!(!tmp.over_limit());

        drop(tmp);
        assert!(!dir.exists());
    }

    fn fake_run_dir(parent: &Path, name: &str) -> PathBuf {
        let dir = parent.join(format!("{PREFIX}{name}"));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("file"), b"x").unwrap();
        dir
    }

    fn sweep(parent: &Path) -> usize {
        sweep_stale(parent, Duration::ZERO)
    }

    /// Sweeps until `want` dirs have gone or a few seconds pass; a forked child briefly holds
    /// a copy of the lease, which only delays removal.
    fn sweep_until(parent: &Path, want: usize) -> usize {
        let mut total = 0;
        for _ in 0..200 {
            total += sweep(parent);
            if total >= want {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        total
    }

    #[test]
    fn a_directory_nothing_holds_is_swept_and_a_held_one_is_not() {
        let parent = tempfile::tempdir().unwrap();
        let dead = fake_run_dir(parent.path(), "1-0");
        let live = fake_run_dir(parent.path(), "2-0");
        let lease = take_lease(&live).unwrap();
        assert!(lease.is_some());

        assert_eq!(sweep(parent.path()), 1);
        assert!(!dead.exists());
        assert!(live.exists(), "swept a directory something was holding");

        drop(lease);
        assert_eq!(sweep_until(parent.path(), 1), 1);
        assert!(!live.exists());
    }

    #[test]
    fn the_roots_swept_are_listed_once() {
        let roots = temp_roots();
        let canon: Vec<_> = roots
            .iter()
            .map(|r| std::fs::canonicalize(r).unwrap_or_else(|_| r.clone()))
            .collect();
        for (i, c) in canon.iter().enumerate() {
            assert!(!canon[i + 1..].contains(c), "{c:?} listed twice");
        }
        assert!(roots.contains(&std::env::temp_dir()));
        #[cfg(target_os = "macos")]
        assert!(
            roots
                .iter()
                .any(|r| r.to_string_lossy().contains("/var/folders/"))
        );
        #[cfg(not(target_os = "macos"))]
        assert!(canon.contains(&std::fs::canonicalize("/tmp").unwrap()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn leftover_run_markers_go_unless_held() {
        let root = tempfile::tempdir().unwrap();
        let age = |p: &Path| {
            let old = SystemTime::now() - Duration::from_secs(3600);
            File::open(p).unwrap().set_modified(old).unwrap();
        };
        for stem in ["nanosandbox-run-1-0", "nanosandbox-run-1-1"] {
            for suffix in ["in", "out"] {
                let p = root.path().join(format!("{stem}-{suffix}"));
                File::create(&p).unwrap();
                age(&p);
            }
        }
        let held = File::open(root.path().join("nanosandbox-run-1-1-in")).unwrap();
        assert!(try_flock(&held).unwrap());
        assert_eq!(sweep_markers(root.path(), Duration::from_secs(120)), 2);
        assert!(!root.path().join("nanosandbox-run-1-0-in").exists());
        assert!(!root.path().join("nanosandbox-run-1-0-out").exists());
        assert!(
            root.path().join("nanosandbox-run-1-1-in").exists()
                && root.path().join("nanosandbox-run-1-1-out").exists(),
            "SAFETY: a held run's markers were removed"
        );
    }

    #[test]
    fn a_young_directory_is_left_alone_even_with_nothing_holding_it() {
        let parent = tempfile::tempdir().unwrap();
        let fresh = fake_run_dir(parent.path(), "3-0");
        assert_eq!(sweep_stale(parent.path(), Duration::from_secs(3600)), 0);
        assert!(fresh.exists());
    }

    #[test]
    fn only_real_directories_of_ours_by_name_are_touched() {
        let parent = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        std::fs::write(victim.path().join("precious"), b"keep").unwrap();
        std::os::unix::fs::symlink(victim.path(), parent.path().join(format!("{PREFIX}evil")))
            .unwrap();
        std::fs::write(parent.path().join(format!("{PREFIX}file")), b"x").unwrap();
        let other = parent.path().join("someone-elses-dir");
        std::fs::create_dir(&other).unwrap();
        let near = parent.path().join("nanosandbox-tmp");
        std::fs::create_dir(&near).unwrap();

        assert_eq!(sweep(parent.path()), 0);
        assert!(
            victim.path().join("precious").exists(),
            "followed a symlink"
        );
        assert!(parent.path().join(format!("{PREFIX}file")).exists());
        assert!(other.exists() && near.exists());
    }

    #[test]
    fn a_private_tmp_holds_its_lease_until_it_is_gone() {
        let tmp = PrivateTmp::create(1).unwrap();
        let dir = tmp.path().to_path_buf();
        let other = File::open(&dir).unwrap();
        assert!(!try_flock(&other).unwrap());
        drop(other);
        assert!(dir.exists());
        sweep(dir.parent().unwrap());
        assert!(dir.exists(), "a sweep removed a live run's directory");
        drop(tmp);
        assert!(!dir.exists());
    }

    /// Helper process for the multi-process test: holds a lease until killed.
    #[test]
    fn lease_holder_helper() {
        let Some(dir) = std::env::var_os("NSB_LEASE_HOLD_DIR") else {
            return;
        };
        let lease = take_lease(Path::new(&dir)).unwrap();
        assert!(lease.is_some());
        println!("lease-held");
        std::thread::sleep(Duration::from_secs(120));
    }

    /// A sweep removes the killed agent's dir and none of the live ones'.
    #[test]
    fn a_sweep_removes_only_the_killed_agents_directory() {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};

        let parent = tempfile::tempdir().unwrap();
        let name = format!(
            "{}::lease_holder_helper",
            module_path!().split_once("::").unwrap().1
        );
        let spawn_holder = |dir: &Path| {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env("NSB_LEASE_HOLD_DIR", dir)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
            while let Some(Ok(line)) = lines.next() {
                if line.contains("lease-held") {
                    return (child, lines);
                }
            }
            let _ = child.kill();
            let _ = child.wait();
            panic!("the holder never took its lease");
        };

        let dirs: Vec<PathBuf> = (0..3)
            .map(|i| fake_run_dir(parent.path(), &format!("agent{i}-0")))
            .collect();
        let mut agents: Vec<_> = dirs.iter().map(|d| spawn_holder(d)).collect();

        assert_eq!(sweep(parent.path()), 0);
        assert!(dirs.iter().all(|d| d.exists()));

        let (mut dead, _keep_pipe) = agents.remove(1);
        dead.kill().unwrap();
        dead.wait().unwrap();

        assert_eq!(sweep_until(parent.path(), 1), 1);
        assert!(!dirs[1].exists(), "the dead agent's directory should go");
        assert!(dirs[0].exists() && dirs[2].exists(), "a live agent's went");

        for (mut child, _) in agents {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        assert_eq!(sweep_until(parent.path(), 2), 2);
    }

    #[test]
    fn test_each_run_gets_its_own_directory() {
        let a = PrivateTmp::create(1).unwrap();
        let b = PrivateTmp::create(1).unwrap();
        assert_ne!(a.path(), b.path());
    }
}

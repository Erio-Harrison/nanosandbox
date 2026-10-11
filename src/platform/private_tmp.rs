//! `private_tmp(size)` where no tmpfs can be mounted at /tmp: on macOS, and
//! on Linux where AppArmor denies mounting in the sandbox's user namespace.
//!
//! A fresh directory per run stands in for the tmpfs. `TMPDIR` points at it,
//! so programs that find their temp directory that way (python's tempfile,
//! node, Go, gcc, clang, mktemp...) get the three things a tmpfs gives: it's
//! private to the run, it's gone afterwards, and it can't grow past `size`.
//! The size is checked periodically while the program runs, and the program
//! is killed if it's over, since there is no file system to report ENOSPC.
//!
//! A program that writes to `/tmp` by name still gets the host's `/tmp`, as
//! without a tmpfs: making that read-only would break it instead.
//!
//! A directory is removed when its run ends, but not when the host process
//! doesn't get to (SIGKILL, SIGTERM, Ctrl-C, a client closing the server's
//! stdin mid-run): then it's left behind. So each run holds a `flock` on its
//! directory for as long as it lives, and a sweep, run by whichever process
//! creates a directory next, removes the ones it can take the lock on. The
//! kernel drops the lock when its holder dies, however it dies. That, not
//! the pid in the directory's name, is what says an owner is gone: a pid may
//! be reused, or belong to a process in another pid namespace or user that
//! this one can't see, and treating a live run as dead deletes its directory
//! under it. See `sweep_stale` for what else it checks before removing.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

const PREFIX: &str = "nanosandbox-tmp-";

/// A directory younger than this isn't swept even if nothing holds its lock:
/// the creator may not have taken it yet.
const STALE_AFTER: Duration = Duration::from_secs(120);

/// How often a process sweeps, at most.
const SWEEP_EVERY: Duration = Duration::from_secs(300);

/// How often the directory's size is measured. Walking it costs more than
/// the wait loop's other checks, and a tmpfs limit is about not filling the
/// disk, not about precision.
const CHECK_INTERVAL: Duration = Duration::from_millis(250);

pub(crate) struct PrivateTmp {
    dir: PathBuf,
    limit: u64,
    last_check: Instant,
    /// The lock that says this run is alive. `None` where the file system
    /// can't lock: a sweep can't take one either, and then leaves it alone.
    _lease: Option<File>,
}

impl PrivateTmp {
    /// Creates the directory, readable only by this user, under the host
    /// process's own temp directory.
    pub(crate) fn create(limit: u64) -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let name = format!(
                "{PREFIX}{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let dir = std::env::temp_dir().join(name);
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {
                    let lease = match take_lease(&dir) {
                        Ok(lease) => lease,
                        // Something else already holds it: not ours to use.
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(e) => return Err(e),
                    };
                    sweep_if_due();
                    return Ok(Self {
                        dir,
                        limit,
                        last_check: Instant::now(),
                        _lease: lease,
                    });
                }
                // Left over from an earlier process with the same pid.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.dir
    }

    /// Whether the directory has grown past the limit. Measures at most once
    /// per `CHECK_INTERVAL`; in between, says no.
    pub(crate) fn over_limit(&mut self) -> bool {
        if self.last_check.elapsed() < CHECK_INTERVAL {
            return false;
        }
        self.last_check = Instant::now();
        disk_usage(&self.dir) > self.limit
    }
}

impl Drop for PrivateTmp {
    fn drop(&mut self) {
        // Doesn't follow symlinks the program may have left in it.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// `flock`s `dir` exclusively and non-blockingly. `Ok(None)`: this file system
/// has no locks to take. `Err(WouldBlock)`: someone holds it.
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
fn try_flock(file: &File) -> std::io::Result<bool> {
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

/// Starts a sweep of the temp directory unless this process swept lately,
/// off to the side so a run doesn't wait on deleting what an earlier one left.
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

/// The temp directories a run may have been using: this process's, and on
/// Linux `/tmp` too, since `TMPDIR` may have been different when a dead run
/// started. Not macOS's per-user default: `confstr(_CS_DARWIN_USER_TEMP_DIR)`,
/// the way to ask for it, got about one run in five killed when called as a
/// run started.
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

/// Sweeps every temp directory a run may have used; returns how many
/// directories it removed. See `sweep_stale` for what it leaves alone.
pub(crate) fn clean_stale() -> usize {
    temp_roots()
        .iter()
        .map(|r| sweep_stale(r, STALE_AFTER))
        .sum()
}

/// Removes the private directories under `parent` whose owner is gone, and
/// returns how many. Best effort, and conservative: a directory is only
/// removed if
/// - it's named like one of ours, is a real directory (not a symlink) and is
///   this user's;
/// - it was last modified at least `min_age` ago; and
/// - its `flock` can be taken here, which means nothing is holding it.
///
/// Anything it can't establish, it leaves. Leaving a directory costs some
/// disk; removing a live run's costs that run.
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
        // Lock the thing we looked at, not whatever the name points to by now.
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
        // Doesn't follow symlinks the program may have left in it.
        if std::fs::remove_dir_all(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Bytes allocated on disk under `dir`, as a tmpfs counts them: a sparse
/// file only counts the blocks it actually uses. Symlinks aren't followed.
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
        // Not measured again right away.
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

    /// Sweeps until `want` directories have gone, or a few seconds pass. A
    /// lock isn't free the instant its holder lets go of it: a process another
    /// thread has just forked holds a copy of every open fd until it execs,
    /// this one's lease included. That only ever delays a removal, never
    /// brings one forward, which is the safe way round for a sweep, but a
    /// test mustn't assume it's instant.
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

        // Once the holder lets go -- or dies -- it's fair game.
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
        // A symlink named like ours, pointing at someone's directory.
        std::os::unix::fs::symlink(victim.path(), parent.path().join(format!("{PREFIX}evil")))
            .unwrap();
        // A file, not a directory; and directories with other names.
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
        // Another open of the same directory can't take the lock.
        let other = File::open(&dir).unwrap();
        assert!(!try_flock(&other).unwrap());
        drop(other);
        // So a sweep, even a zero-age one, leaves it.
        assert!(dir.exists());
        sweep(dir.parent().unwrap());
        assert!(dir.exists(), "a sweep removed a live run's directory");
        drop(tmp);
        assert!(!dir.exists());
    }

    /// Not a test by itself: the other process the multi-process test starts.
    /// It takes the lease on a directory and holds it until it's killed.
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

    /// Several agents on one machine, each running; one is killed outright.
    /// A sweep removes that one's directory and none of the others'.
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

        // Everyone alive: nothing goes, whatever the age.
        assert_eq!(sweep(parent.path()), 0);
        assert!(dirs.iter().all(|d| d.exists()));

        // One is killed outright (no chance to clean up).
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

//! `tmpfs("/tmp", size)` where no private mount is possible: on macOS, and on
//! Linux where AppArmor denies mounting in the sandbox's user namespace.
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

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How often the directory's size is measured. Walking it costs more than
/// the wait loop's other checks, and a tmpfs limit is about not filling the
/// disk, not about precision.
const CHECK_INTERVAL: Duration = Duration::from_millis(250);

/// The size of a `tmpfs("/tmp", size)` in the config, if it has one.
pub(crate) fn requested(config: &crate::builder::SandboxConfig) -> Option<u64> {
    config
        .tmpfs_mounts
        .iter()
        .rev()
        .find(|(path, _)| is_tmp(path))
        .map(|(_, size)| *size)
}

/// `/tmp`, or `/private/tmp` that it links to on macOS.
pub(crate) fn is_tmp(path: &Path) -> bool {
    path == Path::new("/tmp") || path == Path::new("/private/tmp")
}

pub(crate) struct PrivateTmp {
    dir: PathBuf,
    limit: u64,
    last_check: Instant,
}

impl PrivateTmp {
    /// Creates the directory, readable only by this user, under the host
    /// process's own temp directory.
    pub(crate) fn create(limit: u64) -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let name = format!(
                "nanosandbox-tmp-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let dir = std::env::temp_dir().join(name);
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {
                    return Ok(Self {
                        dir,
                        limit,
                        last_check: Instant::now(),
                    })
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

    #[test]
    fn test_each_run_gets_its_own_directory() {
        let a = PrivateTmp::create(1).unwrap();
        let b = PrivateTmp::create(1).unwrap();
        assert_ne!(a.path(), b.path());
    }
}

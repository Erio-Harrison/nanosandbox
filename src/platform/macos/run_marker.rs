//! Finds every process of one run, wherever it went.
//!
//! Walking the process tree from the run's first process misses one that
//! left its process group and whose parent exited: it's been reparented to
//! launchd by then (`setpgrp(); sleep &`, then exit). macOS has no cgroups
//! and no subreaper. What every process of a run does keep is its sandbox:
//! sandbox-exec's profile is inherited by all descendants and can't be left.
//!
//! So each run's profile denies `file-read-metadata` on a file made for that
//! run alone, and allows it on a second one next to it; `sandbox_check` asks
//! any process about both. Only the run's own processes are denied the first
//! and allowed the second. Asking about just one isn't enough: an app's own
//! sandbox (App Sandbox) can't read this temp directory at all, and comes
//! out denied too. Confirmed for real: three of the user's apps did. Both
//! files have to exist: for a missing path, sandbox_check reports 1 for
//! every process, sandboxed or not.

use std::ffi::CString;
use std::path::{Path, PathBuf};

extern "C" {
    /// libsystem_sandbox: 0 if `pid` may do `operation` (on the filter's
    /// argument), 1 if not; for a process without a sandbox, 0.
    fn sandbox_check(
        pid: libc::pid_t,
        operation: *const libc::c_char,
        filter: libc::c_int,
        ...
    ) -> libc::c_int;
}

const SANDBOX_FILTER_NONE: libc::c_int = 0;
const SANDBOX_FILTER_PATH: libc::c_int = 1;
/// Don't log the denial: this is only a question.
const SANDBOX_CHECK_NO_REPORT: libc::c_int = 0x4000_0000;
const PROC_UID_ONLY: u32 = 4;

/// The run's marker files, removed when dropped.
pub(super) struct RunMarker {
    /// Denied to the run.
    denied: PathBuf,
    denied_c: CString,
    /// Allowed to the run, as a control.
    allowed: PathBuf,
    allowed_c: CString,
}

impl RunMarker {
    pub(super) fn create() -> std::io::Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let name = format!(
                "nanosandbox-run-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let dir = std::env::temp_dir();
            let create = |suffix: &str| -> std::io::Result<(PathBuf, CString)> {
                let path = dir.join(format!("{name}-{suffix}"));
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)?;
                // The profile and sandbox_check both see the real path.
                let path = path.canonicalize()?;
                let c = CString::new(path.as_os_str().as_encoded_bytes())
                    .map_err(std::io::Error::other)?;
                Ok((path, c))
            };
            match create("in") {
                Ok((denied, denied_c)) => {
                    let (allowed, allowed_c) = match create("out") {
                        Ok(created) => created,
                        Err(e) => {
                            let _ = std::fs::remove_file(&denied);
                            return Err(e);
                        }
                    };
                    return Ok(Self {
                        denied,
                        denied_c,
                        allowed,
                        allowed_c,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// The profile rules that mark the run.
    pub(super) fn rules(&self) -> [(&'static str, &Path); 2] {
        [
            (
                "(deny file-read-metadata (literal (param \"{}\")))",
                &self.denied,
            ),
            (
                "(allow file-read-metadata (literal (param \"{}\")))",
                &self.allowed,
            ),
        ]
    }

    fn check(pid: libc::pid_t, path: &CString) -> libc::c_int {
        unsafe {
            sandbox_check(
                pid,
                c"file-read-metadata".as_ptr(),
                SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT,
                path.as_ptr(),
            )
        }
    }

    /// Whether `pid` is denied the one file and allowed the other.
    fn marked(&self, pid: libc::pid_t) -> bool {
        Self::check(pid, &self.denied_c) == 1 && Self::check(pid, &self.allowed_c) == 0
    }

    /// This user's processes that are in the run's sandbox. Empty if the
    /// check can't be trusted: if a marker file is gone, or this process
    /// (which has no such sandbox) doesn't come out allowed both.
    pub(super) fn members(&self) -> Vec<libc::pid_t> {
        let me = std::process::id() as libc::pid_t;
        let intact = self.denied.exists() && self.allowed.exists();
        if !intact || Self::check(me, &self.denied_c) != 0 || Self::check(me, &self.allowed_c) != 0
        {
            return Vec::new();
        }
        let uid = unsafe { libc::geteuid() };
        super::MacOSExecutor::list_pids(PROC_UID_ONLY, uid)
            .into_iter()
            .filter(|&pid| pid != me)
            .filter(|&pid| {
                let sandboxed =
                    unsafe { sandbox_check(pid, std::ptr::null(), SANDBOX_FILTER_NONE) } == 1;
                sandboxed && self.marked(pid)
            })
            .collect()
    }
}

impl Drop for RunMarker {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.denied);
        let _ = std::fs::remove_file(&self.allowed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};

    /// sandbox-exec running `script`, under a profile with `marker`'s rules.
    fn sandboxed(marker: Option<&RunMarker>, script: &str) -> Child {
        let rules: String = marker
            .map(|m| {
                m.rules()
                    .iter()
                    .map(|(rule, path)| {
                        rule.replace("(param \"{}\")", &format!("\"{}\"", path.display()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let profile = format!("(version 1)(allow default){rules}");
        Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &profile, "/bin/sh", "-c", script])
            .spawn()
            .unwrap()
    }

    /// Only checks; sends no signals except to its own children, through
    /// their handles.
    #[test]
    fn test_members_are_exactly_the_runs_processes() {
        let marker = RunMarker::create().unwrap();
        // The run: a child that leaves the process group, outliving its
        // parent. Its pid comes back through a file.
        let pid_file = marker.denied.with_extension("pid");
        let mut run = sandboxed(
            Some(&marker),
            &format!(
                "perl -e 'setpgrp(0,0); sleep 5' & echo $! > '{}'; exit 0",
                pid_file.display()
            ),
        );
        // Not the run: another sandbox, and a process with none.
        let mut other = sandboxed(None, "sleep 5");
        let mut plain = Command::new("/bin/sleep").arg("5").spawn().unwrap();

        run.wait().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let escaped: libc::pid_t = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let _ = std::fs::remove_file(&pid_file);

        let members = marker.members();

        // Clean up before asserting: the escapee by the pid it reported, the
        // rest by their handles.
        unsafe {
            libc::kill(escaped, libc::SIGKILL);
        }
        for c in [&mut other, &mut plain] {
            let _ = c.kill();
            let _ = c.wait();
        }

        assert_eq!(members, vec![escaped]);
    }

    #[test]
    fn test_members_includes_the_still_running_root_itself() {
        let marker = RunMarker::create().unwrap();
        let mut root = sandboxed(Some(&marker), "sleep 5");
        std::thread::sleep(std::time::Duration::from_millis(300));

        let members = marker.members();
        let root_included = members.contains(&(root.id() as libc::pid_t));

        let _ = root.kill();
        let _ = root.wait();

        assert!(
            root_included,
            "root's own pid {} missing from members: {:?}",
            root.id(),
            members
        );
    }

    #[test]
    fn test_no_members_without_the_marker_file() {
        let marker = RunMarker::create().unwrap();
        std::fs::remove_file(&marker.denied).unwrap();
        assert!(marker.members().is_empty());
    }
}

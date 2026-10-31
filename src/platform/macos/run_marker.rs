//! Finds every process of one run, including ones reparented to launchd.
//! Each run's profile denies `file-read-metadata` on one marker file and allows it on a second;
//! `sandbox_check` on both identifies the run (the sandbox is inherited and can't be left).
//! Both are needed (App Sandbox apps are denied the first too), and both files must exist,
//! else sandbox_check returns 1 for every process.

use std::ffi::CString;
use std::path::{Path, PathBuf};

unsafe extern "C" {
    /// libsystem_sandbox: 0 if allowed, 1 if denied; 0 without a sandbox.
    fn sandbox_check(
        pid: libc::pid_t,
        operation: *const libc::c_char,
        filter: libc::c_int,
        ...
    ) -> libc::c_int;
}

const SANDBOX_FILTER_NONE: libc::c_int = 0;
const SANDBOX_FILTER_PATH: libc::c_int = 1;
/// Don't log the denial.
const SANDBOX_CHECK_NO_REPORT: libc::c_int = 0x4000_0000;
const PROC_UID_ONLY: u32 = 4;

/// Dir for run markers; no profile lets a command write it, so one run can't delete
/// another's markers. Mode 0700.
pub(crate) fn markers_dir() -> std::io::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir()
        .canonicalize()
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("nanosandbox-markers");
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

/// The run's marker files, removed when dropped.
pub(super) struct RunMarker {
    denied: PathBuf,
    denied_c: CString,
    allowed: PathBuf,
    allowed_c: CString,
    /// Held for the run's life so a sweep can tell live markers from a killed host's.
    /// `None` where the fs can't lock.
    _lease: Option<std::fs::File>,
    /// Leave the files for the sweep: processes of the run outlived its kill.
    keep: bool,
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
            let dir = markers_dir()?;
            let create = |suffix: &str| -> std::io::Result<(PathBuf, CString, std::fs::File)> {
                let path = dir.join(format!("{name}-{suffix}"));
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)?;
                let path = path.canonicalize()?;
                let c = CString::new(path.as_os_str().as_encoded_bytes())
                    .map_err(std::io::Error::other)?;
                Ok((path, c, file))
            };
            match create("in") {
                Ok((denied, denied_c, file)) => {
                    let lease = crate::platform::private_tmp::try_flock(&file)
                        .is_ok_and(|locked| locked)
                        .then_some(file);
                    let (allowed, allowed_c, _) = match create("out") {
                        Ok(created) => created,
                        Err(e) => {
                            let _ = std::fs::remove_file(&denied);
                            return Err(e);
                        }
                    };
                    // Dead runs' markers (and the processes carrying them) are swept from here,
                    // not only from private_tmp: a run without one must sweep too.
                    crate::platform::private_tmp::sweep_if_due();
                    return Ok(Self {
                        denied,
                        denied_c,
                        allowed,
                        allowed_c,
                        _lease: lease,
                        keep: false,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Profile rules that mark the run and stop it touching the markers.
    pub(super) fn rules(&self) -> [(&'static str, &Path); 4] {
        [
            (
                "(deny file-read-metadata (literal (param \"{}\")))",
                &self.denied,
            ),
            (
                "(allow file-read-metadata (literal (param \"{}\")))",
                &self.allowed,
            ),
            // Else the run could delete a marker and escape `members()`.
            ("(deny file-write* (literal (param \"{}\")))", &self.denied),
            ("(deny file-write* (literal (param \"{}\")))", &self.allowed),
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

    /// This user's processes in the run's sandbox; empty if the check can't be trusted.
    pub(super) fn members(&self) -> Vec<libc::pid_t> {
        members_marked_by(&self.denied, &self.denied_c, &self.allowed, &self.allowed_c)
    }
}

fn members_marked_by(
    denied: &Path,
    denied_c: &CString,
    allowed: &Path,
    allowed_c: &CString,
) -> Vec<libc::pid_t> {
    let me = std::process::id() as libc::pid_t;
    let intact = denied.exists() && allowed.exists();
    if !intact || RunMarker::check(me, denied_c) != 0 || RunMarker::check(me, allowed_c) != 0 {
        return Vec::new();
    }
    let uid = unsafe { libc::geteuid() };
    super::MacOSExecutor::list_pids(PROC_UID_ONLY, uid)
        .into_iter()
        .filter(|&pid| pid != me)
        .filter(|&pid| {
            let sandboxed =
                unsafe { sandbox_check(pid, std::ptr::null(), SANDBOX_FILTER_NONE) } == 1;
            sandboxed
                && RunMarker::check(pid, denied_c) == 1
                && RunMarker::check(pid, allowed_c) == 0
        })
        .collect()
}

/// Kills processes left by a dead host's run (e.g. after setsid), found by its marker pair;
/// run before the sweep removes the markers. Returns the count killed.
pub(crate) fn kill_orphans(denied: &Path, allowed: &Path) -> usize {
    let canon = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    let (denied, allowed) = (canon(denied), canon(allowed));
    let Ok(denied_c) = CString::new(denied.as_os_str().as_encoded_bytes()) else {
        return 0;
    };
    let Ok(allowed_c) = CString::new(allowed.as_os_str().as_encoded_bytes()) else {
        return 0;
    };
    let mut killed = std::collections::HashSet::new();
    let deadline = std::time::Instant::now() + super::wait::KILL_RUN_LIMIT;
    while std::time::Instant::now() < deadline {
        let members = members_marked_by(&denied, &denied_c, &allowed, &allowed_c);
        if members.is_empty() {
            break;
        }
        for &pid in &members {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            killed.insert(pid);
        }
        super::kqueue::wait_for_exits(&members, deadline);
    }
    killed.len()
}

impl RunMarker {
    /// Don't remove the marker files on drop: processes still carry them, and the next sweep
    /// (`kill_orphans`, once the lease is seen released) kills what they mark.
    pub(super) fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for RunMarker {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        let _ = std::fs::remove_file(&self.denied);
        let _ = std::fs::remove_file(&self.allowed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};

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

    #[test]
    fn test_a_run_cannot_remove_its_own_markers() {
        let marker = RunMarker::create().unwrap();
        let script = format!(
            "rm -f '{}' '{}' 2>/dev/null; mv '{}' '{}.x' 2>/dev/null; : > '{}' 2>/dev/null; exit 0",
            marker.denied.display(),
            marker.allowed.display(),
            marker.allowed.display(),
            marker.allowed.display(),
            marker.allowed.display(),
        );
        let mut run = sandboxed(Some(&marker), &script);
        run.wait().unwrap();
        assert!(marker.denied.exists(), "the denied marker was removed");
        assert!(
            marker.allowed.exists(),
            "the allowed marker was removed or renamed"
        );
        assert_eq!(
            std::fs::metadata(&marker.allowed).unwrap().len(),
            0,
            "the allowed marker was written"
        );
    }

    #[test]
    fn test_kill_orphans_ends_what_a_dead_runs_markers_still_mark() {
        let marker = RunMarker::create().unwrap();
        let mut run = sandboxed(Some(&marker), "sleep 300");
        let mut other = sandboxed(None, "sleep 300");
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(run.try_wait().unwrap().is_none(), "the run died on its own");

        let killed = kill_orphans(&marker.denied, &marker.allowed);
        assert!(killed >= 1, "killed {killed}");
        let status = run.wait().unwrap();
        assert!(!status.success(), "{status:?}");
        assert!(
            other.try_wait().unwrap().is_none(),
            "another run's process was killed"
        );
        let _ = other.kill();
        let _ = other.wait();
        std::fs::remove_file(&marker.allowed).unwrap();
        assert_eq!(kill_orphans(&marker.denied, &marker.allowed), 0);
    }

    #[test]
    fn test_members_are_exactly_the_runs_processes() {
        let marker = RunMarker::create().unwrap();
        // The run: a child that leaves the process group and outlives its parent.
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

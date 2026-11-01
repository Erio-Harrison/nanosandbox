//! Waiting for the sandboxed process and enforcing the limits the kernel doesn't (supervisor
//! thread; the I/O ends are the caller's, see `platform/supervise.rs`).

use crate::error::{Result, SandboxError};
use crate::platform::checks::{CPU_LIMIT_GRACE, cpu_check_due, poll_timeout_ms};
use crate::platform::private_tmp::PrivateTmp;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use super::{CgroupManager, read_raw};

/// How the sandboxed process ended, from `supervise`.
pub(super) struct Ended {
    pub(super) exit_code: i32,
    pub(super) killed_by_timeout: bool,
    pub(super) killed_by_tmp_limit: bool,
    pub(super) killed_by_cpu_limit: bool,
    pub(super) signal: Option<i32>,
    /// The init shim reported that it couldn't mount a private `/proc`.
    pub(super) proc_mount_failed: bool,
    pub(super) rusage: libc::rusage,
}

/// `cpu_time_limit` over the whole cgroup: RLIMIT_CPU is per process, so forking evades it.
/// `cpu.stat` works without the cpu controller.
pub(super) struct CpuLimit<'a> {
    pub(super) cgroup: &'a CgroupManager,
    pub(super) limit: Duration,
    /// CPUs the run can use at once: how fast its budget can go.
    pub(super) parallelism: u32,
}

/// What the init shim reported on `fd`: a 0 byte if it couldn't mount a private `/proc`
/// (before exec), then a signal number if the command died by one (just before exit).
fn read_reports(fd: RawFd) -> (Option<i32>, bool) {
    let mut bytes = [0u8; 8];
    let n = read_raw(fd, &mut bytes).unwrap_or(0);
    let bytes = &bytes[..n];
    let signal = bytes
        .iter()
        .rev()
        .find(|b| (1..=64).contains(*b))
        .map(|&b| i32::from(b));
    (signal, bytes.contains(&0))
}

/// The limit kills to report: none when the command exited by its own means, since a kill sent
/// just before then came too late to matter.
fn kills_reported(exited: bool, kills: (bool, bool, bool)) -> (bool, bool, bool) {
    if exited { (false, false, false) } else { kills }
}

/// A pidfd (kernel 5.3+), readable once `pid` has exited, so the loop wakes on the exit instead
/// of at a tick. None on older kernels, where the loop keeps a 10 ms tick for it.
fn exit_watch(pid: nix::unistd::Pid) -> Option<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Waits for `pid`, killing on `timeout`, `private_tmp` over size, or `cpu_limit` over budget.
///
/// Sleeps in `poll` on the pidfd until the earliest due check: the wall deadline (once), the
/// next `/tmp` size walk, the next CPU total read (see `checks.rs`). A run with only a wall
/// limit wakes for the exit and the deadline, and nothing else.
pub(super) fn supervise(
    pid: nix::unistd::Pid,
    signal_pipe: OwnedFd,
    timeout: Duration,
    mut private_tmp: Option<&mut PrivateTmp>,
    cpu_limit: Option<CpuLimit<'_>>,
) -> Result<Ended> {
    let start = Instant::now();
    let mut killed_by_timeout = false;
    let mut killed_by_tmp_limit = false;
    let mut killed_by_cpu_limit = false;
    let kill = || {
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
        unsafe {
            libc::kill(-(pid.as_raw()), libc::SIGKILL);
        }
    };
    unsafe {
        let fd = signal_pipe.as_raw_fd();
        libc::fcntl(
            fd,
            libc::F_SETFL,
            libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK,
        );
    }
    let exit_fd = exit_watch(pid);

    // Each check's next due time; None once it can't fire again.
    let mut deadline = Some(start + timeout);
    let mut cpu_due = cpu_limit
        .as_ref()
        .map(|c| cpu_check_due(start, Duration::ZERO, c.limit, c.parallelism));

    loop {
        let now = Instant::now();
        let mut wake = [
            deadline,
            cpu_due,
            private_tmp
                .as_ref()
                .filter(|_| !killed_by_tmp_limit)
                .map(|t| t.due()),
        ]
        .into_iter()
        .flatten()
        .min();
        if exit_fd.is_none() {
            // No pidfd: the exit can only be seen by wait4, so keep a tick.
            wake = Some(wake.map_or(now, |w| w.min(now + Duration::from_millis(10))));
        }
        let mut polled: Vec<libc::pollfd> = exit_fd
            .iter()
            .map(|fd| libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        unsafe {
            libc::poll(
                polled.as_mut_ptr(),
                polled.len() as libc::nfds_t,
                poll_timeout_ms(wake, now),
            );
        }

        // wait4 for rusage: the cpu_time/peak_memory source without a cgroup.
        let mut status: libc::c_int = 0;
        let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::wait4(pid.as_raw(), &mut status, libc::WNOHANG, &mut rusage) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SandboxError::Internal {
                context: format!("wait4 for child {pid}"),
                source: Box::new(err),
            });
        }
        let exited = ret == pid.as_raw() && libc::WIFEXITED(status);
        let signaled = ret == pid.as_raw() && libc::WIFSIGNALED(status);
        if exited || signaled {
            let (reported, proc_mount_failed) = read_reports(signal_pipe.as_raw_fd());
            let (code, signal) = if exited {
                // An exit by its own means the kill a limit sent (if any) came too late to
                // matter: init dies by SIGKILL when it did. Don't report a kill that didn't
                // happen alongside a normal exit code.
                (killed_by_timeout, killed_by_tmp_limit, killed_by_cpu_limit) = kills_reported(
                    true,
                    (killed_by_timeout, killed_by_tmp_limit, killed_by_cpu_limit),
                );
                (libc::WEXITSTATUS(status), reported)
            } else {
                let sig = libc::WTERMSIG(status);
                (128 + sig, Some(sig))
            };
            return Ok(Ended {
                exit_code: code,
                killed_by_timeout,
                killed_by_tmp_limit,
                killed_by_cpu_limit,
                signal,
                proc_mount_failed,
                rusage,
            });
        }
        if ret != 0 {
            continue;
        }

        // Still running: the checks that are due.
        let now = Instant::now();
        if let Some(tmp) = private_tmp.as_deref_mut()
            && !killed_by_tmp_limit
            && tmp.over_limit()
        {
            kill();
            killed_by_tmp_limit = true;
        }
        if let (Some(c), Some(due)) = (&cpu_limit, cpu_due)
            && now >= due
        {
            let used = c
                .cgroup
                .get_cpu_stats()
                .map(|s| Duration::from_micros(s.total_usec))
                .unwrap_or_default();
            if used > c.limit + CPU_LIMIT_GRACE {
                kill();
                killed_by_cpu_limit = true;
                cpu_due = None;
            } else {
                cpu_due = Some(cpu_check_due(now, used, c.limit, c.parallelism));
            }
        }
        if deadline.is_some_and(|d| now >= d) {
            // Child is PID-ns init: its death kills the rest. Kill the group too, just in case.
            kill();
            killed_by_timeout = true;
            deadline = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reports(bytes: &[u8]) -> (Option<i32>, bool) {
        let (read, write) = nix::unistd::pipe().unwrap();
        nix::unistd::write(&write, bytes).unwrap();
        drop(write);
        read_reports(read.as_raw_fd())
    }

    #[test]
    fn test_a_normal_exit_drops_the_limit_kills_that_came_too_late() {
        assert_eq!(
            kills_reported(true, (true, true, true)),
            (false, false, false)
        );
        assert_eq!(
            kills_reported(true, (false, true, false)),
            (false, false, false)
        );
        assert_eq!(
            kills_reported(false, (true, false, true)),
            (true, false, true)
        );
    }

    #[test]
    fn test_reports_carry_a_failed_proc_mount_and_the_signal() {
        assert_eq!(reports(&[]), (None, false));
        assert_eq!(reports(&[15]), (Some(15), false));
        assert_eq!(reports(&[0]), (None, true));
        assert_eq!(reports(&[0, 9]), (Some(9), true));
    }
}

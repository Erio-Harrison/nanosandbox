//! Feeding stdin, collecting output and waiting for the sandboxed process (parent side).

use crate::error::{Result, SandboxError};
use crate::platform::output::Captured;
use crate::platform::private_tmp::PrivateTmp;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use super::{CgroupManager, read_raw, write_raw};

/// See the cpu_limit check in `wait_with_timeout`.
const CPU_LIMIT_GRACE_USEC: u64 = 200_000;

/// How the sandboxed process ended, from `wait_with_timeout`.
pub(super) struct Waited {
    pub(super) stdout: String,
    pub(super) stderr: String,
    pub(super) exit_code: i32,
    pub(super) killed_by_timeout: bool,
    pub(super) killed_by_tmp_limit: bool,
    pub(super) killed_by_cpu_limit: bool,
    pub(super) signal: Option<i32>,
    /// The init shim reported that it couldn't mount a private `/proc`.
    pub(super) proc_mount_failed: bool,
    pub(super) rusage: libc::rusage,
    pub(super) output_truncated: bool,
}

/// The read ends of the pipes a run reports back on.
pub(super) struct ChildReads {
    pub(super) stdout: OwnedFd,
    pub(super) stderr: OwnedFd,
    /// See `reported_signal`.
    pub(super) signal: OwnedFd,
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

/// Reads from `fd` until it would block. False on EOF or error.
fn drain(fd: RawFd, out: &mut Captured) -> bool {
    let mut buf = [0u8; 64 * 1024];
    loop {
        match read_raw(fd, &mut buf) {
            Ok(0) => return false,
            Ok(n) => out.push(&buf[..n]),
            Err(nix::errno::Errno::EAGAIN) => return true,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => return false,
        }
    }
}

/// Feeds stdin, collects output and waits, killing on `timeout`, `private_tmp` over size, or
/// (`cpu_limit`) cgroup CPU time over `cpu_time_limit` (RLIMIT_CPU only catches one process).
///
/// Polls the pipes and drains each when ready; fixed 4 KB reads per 10 ms starved large output.
pub(super) fn wait_with_timeout(
    pid: nix::unistd::Pid,
    reads: ChildReads,
    mut stdin: Option<(OwnedFd, &[u8])>,
    timeout: Duration,
    mut private_tmp: Option<&mut PrivateTmp>,
    max_output: u64,
    cpu_limit: Option<(&CgroupManager, u64)>,
) -> Result<Waited> {
    let start = Instant::now();
    let ChildReads {
        stdout,
        stderr,
        signal: signal_pipe,
    } = reads;
    let outputs = [stdout, stderr];
    let mut captured = [Captured::new(max_output), Captured::new(max_output)];
    let mut open = [true, true];
    let mut killed_by_timeout = false;
    let mut killed_by_tmp_limit = false;
    // Whole-cgroup total: RLIMIT_CPU is per process, so forking evades it. cpu.stat works
    // without the cpu controller.
    let mut killed_by_cpu_limit = false;
    let kill = || {
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
        unsafe {
            libc::kill(-(pid.as_raw()), libc::SIGKILL);
        }
    };

    let set_nonblocking = |fd: RawFd| unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    };
    let fds = [outputs[0].as_raw_fd(), outputs[1].as_raw_fd()];
    fds.iter().for_each(|&fd| set_nonblocking(fd));
    set_nonblocking(signal_pipe.as_raw_fd());
    if let Some((fd, _)) = &stdin {
        set_nonblocking(fd.as_raw_fd());
    }

    loop {
        // Up to 10 ms; the timeout checks below run at least that often.
        let mut polled: Vec<libc::pollfd> = fds
            .iter()
            .zip(open)
            .filter(|(_, open)| *open)
            .map(|(&fd, _)| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        if let Some((fd, _)) = &stdin {
            polled.push(libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            });
        }
        unsafe {
            libc::poll(polled.as_mut_ptr(), polled.len() as libc::nfds_t, 10);
        }

        // Interleaved with draining: writing all stdin first deadlocks against a program (e.g.
        // `cat`) blocked on its full output pipe.
        if let Some((fd, data)) = &mut stdin {
            if !data.is_empty() {
                match write_raw(fd.as_raw_fd(), data) {
                    Ok(n) if n > 0 => *data = &data[n..],
                    Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EINTR) => {}
                    // Wrote 0 or reader gone (EPIPE): stop.
                    _ => *data = &[],
                }
            }
            if data.is_empty() {
                stdin = None; // dropping it closes the pipe: EOF for the program
            }
        }

        for i in 0..2 {
            if open[i] {
                open[i] = drain(fds[i], &mut captured[i]);
            }
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
            // Drain what's there now; a descendant may hold the pipes open, so not to EOF.
            for i in 0..2 {
                if open[i] {
                    drain(fds[i], &mut captured[i]);
                }
            }
            let (reported, proc_mount_failed) = read_reports(signal_pipe.as_raw_fd());
            let (code, signal) = if exited {
                (libc::WEXITSTATUS(status), reported)
            } else {
                let sig = libc::WTERMSIG(status);
                (128 + sig, Some(sig))
            };
            let output_truncated = captured.iter().any(Captured::truncated);
            let [stdout, stderr] = captured.map(Captured::into_string);
            return Ok(Waited {
                stdout,
                stderr,
                exit_code: code,
                killed_by_timeout,
                killed_by_tmp_limit,
                killed_by_cpu_limit,
                signal,
                proc_mount_failed,
                rusage,
                output_truncated,
            });
        }
        if let Some(tmp) = private_tmp.as_deref_mut()
            && ret == 0
            && !killed_by_tmp_limit
            && tmp.over_limit()
        {
            kill();
            killed_by_tmp_limit = true;
        }
        if let Some((cg, limit_usec)) = cpu_limit
            && ret == 0
            && !killed_by_cpu_limit
        {
            let used = cg.get_cpu_stats().map(|s| s.total_usec).unwrap_or(0);
            // Margin so RLIMIT_CPU wins for a single process; without it this poll races ahead under load.
            if used > limit_usec + CPU_LIMIT_GRACE_USEC {
                kill();
                killed_by_cpu_limit = true;
            }
        }
        if ret == 0 && start.elapsed() > timeout && !killed_by_timeout {
            // Child is PID-ns init: its death kills the rest. Kill the group too, just in case.
            kill();
            killed_by_timeout = true;
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
    fn test_reports_carry_a_failed_proc_mount_and_the_signal() {
        assert_eq!(reports(&[]), (None, false));
        assert_eq!(reports(&[15]), (Some(15), false));
        assert_eq!(reports(&[0]), (None, true));
        assert_eq!(reports(&[0, 9]), (Some(9), true));
    }
}

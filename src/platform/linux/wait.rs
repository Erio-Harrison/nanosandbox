//! Feeding stdin, collecting stdout/stderr, and waiting for the sandboxed
//! process to finish or hit a limit. Runs entirely in the parent, after
//! clone() has already returned.

use crate::error::{Result, SandboxError};
use crate::platform::output::Captured;
use crate::platform::private_tmp::PrivateTmp;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use super::{CgroupManager, read_raw, write_raw};

/// See the comment at its one use site, in `wait_with_timeout`'s cpu_limit
/// check.
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
    pub(super) rusage: libc::rusage,
    pub(super) output_truncated: bool,
}

/// Reads what's available on `fd` into `out`, until it would block. False
/// once the writers are all gone (EOF) or it fails.
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

/// Feeds stdin, collects stdout/stderr and waits for the process, killing
/// it on `timeout`, when `private_tmp` goes over its size, or (`cpu_limit`)
/// when the whole cgroup goes over `cpu_time_limit` in total CPU time --
/// `RLIMIT_CPU` alone only catches one process over it, not the group.
///
/// Waits in poll() on the pipes, and reads each one until it's empty when
/// it has data. It used to read 4 KB per stream every 10 ms, about 400 KB/s:
/// a program printing 10 MB took 25 s, and ran out a 10 s time limit.
pub(super) fn wait_with_timeout(
    pid: nix::unistd::Pid,
    outputs: [OwnedFd; 2],
    mut stdin: Option<(OwnedFd, &[u8])>,
    timeout: Duration,
    mut private_tmp: Option<&mut PrivateTmp>,
    max_output: u64,
    cpu_limit: Option<(&CgroupManager, u64)>,
) -> Result<Waited> {
    let start = Instant::now();
    let mut captured = [Captured::new(max_output), Captured::new(max_output)];
    let mut open = [true, true];
    let mut killed_by_timeout = false;
    let mut killed_by_tmp_limit = false;
    // Total across the whole cgroup, not just `pid` itself: RLIMIT_CPU
    // (set in the child) is per process, so a program that forks could use
    // close to N times cpu_time_limit before any one of them individually
    // hit it. cpu.stat's usage_usec works without the "cpu" controller
    // enabled (confirmed for real), so this needs only a cgroup to exist.
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
    if let Some((fd, _)) = &stdin {
        set_nonblocking(fd.as_raw_fd());
    }

    loop {
        // Wait up to 10 ms for output, or for room to write stdin; the
        // wait4/timeout checks below run at least that often.
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

        // Write more stdin, non-blocking, interleaved with draining
        // stdout/stderr below — not all upfront. A program that echoes
        // input to output as it goes (e.g. `cat`) can block on writing its
        // own output once enough of it is buffered and unread, which stops
        // it reading more stdin in turn; writing stdin to completion
        // before anything reads stdout/stderr deadlocks against exactly
        // that, confirmed for real with input over the output pipe's size.
        if let Some((fd, data)) = &mut stdin {
            if !data.is_empty() {
                match write_raw(fd.as_raw_fd(), data) {
                    Ok(n) if n > 0 => *data = &data[n..],
                    Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EINTR) => {}
                    // Either wrote 0 (shouldn't happen for non-empty data)
                    // or the reader's gone (e.g. EPIPE) — nothing more to
                    // usefully write either way.
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

        // wait4, not waitpid: its rusage is where cpu_time/peak_memory come
        // from when there's no cgroup to read them from.
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
            // What's left in the pipes. A descendant that inherited them can
            // keep them open, so not to EOF: only what's there now.
            for i in 0..2 {
                if open[i] {
                    drain(fds[i], &mut captured[i]);
                }
            }
            let (code, signal) = if exited {
                (libc::WEXITSTATUS(status), None)
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
            // Margin past limit_usec so RLIMIT_CPU (same threshold, kernel
            // side) wins for a single process; this check is for what it
            // can't catch, many processes each under budget. Without the
            // margin this poll can race ahead of RLIMIT_CPU under load --
            // confirmed for real.
            if used > limit_usec + CPU_LIMIT_GRACE_USEC {
                kill();
                killed_by_cpu_limit = true;
            }
        }
        if ret == 0 && start.elapsed() > timeout && !killed_by_timeout {
            // The child is init of its PID namespace: when it dies, the
            // kernel kills everything else in there. The process group is
            // killed too, just in case.
            kill();
            killed_by_timeout = true;
        }
    }
}

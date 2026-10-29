//! Wait for a run, poll its limits, and kill every process of it.

use crate::builder::SandboxConfig;
use crate::error::{Result, SandboxError};
use crate::platform::output::Captured;
use crate::platform::private_tmp::PrivateTmp;
use crate::result::ExecutionResult;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use super::MacOSExecutor;
use super::kqueue::{Event, Kqueue, wait_for_exits};
use super::run_marker::RunMarker;
use crate::platform::checks::memory_check_due;

/// How long killing a run's leftovers may take before giving up on them.
pub(super) const KILL_RUN_LIMIT: Duration = Duration::from_millis(250);

impl MacOSExecutor {
    pub(super) fn wait_with_timeout(
        &self,
        child: &mut std::process::Child,
        stdin_data: Option<&[u8]>,
        config: &SandboxConfig,
        mut private_tmp: Option<&mut PrivateTmp>,
        marker: &RunMarker,
        start: Instant,
    ) -> Result<ExecutionResult> {
        let child_pid = child.id() as i32;
        let timeout = config.wall_time_limit.unwrap_or(Duration::from_secs(3600));
        let memory_limit = config.memory_limit;
        let mut killed_by_timeout = false;
        let mut killed_by_oom = false;
        let mut killed_by_tmp_limit = false;

        let mut stdin_pipe = child.stdin.take();
        let mut stdout_pipe = child.stdout.take();
        let mut stderr_pipe = child.stderr.take();
        for fd in [
            stdin_pipe.as_ref().map(|p| p.as_raw_fd()),
            stdout_pipe.as_ref().map(|p| p.as_raw_fd()),
            stderr_pipe.as_ref().map(|p| p.as_raw_fd()),
        ]
        .into_iter()
        .flatten()
        {
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }

        let mut stdin_remaining = stdin_data.unwrap_or(&[]);
        let mut stdout = Captured::new(config.max_output);
        let mut stderr = Captured::new(config.max_output);

        // Sleeps until output, stdin room, the exit or the earliest due check (see checks.rs):
        // the wall deadline once, the next memory read, the next /tmp size walk.
        let kq = Kqueue::new().map_err(|e| SandboxError::ExecutionFailed {
            context: "create kqueue".into(),
            source: Box::new(e),
        })?;
        for fd in [
            stdout_pipe.as_ref().map(|p| p.as_raw_fd()),
            stderr_pipe.as_ref().map(|p| p.as_raw_fd()),
        ]
        .into_iter()
        .flatten()
        {
            let _ = kq.watch_readable(fd);
        }
        if let Some(pipe) = &stdin_pipe {
            let _ = kq.watch_writable(pipe.as_raw_fd());
        }
        // Already gone: don't sleep before the wait4 that reaps it. A failed watch keeps a tick.
        let exit_watched = kq.watch_exit(child_pid);
        let mut exited = matches!(exit_watched, Ok(false));
        let mut deadline = Some(start + timeout);
        let mut memory_due = memory_limit.map(|_| start);

        loop {
            // Interleave stdin writes and output drains; doing them in sequence deadlocks on full pipes.
            if !stdin_remaining.is_empty()
                && let Some(pipe) = stdin_pipe.as_mut()
            {
                match pipe.write(stdin_remaining) {
                    Ok(n) if n > 0 => stdin_remaining = &stdin_remaining[n..],
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    // Wrote 0 or the reader is gone (EPIPE).
                    _ => stdin_remaining = &[],
                }
            }
            if stdin_remaining.is_empty() {
                stdin_pipe = None; // drop closes the fd, signaling EOF
            }
            drain_available(&mut stdout_pipe, &mut stdout);
            drain_available(&mut stderr_pipe, &mut stderr);

            let mut status: libc::c_int = 0;
            let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };

            let result = unsafe { libc::wait4(child_pid, &mut status, libc::WNOHANG, &mut rusage) };

            if result == child_pid {
                drain_available(&mut stdout_pipe, &mut stdout);
                drain_available(&mut stderr_pipe, &mut stderr);

                // Sweep descendants the child backgrounded (`cmd & exit 0`); they'd outlive run().
                Self::kill_run(child_pid, marker);

                let (exit_code, signal) = if libc::WIFEXITED(status) {
                    (libc::WEXITSTATUS(status), None)
                } else if libc::WIFSIGNALED(status) {
                    // 128 + signal, as the shell and Linux report.
                    (128 + libc::WTERMSIG(status), Some(libc::WTERMSIG(status)))
                } else {
                    (-1, None)
                };

                // ru_maxrss is in bytes on macOS.
                let peak_memory = Some(rusage.ru_maxrss as u64);

                let user_time = Duration::new(
                    rusage.ru_utime.tv_sec as u64,
                    rusage.ru_utime.tv_usec as u32 * 1000,
                );
                let sys_time = Duration::new(
                    rusage.ru_stime.tv_sec as u64,
                    rusage.ru_stime.tv_usec as u32 * 1000,
                );
                let cpu_time = Some(user_time + sys_time);

                return Ok(ExecutionResult {
                    output_truncated: stdout.truncated() || stderr.truncated(),
                    stdout: stdout.into_string(),
                    stderr: stderr.into_string(),
                    exit_code,
                    duration: start.elapsed(),
                    killed_by_timeout,
                    killed_by_oom,
                    killed_by_tmp_limit,
                    killed_by_cpu_limit: false,
                    signal,
                    peak_memory,
                    cpu_time,
                    blocked_hosts: Vec::new(), // filled in by execute()
                    proc_isolated: true,
                });
            } else if result == 0 {
                let now = Instant::now();
                if deadline.is_some_and(|d| now >= d) {
                    Self::kill_run(child_pid, marker);
                    killed_by_timeout = true;
                    deadline = None;
                }
                if let (Some(limit), Some(due)) = (memory_limit, memory_due)
                    && now >= due
                {
                    let used = Self::tree_footprint(marker);
                    if used > limit {
                        Self::kill_run(child_pid, marker);
                        killed_by_oom = true;
                        memory_due = None;
                    } else {
                        memory_due = Some(memory_check_due(now, used, limit));
                    }
                }
                if let Some(tmp) = private_tmp.as_deref_mut()
                    && !killed_by_tmp_limit
                    && tmp.over_limit()
                {
                    Self::kill_run(child_pid, marker);
                    killed_by_tmp_limit = true;
                }

                let mut wake = [
                    deadline,
                    memory_due,
                    private_tmp
                        .as_ref()
                        .filter(|_| !killed_by_tmp_limit)
                        .map(|t| t.due()),
                ]
                .into_iter()
                .flatten()
                .min();
                if exited || exit_watched.is_err() {
                    let tick = if exited { Duration::ZERO } else { Duration::from_millis(10) };
                    wake = Some(wake.map_or(now + tick, |w| w.min(now + tick)));
                }
                let events = kq
                    .wait(wake.map(|w| w.saturating_duration_since(Instant::now())))
                    .unwrap_or_default();
                exited = events.contains(&Event::Exited(child_pid));
            } else {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    // EINTR: retry.
                    continue;
                }
                Self::kill_run(child_pid, marker);
                let _ = child.wait();
                return Err(SandboxError::ExecutionFailed {
                    context: "wait4 failed".into(),
                    source: Box::new(err),
                });
            }
        }
    }

    pub(super) fn list_pids(kind: u32, arg: u32) -> Vec<i32> {
        let size = std::mem::size_of::<i32>();
        let bytes = unsafe { libc::proc_listpids(kind, arg, std::ptr::null_mut(), 0) };
        if bytes <= 0 {
            return Vec::new();
        }
        let mut pids = vec![0i32; bytes as usize / size + 16];
        let bytes = unsafe {
            libc::proc_listpids(
                kind,
                arg,
                pids.as_mut_ptr() as *mut libc::c_void,
                (pids.len() * size) as libc::c_int,
            )
        };
        if bytes <= 0 {
            return Vec::new();
        }
        pids.truncate(bytes as usize / size);
        pids.retain(|&pid| pid > 0);
        pids
    }

    /// The root, its process group and descendants found via parent links; processes
    /// orphaned to launchd are not found (see `RunMarker`).
    fn sandbox_pids(root: i32) -> Vec<i32> {
        const PROC_PGRP_ONLY: u32 = 2;
        const PROC_PPID_ONLY: u32 = 6;
        let mut seen = HashSet::from([root]);
        let mut pending = vec![root];
        for pid in Self::list_pids(PROC_PGRP_ONLY, root as u32) {
            if seen.insert(pid) {
                pending.push(pid);
            }
        }
        while let Some(pid) = pending.pop() {
            for child in Self::list_pids(PROC_PPID_ONLY, pid as u32) {
                if seen.insert(child) {
                    pending.push(child);
                }
            }
        }
        seen.into_iter().collect()
    }

    /// Kill the tree under `root`, then whatever the run's sandbox still holds; repeat until
    /// none are left, since one may fork meanwhile. Gives up after `KILL_RUN_LIMIT`.
    fn kill_run(root: i32, marker: &RunMarker) {
        Self::kill_process_tree(root);
        let deadline = Instant::now() + KILL_RUN_LIMIT;
        while Instant::now() < deadline {
            let members = marker.members();
            if members.is_empty() {
                return;
            }
            for &pid in &members {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
            wait_for_exits(&members, deadline);
        }
    }

    fn kill_process_tree(root: i32) {
        for pid in Self::sandbox_pids(root) {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        unsafe {
            libc::kill(-root, libc::SIGKILL);
        }
    }

    /// Physical footprint over the whole run, found by marker so a daemonized process
    /// that left the tree still counts.
    fn tree_footprint(marker: &RunMarker) -> u64 {
        marker
            .members()
            .into_iter()
            .map(|pid| {
                let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
                let ret = unsafe {
                    libc::proc_pid_rusage(
                        pid,
                        libc::RUSAGE_INFO_V2,
                        &mut info as *mut _ as *mut libc::rusage_info_t,
                    )
                };
                if ret == 0 { info.ri_phys_footprint } else { 0 }
            })
            .sum()
    }
}

/// Drain a non-blocking pipe; EOF or a hard error drops the handle.
fn drain_available<R: Read>(pipe: &mut Option<R>, out: &mut Captured) {
    let Some(p) = pipe else { return };
    let mut tmp = [0u8; 64 * 1024];
    loop {
        match p.read(&mut tmp) {
            Ok(0) => {
                *pipe = None;
                break;
            }
            Ok(n) => out.push(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                *pipe = None;
                break;
            }
        }
    }
}

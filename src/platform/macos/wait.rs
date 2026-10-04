//! Waiting for a run to finish, its timeout/memory/tmp polling, and killing
//! every process of it (including ones that left the tracked process tree).

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
use super::run_marker::RunMarker;

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

        // Use wait4 with WNOHANG for non-blocking wait with rusage collection
        loop {
            // Write more stdin and drain whatever output is available, non-
            // blocking, interleaved on every iteration -- not all stdin
            // upfront then all output after exit, which deadlocks once
            // either side fills its pipe buffer before the other side has
            // drained it (confirmed for real).
            if !stdin_remaining.is_empty()
                && let Some(pipe) = stdin_pipe.as_mut()
            {
                match pipe.write(stdin_remaining) {
                    Ok(n) if n > 0 => stdin_remaining = &stdin_remaining[n..],
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    // Either wrote 0 (shouldn't happen for non-empty
                    // data) or the reader's gone (e.g. EPIPE) -- nothing
                    // more to usefully write either way.
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
                // Catch anything written in the child's last moments.
                drain_available(&mut stdout_pipe, &mut stdout);
                drain_available(&mut stderr_pipe, &mut stderr);

                // The immediate child exiting (normally or by signal) says
                // nothing about descendants it backgrounded before doing so
                // (e.g. `cmd & exit 0`) -- those keep running, untracked and
                // unbounded by wall_time_limit/memory_limit, unless we sweep
                // the whole tree here too, not just on the timeout/oom paths
                // below (confirmed for real: a backgrounded `sleep 20` was
                // still alive well after run() returned).
                Self::kill_run(child_pid, marker);

                // Extract exit code and signal
                let (exit_code, signal) = if libc::WIFEXITED(status) {
                    (libc::WEXITSTATUS(status), None)
                } else if libc::WIFSIGNALED(status) {
                    (-1, Some(libc::WTERMSIG(status)))
                } else {
                    (-1, None)
                };

                // Extract resource usage
                // maxrss is in bytes on macOS
                let peak_memory = Some(rusage.ru_maxrss as u64);

                // CPU time = user time + system time
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
                // Still running, check timeout
                if start.elapsed() > timeout && !killed_by_timeout {
                    Self::kill_run(child_pid, marker);
                    killed_by_timeout = true;
                }
                let mut poll = Duration::from_millis(10);
                if let Some(limit) = memory_limit
                    && !killed_by_oom
                {
                    let used = Self::tree_footprint(marker);
                    if used > limit {
                        Self::kill_run(child_pid, marker);
                        killed_by_oom = true;
                    } else if used > limit / 10 * 6 {
                        poll = Duration::from_millis(2);
                    }
                }
                if let Some(tmp) = private_tmp.as_deref_mut()
                    && !killed_by_tmp_limit
                    && tmp.over_limit()
                {
                    Self::kill_run(child_pid, marker);
                    killed_by_tmp_limit = true;
                }
                std::thread::sleep(poll);
            } else {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    // Interrupted by a signal, not a real failure -- WNOHANG
                    // means we weren't blocked on anything to begin with, so
                    // just retry rather than treating this as fatal.
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

    /// The root process, its process group and all descendants. Descendants that
    /// leave the group (setsid/setpgid) are found through parent links; ones
    /// orphaned to launchd are not, macOS has no cgroup-style way to find them.
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

    /// Kill every process of the run: the tree under `root`, then anything
    /// the run's sandbox still has, such as a child that left the process
    /// group and outlived its parent. Again until none are left, in case one
    /// forks while this goes.
    fn kill_run(root: i32, marker: &RunMarker) {
        Self::kill_process_tree(root);
        for _ in 0..50 {
            let members = marker.members();
            if members.is_empty() {
                return;
            }
            for pid in members {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Kill the sandbox's whole process tree
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

    /// Physical footprint summed over the whole run, including a process
    /// that's left the tree `sandbox_pids` would have walked (the same
    /// daemonize pattern `run_marker` exists for). It used to use
    /// `sandbox_pids`, so a daemonized process ballooning memory went
    /// uncounted for as long as the run lasted -- confirmed for real: a
    /// double fork into 300MB, with memory_limit set to 64MB, finished
    /// clean, neither OOM nor timeout. The process still doesn't outlive
    /// the run either way: `kill_run` always sweeps by marker too.
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

/// Read whatever is available on a non-blocking pipe without blocking.
/// EOF (Ok(0)) or a hard error drops the handle so later iterations skip it.
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

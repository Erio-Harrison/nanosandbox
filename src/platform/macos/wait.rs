//! Wait for a run, poll its limits, and kill every process of it (supervisor thread; the I/O
//! ends are the caller's, see `platform/supervise.rs`).

use crate::error::{Result, SandboxError};
use crate::platform::checks::memory_check_due;
use crate::platform::private_tmp::PrivateTmp;
use std::collections::HashSet;
use std::time::{Duration, Instant};

use super::MacOSExecutor;
use super::kqueue::{Event, Kqueue, wait_for_exits};
use super::run_marker::RunMarker;

/// How long killing a run's leftovers may take before giving up on them.
pub(super) const KILL_RUN_LIMIT: Duration = Duration::from_millis(250);

/// How the run's first process ended, from `supervise`.
pub(super) struct Ended {
    pub(super) exit_code: i32,
    pub(super) signal: Option<i32>,
    pub(super) killed_by_timeout: bool,
    pub(super) killed_by_oom: bool,
    pub(super) killed_by_tmp_limit: bool,
    pub(super) rusage: libc::rusage,
}

impl MacOSExecutor {
    /// Waits for `child`, killing the run on `timeout`, `memory_limit` or `private_tmp` over
    /// size, then sweeps what it left behind.
    ///
    /// Sleeps on a kqueue (`NOTE_EXIT`) until the earliest due check (see checks.rs): the wall
    /// deadline once, the next memory read, the next /tmp size walk. Without a memory limit a
    /// run wakes for the exit and the deadline, and nothing else.
    pub(super) fn supervise(
        child: &mut std::process::Child,
        timeout: Duration,
        memory_limit: Option<u64>,
        mut private_tmp: Option<&mut PrivateTmp>,
        marker: &RunMarker,
    ) -> Result<Ended> {
        let child_pid = child.id() as i32;
        let start = Instant::now();
        let mut killed_by_timeout = false;
        let mut killed_by_oom = false;
        let mut killed_by_tmp_limit = false;

        let kq = Kqueue::new().map_err(|e| SandboxError::ExecutionFailed {
            context: "create kqueue".into(),
            source: Box::new(e),
        })?;
        // Already gone: don't sleep before the wait4 that reaps it. A failed watch keeps a tick.
        let exit_watched = kq.watch_exit(child_pid);
        let mut exited = matches!(exit_watched, Ok(false));
        let mut deadline = Some(start + timeout);
        let mut memory_due = memory_limit.map(|_| start);

        loop {
            let mut status: libc::c_int = 0;
            let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
            let result = unsafe { libc::wait4(child_pid, &mut status, libc::WNOHANG, &mut rusage) };

            if result == child_pid {
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
                return Ok(Ended {
                    exit_code,
                    signal,
                    killed_by_timeout,
                    killed_by_oom,
                    killed_by_tmp_limit,
                    rusage,
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
                    let tick = if exited {
                        Duration::ZERO
                    } else {
                        Duration::from_millis(10)
                    };
                    wake = Some(wake.map_or(now + tick, |w| w.min(now + tick)));
                }
                let events = kq
                    .wait(wake.map(|w| w.saturating_duration_since(Instant::now())))
                    .unwrap_or_default();
                exited = events.contains(&Event::Exited(child_pid));
            } else {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
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

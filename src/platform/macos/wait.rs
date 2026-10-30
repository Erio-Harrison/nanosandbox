//! Wait for a run, poll its limits, and kill every process of it (supervisor thread; the I/O
//! ends are the caller's, see `platform/supervise.rs`).

use crate::error::{Result, SandboxError};
use crate::platform::checks::memory_check_due;

/// `proc_listpids` kind: the children of a pid (libproc.h).
const PROC_PPID_ONLY: u32 = 6;
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
    /// Processes of the run still alive when the final kill gave up (see `kill_run`).
    pub(super) survivors: usize,
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
        mut denials: Option<&mut super::denials::RunDenials>,
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
        // With denials to report, the process tree is followed fork by fork, so each denial
        // can be attributed by pid.
        let exit_watched = match denials {
            Some(_) => kq.watch_tree(child_pid),
            None => kq.watch_exit(child_pid),
        };
        let mut exited = matches!(exit_watched, Ok(false));
        let mut deadline = Some(start + timeout);
        let mut memory_due = memory_limit.map(|_| start);

        loop {
            let mut status: libc::c_int = 0;
            let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
            let result = unsafe { libc::wait4(child_pid, &mut status, libc::WNOHANG, &mut rusage) };

            if result == child_pid {
                // Sweep descendants the child backgrounded (`cmd & exit 0`); they'd outlive run().
                let survivors = Self::kill_run(child_pid, marker);

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
                    survivors,
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
                if let Some(run) = denials.as_deref_mut() {
                    // A watched process forked: its children are the run's too, and watched
                    // in turn. One that exits before this runs is missed (best effort).
                    for event in &events {
                        if let Event::Forked(parent) = event {
                            for child in Self::list_pids(PROC_PPID_ONLY, *parent as u32) {
                                if run.saw(child) {
                                    let _ = kq.watch_tree(child);
                                }
                            }
                        }
                    }
                }
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

    /// Kills the tree under `root`, then whatever the run's sandbox still holds. Without a PID
    /// namespace or a process-count limit, a process that forks as fast as it is killed can
    /// outrun a kill loop, so each round first `SIGSTOP`s every member found, repeating until
    /// no new one turns up (a stopped process can't fork; this part isn't on a clock, since
    /// stopping must finish or the bomb goes on), then `SIGKILL`s them all. `KILL_RUN_LIMIT`
    /// bounds only the wait for killed processes to exit: one stuck in an uninterruptible exit
    /// (a binary terminated by a launch constraint) never will. Returns how many such were
    /// left, 0 when the run is gone; the caller keeps the run's marker in that case so a later
    /// sweep can finish the job.
    fn kill_run(root: i32, marker: &RunMarker) -> usize {
        Self::kill_process_tree(root);
        let deadline = Instant::now() + KILL_RUN_LIMIT;
        let mut killed: HashSet<i32> = HashSet::new();
        loop {
            let mut stopped: HashSet<i32> = HashSet::new();
            loop {
                let new: Vec<i32> = marker
                    .members()
                    .into_iter()
                    .filter(|pid| !stopped.contains(pid) && !killed.contains(pid))
                    .collect();
                if new.is_empty() {
                    break;
                }
                for &pid in &new {
                    unsafe {
                        libc::kill(pid, libc::SIGSTOP);
                    }
                    stopped.insert(pid);
                }
            }
            let members: Vec<i32> = stopped.into_iter().collect();
            for &pid in &members {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                killed.insert(pid);
            }
            if !members.is_empty() {
                wait_for_exits(
                    &members,
                    deadline.max(Instant::now() + Duration::from_millis(20)),
                );
            }
            let left = marker.members();
            if left.is_empty() {
                return 0;
            }
            // Only processes already killed are left: they're exiting, or can't. Give them the
            // rest of the budget, then count them.
            if left.iter().all(|pid| killed.contains(pid)) {
                if Instant::now() >= deadline {
                    return left.len();
                }
                wait_for_exits(&left, deadline);
                if marker.members().is_empty() {
                    return 0;
                }
                if Instant::now() >= deadline {
                    return marker.members().len();
                }
            }
            // Otherwise new processes appeared since the stop round: go round again.
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

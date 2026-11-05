//! The processes of a run, kept up from kqueue events: a fork of a watched process lists its new
//! children and watches them in turn, an exit drops one. Reading the run's footprint then touches
//! only these, where finding them by marker (`RunMarker::members`) checks every process of the
//! user.
//!
//! Events can miss one process: a child that forked and exited before it could be listed may have
//! left a grandchild outside the tree. That sets `rescan`, and one scan by marker picks up what
//! was missed (at most every `RESCAN_EVERY`, so a program forking in a loop can't keep the host
//! scanning). A run that forks nothing never scans.

use super::MacOSExecutor;
use super::kqueue::Kqueue;
use super::run_marker::RunMarker;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// `proc_listpids` kind: the children of a pid (libproc.h).
const PROC_PPID_ONLY: u32 = 6;

/// Least time between two scans by marker.
const RESCAN_EVERY: Duration = Duration::from_millis(100);

pub(super) struct Members {
    pids: HashSet<libc::pid_t>,
    /// A process may have slipped out of the tree; a scan by marker is due.
    rescan: bool,
    last_scan: Option<Instant>,
}

impl Members {
    /// A run whose first process is `root`, which the caller watches with `watch_tree`. Call
    /// `scan` next, for the processes it forked before that.
    pub(super) fn new(root: libc::pid_t) -> Self {
        Self {
            pids: HashSet::from([root]),
            rescan: false,
            last_scan: None,
        }
    }

    /// A watched process forked: list its children, and theirs, and watch them.
    pub(super) fn forked(&mut self, kq: &Kqueue, parent: libc::pid_t) {
        let mut pending = vec![parent];
        while let Some(pid) = pending.pop() {
            let children = MacOSExecutor::list_pids(PROC_PPID_ONLY, pid as u32);
            if children.is_empty() {
                // Its children are gone already, and may have left children of their own.
                self.rescan = true;
                continue;
            }
            for child in children {
                if self.pids.contains(&child) {
                    continue;
                }
                match kq.watch_tree(child) {
                    Ok(true) => {
                        self.pids.insert(child);
                        pending.push(child);
                    }
                    // Gone before it could be watched.
                    _ => self.rescan = true,
                }
            }
        }
    }

    pub(super) fn exited(&mut self, pid: libc::pid_t) {
        self.pids.remove(&pid);
    }

    /// Whether a scan by marker is due now.
    pub(super) fn rescan_due(&self, now: Instant) -> bool {
        self.rescan && self.last_scan.is_none_or(|t| now >= t + RESCAN_EVERY)
    }

    /// When the scan that is waiting comes due; `None` if none is.
    pub(super) fn next_rescan(&self, now: Instant) -> Option<Instant> {
        self.rescan
            .then(|| self.last_scan.map_or(now, |t| (t + RESCAN_EVERY).max(now)))
    }

    /// Takes in every process the run's marker finds that isn't followed yet, and watches it.
    pub(super) fn scan(&mut self, kq: &Kqueue, marker: &RunMarker) {
        for pid in marker.members() {
            if !self.pids.contains(&pid) && kq.watch_tree(pid).unwrap_or(false) {
                self.pids.insert(pid);
            }
        }
        self.rescan = false;
        self.last_scan = Some(Instant::now());
    }

    /// Physical footprint of the processes followed.
    pub(super) fn footprint(&self) -> u64 {
        self.pids
            .iter()
            .map(|&pid| {
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

#[cfg(test)]
mod tests {
    use super::super::kqueue::Event;
    use super::*;
    use std::process::{Child, Command};

    /// Feeds `members` the kqueue's events until `done` holds or `within` passes.
    fn follow(
        kq: &Kqueue,
        members: &mut Members,
        within: Duration,
        done: impl Fn(&Members) -> bool,
    ) -> bool {
        let end = Instant::now() + within;
        while Instant::now() < end {
            if done(members) {
                return true;
            }
            let left = end.saturating_duration_since(Instant::now());
            for event in kq.wait(Some(left.min(Duration::from_millis(50)))).unwrap() {
                match event {
                    Event::Forked(pid) => members.forked(kq, pid),
                    Event::Exited(pid) => members.exited(pid),
                    _ => {}
                }
            }
        }
        done(members)
    }

    /// A process inside the sandbox `marker` stands for.
    fn marked(marker: &RunMarker, script: &str) -> Child {
        let rules: String = marker
            .rules()
            .iter()
            .map(|(rule, path)| rule.replace("(param \"{}\")", &format!("\"{}\"", path.display())))
            .collect();
        // Held for the fork, as in a run (see FORK_LOCK).
        let _fork = super::super::FORK_LOCK
            .read()
            .unwrap_or_else(|e| e.into_inner());
        Command::new("/usr/bin/sandbox-exec")
            .args([
                "-p",
                &format!("(version 1)(allow default){rules}"),
                "/bin/sh",
                "-c",
                script,
            ])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    }

    /// Blocks until the script has printed "ready": the profile is applied by then.
    fn ready(child: &mut Child) {
        use std::io::{BufRead, BufReader};
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "ready");
    }

    fn shell(script: &str) -> Child {
        Command::new("/bin/sh")
            .args(["-c", script])
            .spawn()
            .unwrap()
    }

    #[test]
    fn test_children_are_followed_when_they_fork_and_dropped_when_they_exit() {
        let mut root = shell("sleep 1 & sleep 1 & wait");
        let root_pid = root.id() as libc::pid_t;
        let kq = Kqueue::new().unwrap();
        assert!(kq.watch_tree(root_pid).unwrap());
        let mut members = Members::new(root_pid);
        assert!(
            follow(&kq, &mut members, Duration::from_secs(5), |m| m.pids.len()
                == 3),
            "followed {:?}",
            members.pids
        );
        assert!(
            follow(&kq, &mut members, Duration::from_secs(5), |m| m.pids.len()
                == 1),
            "still followed {:?}",
            members.pids
        );
        root.wait().unwrap();
    }

    #[test]
    fn test_a_grandchild_is_followed_through_its_parent() {
        let mut root = shell("sh -c 'sleep 1 & wait' & wait");
        let root_pid = root.id() as libc::pid_t;
        let kq = Kqueue::new().unwrap();
        assert!(kq.watch_tree(root_pid).unwrap());
        let mut members = Members::new(root_pid);
        assert!(
            follow(&kq, &mut members, Duration::from_secs(5), |m| m.pids.len()
                == 3),
            "followed {:?}",
            members.pids
        );
        root.wait().unwrap();
    }

    #[test]
    fn test_a_fork_whose_children_are_gone_asks_for_a_rescan() {
        let mut gone = shell("true");
        let pid = gone.id() as libc::pid_t;
        gone.wait().unwrap();
        let kq = Kqueue::new().unwrap();
        let mut members = Members::new(pid);
        let now = Instant::now();
        assert!(!members.rescan_due(now));
        assert_eq!(members.next_rescan(now), None);
        members.forked(&kq, pid);
        assert!(members.rescan_due(now));
        assert_eq!(members.next_rescan(now), Some(now));
    }

    #[test]
    fn test_scans_are_spaced() {
        let mut members = Members::new(1);
        let start = Instant::now();
        members.rescan = true;
        members.last_scan = Some(start);
        assert!(!members.rescan_due(start + RESCAN_EVERY / 2));
        assert_eq!(members.next_rescan(start), Some(start + RESCAN_EVERY));
        assert!(members.rescan_due(start + RESCAN_EVERY));
    }

    #[test]
    fn test_footprint_counts_the_processes_followed_and_only_those() {
        let mut sleeper = Command::new("/bin/sleep").arg("5").spawn().unwrap();
        let pid = sleeper.id() as libc::pid_t;
        let mut members = Members::new(pid);
        assert!(members.footprint() > 0);
        members.exited(pid);
        assert_eq!(members.footprint(), 0);
        sleeper.kill().unwrap();
        sleeper.wait().unwrap();
    }

    #[test]
    fn test_a_scan_takes_in_the_marked_processes_that_were_not_followed() {
        let marker = RunMarker::create().unwrap();
        // Born outside what the events showed: marked, but nobody watched its parent.
        let mut run = marked(&marker, "echo ready; exec sleep 5");
        let mut root = Command::new("/bin/sleep").arg("5").spawn().unwrap();
        ready(&mut run);
        let (root_pid, run_pid) = (root.id() as libc::pid_t, run.id() as libc::pid_t);

        let kq = Kqueue::new().unwrap();
        let mut members = Members::new(root_pid);
        members.rescan = true;
        assert!(!members.pids.contains(&run_pid));
        members.scan(&kq, &marker);

        let followed = members.pids.contains(&run_pid);
        let asked_again = members.rescan_due(Instant::now());
        for c in [&mut run, &mut root] {
            let _ = c.kill();
            let _ = c.wait();
        }
        assert!(followed, "followed {:?}", members.pids);
        assert!(!asked_again);
    }
}

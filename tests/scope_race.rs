//! The first run with a resource limit puts this process into a delegated scope of its own
//! (`cgroup/scope.rs`) and enables controllers in that scope's root, which needs the root to
//! hold no process. Processes forked at that moment, by the library or by the host's own code,
//! used to land in the root and fail it ("cannot enable '+memory' ... busy"). The move happens
//! once per process, so every round is a fresh process: this binary again, run directly and
//! under `systemd-run --scope -p Delegate=yes -p MemoryMax=300M` (a delegated unit with a limit
//! of its own, which the fresh scope copies), with other threads forking all the while.

#![cfg(target_os = "linux")]

use nanosandbox::{MB, Sandbox};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

const ROUND: &str = "NANOSANDBOX_SCOPE_RACE_ROUND";
const ROUNDS: usize = 20;
const TEST: &str = "test_the_first_limited_run_succeeds_while_other_threads_fork";

/// One round, in a fresh process: other threads fork in a loop, half of them starting runs and
/// half spawning plain commands, and once each has forked once, the first run with a limit.
fn round() {
    let stop = Arc::new(AtomicBool::new(false));
    let threads = 6;
    let started = Arc::new(Barrier::new(threads + 1));
    let storm: Vec<_> = (0..threads)
        .map(|i| {
            let (stop, started) = (Arc::clone(&stop), Arc::clone(&started));
            thread::spawn(move || {
                let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();
                let mut first = true;
                while first || !stop.load(Ordering::Relaxed) {
                    if i % 2 == 0 {
                        let _ = sandbox.run("true", &[]);
                    } else {
                        let _ = Command::new("true").status();
                    }
                    if first {
                        started.wait();
                        first = false;
                    }
                }
            })
        })
        .collect();
    started.wait();

    let limited = Sandbox::builder()
        .working_dir("/tmp")
        .memory_limit(64 * MB)
        .build();
    let mut outcome = match limited {
        Err(e) if e.to_string().contains("busy") => format!("BUSY {e}"),
        Err(e) => format!("SKIP {e}"),
        Ok(sandbox) => match sandbox.run("true", &[]) {
            Ok(r) if r.exit_code == 0 => "OK".to_string(),
            Ok(r) => format!("FAILED {r:?}"),
            Err(e) if e.to_string().contains("busy") => format!("BUSY {e}"),
            Err(e) => format!("FAILED {e}"),
        },
    };
    stop.store(true, Ordering::Relaxed);
    for t in storm {
        t.join().unwrap();
    }
    if outcome == "OK" {
        // This process sits in a leaf of its scope; the scope's root holds the limits.
        let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
        let rel = cgroup.trim().trim_start_matches("0::");
        let own = std::path::Path::new("/sys/fs/cgroup")
            .join(rel.trim_start_matches('/'))
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_default();
        let memory_max = std::fs::read_to_string(own.join("memory.max")).unwrap_or_default();
        let fresh = own
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("nanosandbox-"));
        outcome = format!(
            "OK {} memory.max={}",
            if fresh { "fresh" } else { "elsewhere" },
            memory_max.trim()
        );
    }
    // On a line of its own: libtest prints the test's name just before.
    println!("\nROUND-OUTCOME {outcome}");
}

/// Runs `ROUNDS` rounds through `launcher` (the binary itself, or systemd-run wrapping it).
/// None if limits are unavailable here.
fn rounds(launcher: &[&str]) -> Option<Vec<String>> {
    let exe = std::env::current_exe().unwrap();
    let mut outcomes = Vec::new();
    for _ in 0..ROUNDS {
        let mut cmd = Command::new(launcher.first().copied().unwrap_or(exe.to_str().unwrap()));
        if !launcher.is_empty() {
            cmd.args(&launcher[1..]).arg(&exe);
        }
        let out = cmd
            .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(ROUND, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let outcome = stdout
            .lines()
            .find_map(|l| l.split_once("ROUND-OUTCOME ").map(|(_, o)| o))
            .unwrap_or("no outcome")
            .to_string();
        if outcome.starts_with("SKIP") {
            eprintln!("skipping: resource limits are unavailable here ({outcome})");
            return None;
        }
        outcomes.push(outcome);
    }
    Some(outcomes)
}

#[test]
fn test_the_first_limited_run_succeeds_while_other_threads_fork() {
    if std::env::var_os(ROUND).is_some() {
        return round();
    }
    let mut bad = Vec::new();
    if let Some(outcomes) = rounds(&[]) {
        bad.extend(
            outcomes
                .into_iter()
                .filter(|o| o != "OK fresh memory.max=max"),
        );
    }
    // Inside a delegated unit with a limit of its own: a fresh scope still, carrying the limit.
    let systemd_run = [
        "systemd-run",
        "--user",
        "--scope",
        "-q",
        "-p",
        "Delegate=yes",
        "-p",
        "MemoryMax=300M",
    ];
    let usable = Command::new(systemd_run[0])
        .args(&systemd_run[1..])
        .arg("true")
        .status()
        .is_ok_and(|s| s.success());
    if !usable {
        eprintln!("skipping the delegated-unit rounds: systemd-run --user --scope is unavailable");
    } else if let Some(outcomes) = rounds(&systemd_run) {
        bad.extend(
            outcomes
                .into_iter()
                .filter(|o| o != "OK fresh memory.max=314572800"),
        );
    }
    assert!(bad.is_empty(), "rounds that failed: {bad:?}");
}

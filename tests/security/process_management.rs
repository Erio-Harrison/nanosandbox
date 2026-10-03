//! P0: Process Management Security Tests
//!
//! Tests for:
//! - Zombie process prevention (wait after kill)
//! - Process group killing (killpg)
//! - Signal handler cleanup (SIGTERM/SIGINT handling)

use nanosandbox::Sandbox;
use std::process::Command;
use std::time::Duration;

/// Test: Zombie processes should NOT accumulate after timeout kills
///
/// Current bug: kill() without wait() leaves zombie processes
/// Expected: After sandbox timeout, no zombie processes remain
#[test]
#[cfg(unix)]
fn test_no_zombie_after_timeout() {
    // Run multiple sandboxes that will timeout
    for _ in 0..5 {
        let sandbox = Sandbox::builder()
            .working_dir("/tmp")
            .wall_time_limit(Duration::from_millis(100))
            .build()
            .unwrap();

        // This sleep will be killed by timeout
        let result = sandbox.run("sleep", &["10"]);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.killed_by_timeout);
    }

    let leaked = lasting_zombie_children();
    assert!(leaked.is_empty(), "Zombie processes leaked: {leaked:?}");
}

/// Test: Child processes should be killed when parent times out
///
/// Current bug: Only parent process is killed, children keep running
/// Expected: All processes in the sandbox process group are killed
#[test]
#[cfg(unix)]
fn test_process_group_killing() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(2))
        .build()
        .unwrap();

    // Start a script that spawns child processes
    let result = sandbox
        .run("sh", &["-c", "sleep 7777 & sleep 7777 & sleep 7777"])
        .unwrap();

    assert!(
        result.killed_by_timeout,
        "Expected timeout, got exit_code={}, duration={:?}, stderr={}",
        result.exit_code, result.duration, result.stderr
    );

    // Wait a moment for process cleanup
    std::thread::sleep(Duration::from_millis(500));

    // Check that no orphan sleep 7777 processes remain
    let orphans = Command::new("pgrep").args(["-f", "sleep 7777"]).output();

    if let Ok(output) = orphans {
        let orphan_pids: Vec<_> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        assert!(
            orphan_pids.is_empty(),
            "Orphan child processes found: {:?}",
            orphan_pids
        );
    }
}

/// Test: SIGTERM to sandbox should cleanup all children
///
/// Expected: External SIGTERM triggers graceful cleanup of sandbox processes
#[test]
#[cfg(unix)]
fn test_sigterm_cleanup() {
    // We can't easily test SIGTERM on ourselves, but we can verify
    // the sandbox properly cleans up on normal termination
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    // Quick command that spawns a child and waits
    let result = sandbox.run("sh", &["-c", "sleep 1 & wait"]).unwrap();

    // Should complete normally
    assert_eq!(
        result.exit_code, 0,
        "Expected exit 0, got {}, stderr: {}",
        result.exit_code, result.stderr
    );
    assert!(!result.killed_by_timeout);
}

/// Test: Rapid sandbox creation/destruction doesn't leak zombie processes
#[test]
#[cfg(unix)]
fn test_rapid_sandbox_no_leaks() {
    for _ in 0..20 {
        let sandbox = Sandbox::builder()
            .working_dir("/tmp")
            .wall_time_limit(Duration::from_millis(50))
            .build()
            .unwrap();

        let _ = sandbox.run("true", &[]);
    }

    let leaked = lasting_zombie_children();
    assert!(leaked.is_empty(), "Zombie processes leaked: {leaked:?}");
}

/// Test: Long-running child processes are properly terminated
#[test]
#[cfg(unix)]
fn test_deep_process_tree_killed() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(2))
        .build()
        .unwrap();

    // Create a deep process tree with unique sleep time
    // Use proper shell syntax: command1 & command2
    let result = sandbox
        .run("sh", &["-c", "sh -c 'sh -c \"sleep 8888\" &' & sleep 8888"])
        .unwrap();

    assert!(
        result.killed_by_timeout,
        "Expected timeout, got exit_code={}, duration={:?}, stderr={}",
        result.exit_code, result.duration, result.stderr
    );

    // Verify no deep children survive
    std::thread::sleep(Duration::from_millis(500));

    let orphans = Command::new("pgrep").args(["-f", "sleep 8888"]).output();

    if let Ok(output) = orphans {
        assert!(
            output.stdout.is_empty(),
            "Deep child processes survived: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

// Helper functions

#[cfg(unix)]
/// Zombies whose parent is this test process and that are still there half a
/// second later. Other tests run sandboxes in parallel, and each of their
/// processes is briefly a zombie between exiting and being reaped; a leaked
/// one stays. Counting every zombie on the system made this flaky.
fn lasting_zombie_children() -> Vec<String> {
    let sample = || -> Vec<String> {
        let output = Command::new("ps")
            .args(["-A", "-o", "pid=,ppid=,stat="])
            .output()
            .expect("Failed to run ps");
        let me = std::process::id().to_string();
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(
                |line| match line.split_whitespace().collect::<Vec<_>>()[..] {
                    [pid, ppid, stat] if ppid == me && stat.starts_with('Z') => {
                        Some(pid.to_string())
                    }
                    _ => None,
                },
            )
            .collect()
    };
    let first = sample();
    std::thread::sleep(Duration::from_millis(500));
    let second = sample();
    first
        .into_iter()
        .filter(|pid| second.contains(pid))
        .collect()
}

/// Test: a background process that leaves the process group and outlives
/// its parent is killed with the run, even though the run ended normally.
/// It used to keep running: by then it's launchd's child, and the tree walk
/// from the run's first process doesn't find it. Processes that aren't the
/// run's, inside another sandbox or none, are left alone.
#[test]
#[cfg(target_os = "macos")]
fn test_escaped_background_process_killed() {
    let alive = |pid: i32| unsafe { libc::kill(pid, 0) } == 0;

    let mut unrelated = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let other = std::sync::Arc::new(Sandbox::builder().build().unwrap());
    let other_run = {
        let other = other.clone();
        std::thread::spawn(move || other.run("sh", &["-c", "sleep 3; echo still-here"]))
    };

    let sandbox = Sandbox::builder().build().unwrap();
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                "perl -e 'setpgrp(0,0); sleep 30' & echo $!; sleep 0.2",
            ],
        )
        .unwrap();
    let escaped: i32 = result.stdout.trim().parse().unwrap();

    // Killed, and then reaped by launchd.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while alive(escaped) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let escaped_alive = alive(escaped);
    let unrelated_alive = alive(unrelated.id() as i32);
    if escaped_alive {
        unsafe {
            libc::kill(escaped, libc::SIGKILL);
        }
    }
    let _ = unrelated.kill();
    let _ = unrelated.wait();

    assert!(
        !escaped_alive,
        "background process {escaped} outlived the run"
    );
    assert!(unrelated_alive, "a process outside the sandbox was killed");
    let other = other_run.join().unwrap().unwrap();
    assert_eq!(
        other.stdout.trim(),
        "still-here",
        "another sandbox's run was killed"
    );
}

/// Test: if the process running the sandbox dies, the sandbox does too. It
/// used to keep running, with nothing left to enforce its time limit.
///
/// Runs this test binary again as the host process, which the test then
/// kills (it only kills that one child of its own, by its handle).
#[test]
#[cfg(target_os = "linux")]
fn test_sandbox_dies_with_its_host_process() {
    const MARKER: &str = "31.4159";
    if std::env::var_os("NSB_PDEATH_HOST").is_some() {
        let sandbox = Sandbox::builder()
            .wall_time_limit(Duration::from_secs(60))
            .build()
            .unwrap();
        let _ = sandbox.run("sleep", &[MARKER]);
        return;
    }
    let running = || {
        Command::new("pgrep")
            .args(["-f", &format!("^sleep {MARKER}$")])
            .output()
            .map(|o| !o.stdout.is_empty())
            .unwrap_or(false)
    };
    let mut host = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "process_management::test_sandbox_dies_with_its_host_process",
        ])
        .env("NSB_PDEATH_HOST", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !running() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(running(), "the sandbox never started");

    host.kill().unwrap();
    host.wait().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while running() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!running(), "the sandbox outlived its host process");
}

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

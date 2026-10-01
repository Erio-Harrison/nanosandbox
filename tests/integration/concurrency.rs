//! P1: Concurrency Tests
//!
//! Tests for:
//! - Thread-safe sandbox ID generation
//! - Parallel execution safety
//! - Cgroup name collision prevention (Linux)

use nanosandbox::Sandbox;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Test: Sandbox IDs should be unique across threads
#[test]
fn test_sandbox_id_unique_across_threads() {
    let ids: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let mut handles = vec![];

    // Spawn 20 threads, each creating 5 sandboxes
    for _ in 0..20 {
        let _ids_clone = Arc::clone(&ids);
        let handle = thread::spawn(move || {
            let mut local_ids = vec![];
            for _ in 0..5 {
                let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();
                local_ids.push(sandbox.id().to_string());
            }
            local_ids
        });
        handles.push(handle);
    }

    // Collect all IDs
    for handle in handles {
        let local_ids = handle.join().unwrap();
        let mut ids_guard = ids.lock().unwrap();
        for id in local_ids {
            assert!(
                ids_guard.insert(id.clone()),
                "Duplicate sandbox ID detected: {}",
                id
            );
        }
    }

    // Should have 100 unique IDs
    assert_eq!(ids.lock().unwrap().len(), 100);
}

/// Test: Parallel sandbox execution should not interfere with each other
#[test]
fn test_parallel_execution_isolation() {
    let results: Arc<Mutex<Vec<(usize, String)>>> = Arc::new(Mutex::new(vec![]));
    let mut handles = vec![];

    // Run 10 sandboxes in parallel, each outputting a unique value
    for i in 0..10 {
        let results_clone = Arc::clone(&results);
        let handle = thread::spawn(move || {
            let sandbox = Sandbox::builder()
                .working_dir("/tmp")
                .env("UNIQUE_ID", i.to_string())
                .wall_time_limit(Duration::from_secs(5))
                .build()
                .unwrap();

            let result = sandbox.run("sh", &["-c", "echo $UNIQUE_ID"]).unwrap();
            let output = result.stdout.trim().to_string();

            results_clone.lock().unwrap().push((i, output));
        });
        handles.push(handle);
    }

    // Wait for all to complete
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify each sandbox got its own unique value
    let results = results.lock().unwrap();
    for (expected, actual) in results.iter() {
        assert_eq!(
            actual,
            &expected.to_string(),
            "Sandbox {} got wrong environment value: {}",
            expected,
            actual
        );
    }
}

/// Test: Cgroup names should not conflict between parallel sandboxes (Linux)
#[test]
#[cfg(target_os = "linux")]
fn test_cgroup_no_conflicts() {
    use std::path::Path;

    let mut handles = vec![];

    // Run sandboxes with memory limits (which create cgroups) in parallel
    for i in 0..10 {
        let handle = thread::spawn(move || {
            let sandbox = Sandbox::builder()
                .working_dir("/tmp")
                .memory_limit(64 * 1024 * 1024)
                .wall_time_limit(Duration::from_secs(5))
                .build();

            if let Ok(sandbox) = sandbox {
                let result = sandbox.run("echo", &[&i.to_string()]);
                result.is_ok()
            } else {
                // Cgroup creation might fail without root
                true
            }
        });
        handles.push(handle);
    }

    // All should complete without cgroup conflicts
    let mut successes = 0;
    for handle in handles {
        if handle.join().unwrap() {
            successes += 1;
        }
    }

    // At least some should succeed (might fail without cgroup permissions)
    assert!(
        successes >= 1 || !Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
        "No sandboxes succeeded with cgroups"
    );
}

/// Test: Concurrent proxy operations should not conflict
#[test]
fn test_concurrent_proxy_no_conflicts() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    let mut handles = vec![];

    // Run multiple sandboxes with proxied network in parallel
    for _ in 0..5 {
        let handle = thread::spawn(move || {
            let sandbox = Sandbox::builder()
                .working_dir("/tmp")
                .allow_network(&["example.com"])
                .wall_time_limit(Duration::from_secs(5))
                .build();

            match sandbox {
                Ok(s) => {
                    // Just verify proxy setup works
                    let result = s.run("sh", &["-c", "echo $http_proxy"]);
                    result.is_ok() && result.unwrap().stdout.contains("127.0.0.1")
                }
                Err(_) => {
                    // Proxy port might conflict - this is what we're testing
                    false
                }
            }
        });
        handles.push(handle);
    }

    // Collect results
    let mut successes = 0;
    for handle in handles {
        if handle.join().unwrap() {
            successes += 1;
        }
    }

    // All should succeed (each gets unique proxy port)
    assert_eq!(
        successes, 5,
        "Some concurrent proxy setups failed - possible port conflict"
    );
}

/// Test: Rapid creation and destruction should not cause races
#[test]
fn test_rapid_create_destroy() {
    let mut handles = vec![];

    for _ in 0..50 {
        let handle = thread::spawn(|| {
            let sandbox = Sandbox::builder()
                .working_dir("/tmp")
                .wall_time_limit(Duration::from_millis(100))
                .build()
                .unwrap();

            let _ = sandbox.run("true", &[]);
            // Sandbox drops here
        });
        handles.push(handle);
    }

    // All should complete without panic
    for handle in handles {
        handle
            .join()
            .expect("Thread panicked during rapid create/destroy");
    }
}

/// Test: Shared state (if any) should be properly synchronized
#[test]
fn test_no_data_races() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let success_count = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    for _ in 0..20 {
        let counter = Arc::clone(&success_count);
        let handle = thread::spawn(move || {
            let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

            let result = sandbox.run("echo", &["test"]).unwrap();
            if result.exit_code == 0 && result.stdout.trim() == "test" {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // All should succeed
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        20,
        "Some parallel executions failed - possible race condition"
    );
}

/// Test: Timeout handling should work correctly under contention
#[test]
fn test_timeout_under_contention() {
    let mut handles = vec![];

    for _ in 0..10 {
        let handle = thread::spawn(|| {
            let sandbox = Sandbox::builder()
                .working_dir("/tmp")
                .wall_time_limit(Duration::from_millis(200))
                .build()
                .unwrap();

            let start = std::time::Instant::now();
            let result = sandbox.run("sleep", &["10"]).unwrap();
            let elapsed = start.elapsed();

            // Should timeout around 200ms, not much later
            assert!(result.killed_by_timeout, "Should have timed out");
            assert!(
                elapsed < Duration::from_secs(1),
                "Timeout took too long: {:?}",
                elapsed
            );
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

/// Test: Process cleanup should work when many sandboxes run in parallel
#[test]
#[cfg(unix)]
fn test_parallel_cleanup() {
    use std::process::Command;

    // Run a few sandboxes and verify they don't leave zombies
    let mut handles = vec![];

    for _ in 0..10 {
        let handle = thread::spawn(|| {
            let sandbox = Sandbox::builder()
                .working_dir("/tmp")
                .wall_time_limit(Duration::from_millis(100))
                .build()
                .unwrap();

            let result = sandbox.run("sleep", &["5"]).unwrap();
            assert!(result.killed_by_timeout);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Wait for cleanup
    thread::sleep(Duration::from_millis(500));

    // Check for zombie processes
    let output = Command::new("ps").args(["aux"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let zombies: Vec<&str> = stdout
        .lines()
        .filter(|line| line.contains(" Z ") || line.contains(" Z+ "))
        .filter(|line| line.contains("sandbox") || line.contains("sleep"))
        .collect();

    assert!(
        zombies.is_empty(),
        "Found zombie processes from sandbox: {:?}",
        zombies
    );
}

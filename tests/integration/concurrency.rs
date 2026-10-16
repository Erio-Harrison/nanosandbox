//! Concurrency: unique IDs, parallel runs, cgroup names, proxy ports, fd isolation.

use nanosandbox::Sandbox;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[test]
#[cfg(unix)]
fn test_sandbox_id_unique_across_threads() {
    let ids: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let mut handles = vec![];

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

    assert_eq!(ids.lock().unwrap().len(), 100);
}

#[test]
#[cfg(unix)]
fn test_parallel_execution_isolation() {
    let results: Arc<Mutex<Vec<(usize, String)>>> = Arc::new(Mutex::new(vec![]));
    let mut handles = vec![];

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

    for handle in handles {
        handle.join().unwrap();
    }

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

#[test]
#[cfg(target_os = "linux")]
fn test_cgroup_no_conflicts() {
    use std::path::Path;

    let mut handles = vec![];

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
                true
            }
        });
        handles.push(handle);
    }

    let mut successes = 0;
    for handle in handles {
        if handle.join().unwrap() {
            successes += 1;
        }
    }

    assert!(
        successes >= 1 || !Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
        "No sandboxes succeeded with cgroups"
    );
}

#[test]
#[cfg(unix)]
fn test_concurrent_proxy_no_conflicts() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    let mut handles = vec![];

    for _ in 0..5 {
        let handle = thread::spawn(move || {
            let sandbox = Sandbox::builder()
                .working_dir("/tmp")
                .allow_network(&["example.com"])
                .wall_time_limit(Duration::from_secs(5))
                .build();

            match sandbox {
                Ok(s) => {
                    let result = s.run("sh", &["-c", "echo $http_proxy"]);
                    result.is_ok() && result.unwrap().stdout.contains("127.0.0.1")
                }
                Err(_) => false,
            }
        });
        handles.push(handle);
    }

    let mut successes = 0;
    for handle in handles {
        if handle.join().unwrap() {
            successes += 1;
        }
    }

    assert_eq!(
        successes, 5,
        "Some concurrent proxy setups failed - possible port conflict"
    );
}

#[test]
#[cfg(unix)]
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
        });
        handles.push(handle);
    }

    for handle in handles {
        handle
            .join()
            .expect("Thread panicked during rapid create/destroy");
    }
}

#[test]
#[cfg(unix)]
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

    assert_eq!(
        success_count.load(Ordering::SeqCst),
        20,
        "Some parallel executions failed - possible race condition"
    );
}

#[test]
#[cfg(unix)]
fn test_timeout_under_contention() {
    let mut handles = vec![];

    for _ in 0..10 {
        let handle = thread::spawn(|| {
            // 1s, not 200ms: 10 polling loops on a loaded CI runner need margin; still far under the 10s sleep.
            let sandbox = Sandbox::builder()
                .working_dir("/tmp")
                .wall_time_limit(Duration::from_secs(1))
                .build()
                .unwrap();

            let start = std::time::Instant::now();
            let result = sandbox.run("sleep", &["10"]).unwrap();
            let elapsed = start.elapsed();

            assert!(result.killed_by_timeout, "Should have timed out");
            assert!(
                elapsed < Duration::from_secs(5),
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

#[test]
#[cfg(unix)]
fn test_parallel_cleanup() {
    use std::process::Command;

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

    // Poll for cleanup: a loaded CI runner reaps slower; only eventual completion matters.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let zombies = loop {
        let output = Command::new("ps").args(["aux"]).output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let zombies: Vec<String> = stdout
            .lines()
            .filter(|line| line.contains(" Z ") || line.contains(" Z+ "))
            .filter(|line| line.contains("sandbox") || line.contains("sleep"))
            .map(str::to_string)
            .collect();
        if zombies.is_empty() || std::time::Instant::now() >= deadline {
            break zombies;
        }
        thread::sleep(Duration::from_millis(100));
    };

    assert!(
        zombies.is_empty(),
        "Found zombie processes from sandbox: {:?}",
        zombies
    );
}

/// A run gets only its own stdin/stdout/stderr while other threads' pipes are open; they used to leak in.
#[test]
#[cfg(target_os = "linux")]
fn test_no_fds_leak_between_concurrent_runs() {
    let sandbox = Arc::new(
        Sandbox::builder()
            .working_dir("/tmp")
            .wall_time_limit(Duration::from_secs(10))
            .build()
            .unwrap(),
    );

    // Baseline measured up front: some CI runners (GitHub Actions Linux) hold an ambient fd in every
    // child, which isn't cross-talk.
    let baseline = sandbox
        .run_with_input(
            "sh",
            &["-c", "cat >/dev/null; ls /proc/self/fd"],
            Some(b"in"),
        )
        .unwrap()
        .stdout;

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let sandbox = Arc::clone(&sandbox);
            let baseline = baseline.clone();
            thread::spawn(move || {
                let mut leaks = Vec::new();
                for _ in 0..15 {
                    // `ls` itself holds the directory open as fd 3.
                    let result = sandbox
                        .run_with_input(
                            "sh",
                            &["-c", "cat >/dev/null; ls /proc/self/fd"],
                            Some(b"in"),
                        )
                        .unwrap();
                    if result.stdout != baseline {
                        leaks.push(result.stdout);
                    }
                }
                leaks
            })
        })
        .collect();

    let leaks: Vec<String> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    assert!(leaks.is_empty(), "fds leaked into sandboxes: {leaks:?}");
}

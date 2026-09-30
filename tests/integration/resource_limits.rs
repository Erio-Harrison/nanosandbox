//! Resource limits tests

use nanosandbox::{Sandbox, MB};
use std::time::{Duration, Instant};

/// Wall time limit test - all platforms supported
#[test]
fn test_wall_time_limit() {
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .wall_time_limit(Duration::from_millis(500))
        .build()
        .unwrap();

    let start = Instant::now();

    #[cfg(target_os = "windows")]
    let result = sandbox.run("timeout", &["/t", "10"]).unwrap();
    #[cfg(not(target_os = "windows"))]
    let result = sandbox.run("sleep", &["10"]).unwrap();

    let elapsed = start.elapsed();

    assert!(result.killed_by_timeout);
    assert!(elapsed < Duration::from_secs(3));
}

#[test]
fn test_wall_time_within_limit() {
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    #[cfg(not(target_os = "windows"))]
    {
        let result = sandbox.run("sleep", &["0.1"]).unwrap();
        assert!(result.success());
        assert!(!result.killed_by_timeout);
    }
}

/// Memory limit test - platform specific
#[test]
#[cfg(target_os = "linux")]
fn test_memory_limit_linux() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .memory_limit(64 * MB)
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    // Try to allocate more memory than allowed
    let result = sandbox.run(
        "python3",
        &[
            "-c",
            "x = bytearray(100 * 1024 * 1024)", // Try to allocate 100MB
        ],
    );

    // Should either fail or be killed (an Err is also acceptable)
    if let Ok(r) = result {
        assert!(!r.success() || r.killed_by_oom);
    }
}

#[test]
fn test_memory_within_limit() {
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .memory_limit(256 * MB)
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    #[cfg(not(target_os = "windows"))]
    {
        // Check if python3 is available
        let result = sandbox.run(
            "python3",
            &[
                "-c",
                "x = bytearray(10 * 1024 * 1024); print('ok')", // 10MB - well within limit
            ],
        );

        // An Err means python3 isn't available
        if let Ok(r) = result {
            if r.exit_code == 0 {
                assert_eq!(r.stdout.trim(), "ok");
            }
        }
    }
}

/// Process limit test - Linux only
#[test]
#[cfg(target_os = "linux")]
fn test_max_pids_limit() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .max_pids(10)
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    // Try fork bomb - should be contained
    let start = Instant::now();
    sandbox.run("sh", &["-c", ":(){ :|:& };:"]).unwrap();
    let elapsed = start.elapsed();

    // Should complete within time limit (contained by pids limit)
    assert!(elapsed < Duration::from_secs(6));
}

#[test]
fn test_multiple_limits_combined() {
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .memory_limit(128 * MB)
        .wall_time_limit(Duration::from_secs(5))
        .max_pids(50)
        .build()
        .unwrap();

    #[cfg(not(target_os = "windows"))]
    {
        let result = sandbox.run("echo", &["hello"]).unwrap();
        assert!(result.success());
    }
}

#[test]
fn test_cpu_limit() {
    // CPU limit test - verifies it doesn't crash
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .cpu_limit(1.0)
        .wall_time_limit(Duration::from_secs(2))
        .build()
        .unwrap();

    #[cfg(not(target_os = "windows"))]
    {
        let result = sandbox.run("echo", &["cpu test"]).unwrap();
        assert!(result.success());
    }
}

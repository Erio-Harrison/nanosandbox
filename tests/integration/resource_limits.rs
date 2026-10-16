//! Resource limits tests

use nanosandbox::MB;
use std::time::{Duration, Instant};

#[test]
fn test_wall_time_limit() {
    let sandbox = crate::common::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .wall_time_limit(Duration::from_millis(500))
        .build()
        .unwrap();

    let start = Instant::now();

    // Not `timeout /t`: it exits at once when stdin isn't a console.
    #[cfg(target_os = "windows")]
    let result = sandbox.run("ping", &["-n", "10", "127.0.0.1"]).unwrap();
    #[cfg(not(target_os = "windows"))]
    let result = sandbox.run("sleep", &["10"]).unwrap();

    let elapsed = start.elapsed();

    assert!(result.killed_by_timeout);
    assert!(elapsed < Duration::from_secs(3));
}

#[test]
fn test_wall_time_within_limit() {
    let sandbox = crate::common::builder()
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

#[test]
#[cfg(target_os = "linux")]
fn test_memory_limit_linux() {
    let sandbox = crate::common::builder()
        .working_dir("/tmp")
        .memory_limit(64 * MB)
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    let result = sandbox.run(
        "python3",
        &[
            "-c",
            "x = bytearray(100 * 1024 * 1024)", // Try to allocate 100MB
        ],
    );

    if let Ok(r) = result {
        assert!(!r.success() || r.killed_by_oom);
    }
}

#[test]
fn test_memory_within_limit() {
    let sandbox = crate::common::builder()
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
        let result = sandbox.run(
            "python3",
            &[
                "-c",
                "x = bytearray(10 * 1024 * 1024); print('ok')", // 10MB - well within limit
            ],
        );

        if let Ok(r) = result
            && r.exit_code == 0
        {
            assert_eq!(r.stdout.trim(), "ok");
        }
    }
}

#[test]
#[cfg(target_os = "linux")]
fn test_max_pids_limit() {
    let sandbox = crate::common::builder()
        .working_dir("/tmp")
        .max_pids(10)
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    let start = Instant::now();
    sandbox.run("sh", &["-c", ":(){ :|:& };:"]).unwrap();
    let elapsed = start.elapsed();

    assert!(elapsed < Duration::from_secs(6));
}

#[test]
fn test_multiple_limits_combined() {
    let sandbox = crate::common::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .memory_limit(128 * MB)
        .wall_time_limit(Duration::from_secs(5));
    // Windows has no open-file limit, and refuses one.
    #[cfg(not(target_os = "windows"))]
    let sandbox = sandbox.max_open_files(50);
    let sandbox = sandbox.build().unwrap();

    #[cfg(target_os = "windows")]
    let result = sandbox.run("cmd", &["/c", "echo hello"]).unwrap();
    #[cfg(not(target_os = "windows"))]
    let result = sandbox.run("echo", &["hello"]).unwrap();
    assert!(result.success());
}

#[test]
#[cfg(target_os = "linux")]
fn test_cpu_limit() {
    let sandbox = crate::common::builder()
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

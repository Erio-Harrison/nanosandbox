//! Observability: timing, IDs, platform, exit codes, signals, output capture.

use nanosandbox::Sandbox;
use std::time::Duration;

#[test]
#[cfg(unix)]
fn test_result_contains_timing() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox.run("sleep", &["0.1"]).unwrap();

    assert!(
        result.duration > Duration::from_millis(50),
        "Duration too short: {:?}",
        result.duration
    );
    assert!(
        result.duration < Duration::from_secs(5),
        "Duration too long: {:?}",
        result.duration
    );
}

#[test]
#[cfg(unix)]
fn test_sandbox_has_traceable_id() {
    let sandbox1 = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let sandbox2 = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let id1 = sandbox1.id();
    let id2 = sandbox2.id();

    assert!(!id1.is_empty(), "Sandbox ID should not be empty");
    assert!(!id2.is_empty(), "Sandbox ID should not be empty");

    assert_ne!(id1, id2, "Sandbox IDs should be unique");

    assert!(
        id1.chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
        "Sandbox ID should be log-friendly: {}",
        id1
    );
}

#[test]
fn test_platform_identifiable() {
    let sandbox = crate::common::builder()
        .working_dir("/tmp")
        .build()
        .unwrap();

    let platform = sandbox.platform();

    assert!(
        ["linux", "macos", "windows"].contains(&platform),
        "Unknown platform: {}",
        platform
    );

    #[cfg(target_os = "linux")]
    assert_eq!(platform, "linux");

    #[cfg(target_os = "macos")]
    assert_eq!(platform, "macos");

    #[cfg(target_os = "windows")]
    assert_eq!(platform, "windows");
}

#[test]
#[cfg(unix)]
fn test_exit_code_accuracy() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    for expected_code in [0, 1, 42, 127, 255] {
        let result = sandbox
            .run("sh", &["-c", &format!("exit {}", expected_code)])
            .unwrap();
        assert_eq!(
            result.exit_code, expected_code,
            "Exit code mismatch: expected {}, got {}",
            expected_code, result.exit_code
        );
    }
}

/// On Linux the command runs under an init shim that relays signals, so exercise our own
/// wall_time_limit kill, sent from outside the namespace: the one path every build shares.
#[test]
#[cfg(unix)]
fn test_signal_capture() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_millis(300))
        .build()
        .unwrap();

    let result = sandbox.run("sleep", &["10"]).unwrap();

    assert!(result.killed_by_timeout);
    assert_eq!(result.signal, Some(9), "Should be SIGKILL (9)");
}

#[test]
#[cfg(unix)]
fn test_timeout_flag_accuracy() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_millis(100))
        .build()
        .unwrap();

    let result = sandbox.run("true", &[]).unwrap();
    assert!(!result.killed_by_timeout, "true should not timeout");

    let result = sandbox.run("sleep", &["10"]).unwrap();
    assert!(
        result.killed_by_timeout,
        "sleep 10 should timeout with 100ms limit"
    );
}

#[test]
#[cfg(unix)]
fn test_output_separation() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox
        .run("sh", &["-c", "echo STDOUT; echo STDERR >&2"])
        .unwrap();

    assert!(
        result.stdout.contains("STDOUT"),
        "Stdout should contain STDOUT: {}",
        result.stdout
    );
    assert!(
        result.stderr.contains("STDERR"),
        "Stderr should contain STDERR: {}",
        result.stderr
    );
    assert!(
        !result.stdout.contains("STDERR"),
        "Stdout should not contain STDERR"
    );
    assert!(
        !result.stderr.contains("STDOUT"),
        "Stderr should not contain STDOUT"
    );
}

#[test]
#[cfg(unix)]
fn test_resource_metrics_structure() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .memory_limit(128 * 1024 * 1024)
        .build()
        .unwrap();

    let result = sandbox.run("echo", &["test"]).unwrap();

    let _ = result.peak_memory;
    let _ = result.cpu_time;
    let _ = result.killed_by_oom;
}

/// A normal run gets its own private /proc. The AppArmor-restricted case isn't covered;
/// see docs/platform-linux.md.
#[test]
#[cfg(target_os = "linux")]
fn test_proc_isolated_true_outside_apparmor_restriction() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();
    let result = sandbox.run("true", &[]).unwrap();
    assert!(result.proc_isolated);
}

#[test]
#[cfg(unix)]
fn test_duration_accuracy() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox.run("true", &[]).unwrap();
    assert!(
        result.duration < Duration::from_secs(1),
        "true should be fast: {:?}",
        result.duration
    );

    let result = sandbox.run("sleep", &["0.2"]).unwrap();
    assert!(
        result.duration >= Duration::from_millis(150),
        "sleep 0.2 should take ~200ms: {:?}",
        result.duration
    );
    assert!(
        result.duration < Duration::from_secs(1),
        "sleep 0.2 should not take 1s: {:?}",
        result.duration
    );
}

#[test]
#[cfg(unix)]
fn test_independent_metrics() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let results: Vec<_> = (0..3)
        .map(|i| {
            sandbox
                .run("sh", &["-c", &format!("sleep 0.{}; echo {}", i + 1, i)])
                .unwrap()
        })
        .collect();

    for (i, result) in results.iter().enumerate() {
        assert!(
            result.stdout.trim() == i.to_string(),
            "Output should be independent"
        );
    }

    assert!(
        results[0].duration < results[2].duration,
        "Durations should reflect sleep time"
    );
}

#[test]
#[cfg(unix)]
fn test_error_output_capture() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                r#"
        echo "Error line 1" >&2
        echo "Error line 2" >&2
        echo "Error line 3" >&2
        exit 1
    "#,
            ],
        )
        .unwrap();

    assert_eq!(result.exit_code, 1);
    assert!(result.stderr.contains("Error line 1"));
    assert!(result.stderr.contains("Error line 2"));
    assert!(result.stderr.contains("Error line 3"));
}

#[test]
#[cfg(unix)]
fn test_large_output_capture() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(30))
        .build()
        .unwrap();

    let result = sandbox.run("sh", &["-c",
        "i=1; while [ $i -le 500 ]; do echo \"Line $i: This is test content\"; i=$((i+1)); done"
    ]).unwrap();

    assert!(
        result.exit_code == 0,
        "Exit code should be 0, got {}. stderr: {}",
        result.exit_code,
        result.stderr
    );
    assert!(
        result.stdout.len() > 10000,
        "Should capture large output: {} bytes",
        result.stdout.len()
    );
    assert!(
        result.stdout.contains("Line 1:"),
        "Should contain first line"
    );
    assert!(
        result.stdout.contains("Line 500:"),
        "Should contain last line"
    );
}

#[test]
#[cfg(unix)]
fn test_binary_output_handling() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                r#"
        printf '\x00\x01\x02\x03'
        echo "text after binary"
    "#,
            ],
        )
        .unwrap();

    assert!(
        result.stdout.contains("text after binary"),
        "Text after binary should be captured"
    );
}

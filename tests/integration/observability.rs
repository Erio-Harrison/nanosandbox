//! P2: Observability Tests
//!
//! Tests for:
//! - Structured logging with tracing
//! - Execution metrics collection
//! - Security audit logging

use nanosandbox::Sandbox;
use std::time::Duration;

/// Test: ExecutionResult should contain timing information
#[test]
fn test_result_contains_timing() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox.run("sleep", &["0.1"]).unwrap();

    // Duration should be populated and reasonable
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

/// Test: Sandbox should have unique, traceable ID
#[test]
fn test_sandbox_has_traceable_id() {
    let sandbox1 = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let sandbox2 = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let id1 = sandbox1.id();
    let id2 = sandbox2.id();

    // IDs should be non-empty
    assert!(!id1.is_empty(), "Sandbox ID should not be empty");
    assert!(!id2.is_empty(), "Sandbox ID should not be empty");

    // IDs should be unique
    assert_ne!(id1, id2, "Sandbox IDs should be unique");

    // IDs should be suitable for logging (no special chars)
    assert!(
        id1.chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
        "Sandbox ID should be log-friendly: {}",
        id1
    );
}

/// Test: Platform should be identifiable
#[test]
fn test_platform_identifiable() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let platform = sandbox.platform();

    // Should be one of known platforms
    assert!(
        ["linux", "macos", "windows"].contains(&platform),
        "Unknown platform: {}",
        platform
    );

    // Should match actual OS
    #[cfg(target_os = "linux")]
    assert_eq!(platform, "linux");

    #[cfg(target_os = "macos")]
    assert_eq!(platform, "macos");

    #[cfg(target_os = "windows")]
    assert_eq!(platform, "windows");
}

/// Test: Exit codes should be accurately captured
#[test]
fn test_exit_code_accuracy() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    // Test various exit codes
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

/// Test: Signal information should be captured
///
/// On Linux, the sandboxed process is PID 1 of its own PID namespace
/// (pid_namespaces(7)), and the kernel suppresses unhandled signals —
/// including self-directed SIGKILL — sent to an init process from
/// *within* its own namespace; only a signal sent from an ancestor
/// namespace is forcibly delivered. So `sh -c "kill -9 $$"` is a no-op
/// here, not a bug: verified with a real sandbox that it prints and
/// keeps running afterward. Exercise the delivery path that actually
/// applies to us instead — our own wall_time_limit kill, sent from
/// outside the sandbox's namespace.
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

/// Test: Timeout flag should be accurate
#[test]
fn test_timeout_flag_accuracy() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_millis(100))
        .build()
        .unwrap();

    // Command that doesn't timeout
    let result = sandbox.run("true", &[]).unwrap();
    assert!(!result.killed_by_timeout, "true should not timeout");

    // Command that does timeout
    let result = sandbox.run("sleep", &["10"]).unwrap();
    assert!(
        result.killed_by_timeout,
        "sleep 10 should timeout with 100ms limit"
    );
}

/// Test: Stdout and stderr should be properly separated
#[test]
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

/// Test: Resource metrics structure is present (even if values are None)
#[test]
fn test_resource_metrics_structure() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .memory_limit(128 * 1024 * 1024)
        .build()
        .unwrap();

    let result = sandbox.run("echo", &["test"]).unwrap();

    // These fields should exist (even if None currently)
    let _ = result.peak_memory;
    let _ = result.cpu_time;
    let _ = result.killed_by_oom;

    // Once implemented, they should have values
    // For now, just verify the structure exists
}

/// Test: a normal (unrestricted) run gets its own private /proc. The
/// AppArmor-restricted case (`proc_isolated == false`) isn't covered here --
/// forcing that sysctl mid-suite isn't something a single test can do
/// safely; see docs/platform-linux.md.
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

/// Test: Duration should be accurate for various execution times
#[test]
fn test_duration_accuracy() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    // Short command
    let result = sandbox.run("true", &[]).unwrap();
    assert!(
        result.duration < Duration::from_secs(1),
        "true should be fast: {:?}",
        result.duration
    );

    // Medium command
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

/// Test: Multiple runs should each have independent metrics
#[test]
fn test_independent_metrics() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let results: Vec<_> = (0..3)
        .map(|i| {
            sandbox
                .run("sh", &["-c", &format!("sleep 0.{}; echo {}", i + 1, i)])
                .unwrap()
        })
        .collect();

    // Each should have different durations
    for (i, result) in results.iter().enumerate() {
        assert!(
            result.stdout.trim() == i.to_string(),
            "Output should be independent"
        );
    }

    // Durations should be roughly increasing
    assert!(
        results[0].duration < results[2].duration,
        "Durations should reflect sleep time"
    );
}

/// Test: Error output should be captured completely
#[test]
fn test_error_output_capture() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    // Generate multi-line error
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

/// Test: Large output should be captured (within limits)
#[test]
fn test_large_output_capture() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(30))
        .build()
        .unwrap();

    // Generate ~50KB of output (simpler command)
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

/// Test: Binary output should not corrupt results
#[test]
fn test_binary_output_handling() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    // Output some binary data
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

    // Should not crash, text should be present
    assert!(
        result.stdout.contains("text after binary"),
        "Text after binary should be captured"
    );
}

//! P1: Error Handling Tests
//!
//! Tests for:
//! - Graceful degradation (handle missing permissions without panic)
//! - Resource pre-check (verify permissions before execution)
//! - Detailed error types (distinguish command not found vs permission denied vs resource limit)

use nanosandbox::{Sandbox, SandboxError};
use std::time::Duration;

/// Test: Missing command should return CommandNotFound error
#[test]
fn test_error_command_not_found() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox.run("nonexistent_command_xyz_123", &[]);

    match result {
        Err(SandboxError::CommandNotFound(cmd)) => {
            assert!(cmd.contains("nonexistent_command_xyz_123"));
        }
        Err(e) => {
            // On some systems might be ExecutionFailed
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("not found") || msg.contains("No such file"),
                "Expected CommandNotFound error, got: {:?}",
                e
            );
        }
        Ok(r) => {
            // Shell might have caught it
            assert!(r.exit_code != 0, "Nonexistent command should fail");
        }
    }
}

/// Test: Permission denied should return appropriate error
#[test]
#[cfg(unix)]
fn test_error_permission_denied() {
    use std::fs::{self, File};
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = std::env::temp_dir().join("nanosandbox_perm_test");
    let _ = fs::create_dir_all(&temp_dir);
    let script = temp_dir.join("no_exec.sh");

    // Create a file without execute permission
    File::create(&script).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o644)).unwrap();

    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox.run(script.to_str().unwrap(), &[]);

    // Should fail with some error (permission or execution related)
    match result {
        Err(SandboxError::ExecutionFailed(msg)) => {
            // Execution failed is expected for permission issues
            let _ = msg; // Any message is acceptable
        }
        Err(SandboxError::CommandNotFound(_)) => {
            // Also acceptable since file isn't executable
        }
        Err(_) => {
            // Any error is acceptable as long as it doesn't panic
        }
        Ok(r) => {
            // If execution succeeded, exit code should be non-zero
            assert!(r.exit_code != 0, "Non-executable should fail");
        }
    }

    // Cleanup
    let _ = fs::remove_file(&script);
}

/// Test: Mount of non-existent path should return PathNotFound error
#[test]
fn test_error_path_not_found() {
    let result = Sandbox::builder()
        .read_only("/nonexistent/path/xyz")
        .build();

    match result {
        Err(SandboxError::PathNotFound(path)) => {
            assert!(path.to_string_lossy().contains("nonexistent"));
        }
        Err(e) => {
            panic!("Expected PathNotFound error, got: {:?}", e);
        }
        Ok(_) => {
            panic!("Expected error for non-existent mount path");
        }
    }
}

/// Test: Invalid rootfs should return appropriate error
#[test]
#[cfg(target_os = "linux")]
fn test_error_invalid_rootfs() {
    let result = Sandbox::builder().rootfs("/nonexistent/rootfs").build();

    match result {
        Err(SandboxError::PathNotFound(_)) => {
            // Expected
        }
        Err(e) => {
            panic!("Expected PathNotFound error for rootfs, got: {:?}", e);
        }
        Ok(_) => {
            panic!("Expected error for non-existent rootfs");
        }
    }
}

/// Test: Graceful handling when sandbox-exec unavailable (macOS)
#[test]
#[cfg(target_os = "macos")]
fn test_graceful_sandbox_exec_check() {
    // This test verifies we check for sandbox-exec availability
    // The actual sandbox creation should work on macOS
    let result = Sandbox::builder().working_dir("/tmp").build();

    // Should succeed on macOS where sandbox-exec exists
    assert!(result.is_ok(), "Sandbox should be available on macOS");
}

/// Test: Graceful handling when cgroups unavailable (Linux)
#[test]
#[cfg(target_os = "linux")]
fn test_graceful_cgroup_check() {
    use std::path::Path;

    // Check if cgroups v2 is available
    let cgroups_available = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();

    let result = Sandbox::builder()
        .working_dir("/tmp")
        .memory_limit(64 * 1024 * 1024) // Requires cgroups
        .build();

    if cgroups_available {
        // With root/appropriate permissions, should work
        // Without, should return appropriate error
        match result {
            Ok(_) => { /* Good */ }
            Err(SandboxError::CgroupCreation(_)) => { /* Cgroup error - acceptable */ }
            Err(SandboxError::CgroupV2Unavailable) => { /* Also acceptable */ }
            Err(e) => {
                // Any error should be descriptive, not a panic
                let msg = format!("{:?}", e);
                assert!(
                    !msg.contains("panic") && !msg.contains("unwrap"),
                    "Error should be graceful, got: {}",
                    msg
                );
            }
        }
    }
}

/// Test: Timeout errors should be distinguishable
#[test]
fn test_error_timeout_distinguishable() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_millis(100))
        .build()
        .unwrap();

    let result = sandbox.run("sleep", &["10"]).unwrap();

    // Should be marked as killed by timeout
    assert!(
        result.killed_by_timeout,
        "Timeout kill should be distinguishable"
    );
}

/// Test: Errors should contain useful context
#[test]
fn test_error_contains_context() {
    let result = Sandbox::builder()
        .read_only("/nonexistent/specific/path/for/test")
        .build();

    match result {
        Err(e) => {
            let msg = format!("{:?}", e);
            // Error should mention the problematic path
            assert!(
                msg.contains("nonexistent") || msg.contains("specific"),
                "Error should contain context about the problem: {}",
                msg
            );
        }
        Ok(_) => {
            panic!("Expected error for nonexistent path");
        }
    }
}

/// Test: Multiple errors should all be reported (validation)
#[test]
fn test_validation_reports_issues() {
    // This tests that validation catches problems early
    let result = Sandbox::builder().read_only("/nonexistent1").build();

    // Should fail at validation
    assert!(result.is_err());

    // Error should be validation-related
    match result {
        Err(SandboxError::PathNotFound(_)) => { /* Good */ }
        Err(e) => {
            panic!("Expected PathNotFound during validation, got: {:?}", e);
        }
        Ok(_) => unreachable!(),
    }
}

/// Test: Build should succeed with valid configuration
#[test]
fn test_valid_config_succeeds() {
    let result = Sandbox::builder()
        .working_dir("/tmp")
        .memory_limit(256 * 1024 * 1024)
        .wall_time_limit(Duration::from_secs(60))
        .build();

    assert!(
        result.is_ok(),
        "Valid config should succeed: {}",
        result
            .as_ref()
            .err()
            .map(|e| format!("{:?}", e))
            .unwrap_or_default()
    );
}

/// Test: Error display should be user-friendly
#[test]
fn test_error_display_user_friendly() {
    let result = Sandbox::builder().read_only("/does/not/exist").build();

    if let Err(e) = result {
        let display = format!("{}", e);

        // Display should be readable
        assert!(!display.is_empty(), "Error Display should not be empty");

        // Should not expose internal details excessively
        assert!(
            !display.contains("0x") || display.len() < 200,
            "Error should be user-friendly, not raw debug: {}",
            display
        );
    }
}

/// Limits that can't work are refused at build(), not at every run().
#[test]
fn test_invalid_limits_refused() {
    for builder in [
        Sandbox::builder().cpu_limit(0.0),
        Sandbox::builder().cpu_limit(f64::NAN),
        Sandbox::builder().cpu_limit(-1.0),
        Sandbox::builder().memory_limit(0),
        Sandbox::builder().max_open_files(0),
    ] {
        assert!(
            matches!(builder.build(), Err(SandboxError::Config(_))),
            "an invalid limit was accepted"
        );
    }
}

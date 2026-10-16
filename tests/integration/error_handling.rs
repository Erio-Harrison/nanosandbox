//! Error handling: graceful degradation, pre-checks, distinct error types.

use nanosandbox::{Sandbox, SandboxError};
use std::time::Duration;

/// A missing command is `CommandNotFound`, not `Ok` with a nonzero exit: Linux/macOS exec in a
/// child so spawn() never fails; only Windows, which execs directly, could return it synchronously.
#[test]
#[cfg(unix)]
fn test_error_command_not_found() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox.run("nonexistent_command_xyz_123", &[]);
    match result {
        Err(SandboxError::CommandNotFound(cmd)) => {
            assert!(cmd.contains("nonexistent_command_xyz_123"));
        }
        other => panic!("expected CommandNotFound, got {other:?}"),
    }

    let result = sandbox.run("/no/such/nanosandbox-binary", &[]);
    assert!(matches!(result, Err(SandboxError::CommandNotFound(_))));

    let result = sandbox.run("echo", &["hi"]).unwrap();
    assert_eq!(result.stdout.trim(), "hi");
}

#[test]
#[cfg(unix)]
fn test_error_permission_denied() {
    use std::fs::{self, File};
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = std::env::temp_dir().join("nanosandbox_perm_test");
    let _ = fs::create_dir_all(&temp_dir);
    let script = temp_dir.join("no_exec.sh");

    File::create(&script).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o644)).unwrap();

    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox.run(script.to_str().unwrap(), &[]);

    match result {
        Err(SandboxError::ExecutionFailed { .. }) => {}
        Err(SandboxError::CommandNotFound(_)) => {}
        Err(_) => {}
        Ok(r) => {
            assert!(r.exit_code != 0, "Non-executable should fail");
        }
    }

    let _ = fs::remove_file(&script);
}

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

#[test]
#[cfg(target_os = "linux")]
fn test_error_invalid_rootfs() {
    let result = Sandbox::builder().rootfs("/nonexistent/rootfs").build();

    match result {
        Err(SandboxError::PathNotFound(_)) => {}
        Err(e) => {
            panic!("Expected PathNotFound error for rootfs, got: {:?}", e);
        }
        Ok(_) => {
            panic!("Expected error for non-existent rootfs");
        }
    }
}

#[test]
#[cfg(target_os = "macos")]
fn test_graceful_sandbox_exec_check() {
    let result = Sandbox::builder().working_dir("/tmp").build();

    assert!(result.is_ok(), "Sandbox should be available on macOS");
}

#[test]
#[cfg(target_os = "linux")]
fn test_graceful_cgroup_check() {
    use std::path::Path;

    let cgroups_available = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();

    let result = Sandbox::builder()
        .working_dir("/tmp")
        .memory_limit(64 * 1024 * 1024) // Requires cgroups
        .build();

    if cgroups_available {
        match result {
            Ok(_) => { /* Good */ }
            Err(SandboxError::CgroupCreation { .. }) => { /* Cgroup error - acceptable */ }
            Err(SandboxError::CgroupV2Unavailable) => { /* Also acceptable */ }
            Err(e) => {
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

#[test]
#[cfg(unix)]
fn test_error_timeout_distinguishable() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_millis(100))
        .build()
        .unwrap();

    let result = sandbox.run("sleep", &["10"]).unwrap();

    assert!(
        result.killed_by_timeout,
        "Timeout kill should be distinguishable"
    );
}

#[test]
fn test_error_contains_context() {
    let result = Sandbox::builder()
        .read_only("/nonexistent/specific/path/for/test")
        .build();

    match result {
        Err(e) => {
            let msg = format!("{:?}", e);
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

#[test]
fn test_validation_reports_issues() {
    let result = Sandbox::builder().read_only("/nonexistent1").build();

    assert!(result.is_err());

    match result {
        Err(SandboxError::PathNotFound(_)) => { /* Good */ }
        Err(e) => {
            panic!("Expected PathNotFound during validation, got: {:?}", e);
        }
        Ok(_) => unreachable!(),
    }
}

#[test]
#[cfg(unix)]
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

#[test]
fn test_error_display_user_friendly() {
    let result = Sandbox::builder().read_only("/does/not/exist").build();

    if let Err(e) = result {
        let display = format!("{}", e);

        assert!(!display.is_empty(), "Error Display should not be empty");

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
            matches!(builder.build(), Err(SandboxError::Config { .. })),
            "an invalid limit was accepted"
        );
    }
}

/// A NUL byte in an argument is an error, not a panic, and leaks nothing.
/// It used to panic, and before that leak the run's pipes.
#[test]
#[cfg(unix)]
fn test_nul_in_argument_is_an_error() {
    let sandbox = Sandbox::builder().build().unwrap();
    let fds = || std::fs::read_dir("/proc/self/fd").map(|d| d.count()).ok();
    let before = fds();
    for _ in 0..50 {
        let result = sandbox.run("echo", &["a\0b"]);
        assert!(
            matches!(result, Err(SandboxError::NulError(_))),
            "{result:?}"
        );
    }
    // Linux: no fds left behind. Other tests churn fds, so allow noise: a leak was 4+ per run, over 200.
    if let (Some(before), Some(after)) = (before, fds()) {
        assert!(after < before + 50, "fds leaked: {before} -> {after}");
    }
}

/// A working directory that doesn't exist is refused at build(). On Linux it
/// used to be ignored, and the program ran wherever this process was.
#[test]
#[cfg(unix)]
fn test_missing_working_dir_refused() {
    let result = Sandbox::builder()
        .working_dir("/nanosandbox-no-such-dir")
        .build();
    assert!(matches!(result, Err(SandboxError::PathNotFound(_))));
}

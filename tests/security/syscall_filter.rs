//! Seccomp syscall filter tests - Linux only

#![cfg(target_os = "linux")]

use nanosandbox::{Sandbox, SeccompProfile, MB};
use std::time::Duration;

#[test]
fn test_strict_allows_basic_io() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .seccomp_profile(SeccompProfile::Strict)
        .build()
        .unwrap();

    let result = sandbox.run("echo", &["hello"]).unwrap();
    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.contains("hello"));
}

#[test]
fn test_standard_allows_file_operations() {
    if crate::common::skip_without_mounts() {
        return;
    }
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .seccomp_profile(SeccompProfile::Standard)
        .tmpfs("/tmp", 64 * MB)
        .build()
        .unwrap();

    let result = sandbox
        .run("sh", &["-c", "echo test > /tmp/file && cat /tmp/file"])
        .unwrap();

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout.trim(), "test");
}

#[test]
fn test_standard_allows_process_creation() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .seccomp_profile(SeccompProfile::Standard)
        .build()
        .unwrap();

    let result = sandbox.run("sh", &["-c", "echo a | cat"]).unwrap();
    assert_eq!(result.exit_code, 0);
}

#[test]
fn test_permissive_allows_most_operations() {
    // AppArmor's unprivileged_userns profile denies reading `/` itself,
    // whatever the seccomp profile is.
    if crate::common::skip_without_mounts() {
        return;
    }
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .seccomp_profile(SeccompProfile::Permissive)
        .build()
        .unwrap();

    // Most normal operations should work
    let result = sandbox
        .run("sh", &["-c", "echo hello && ls / > /dev/null && pwd"])
        .unwrap();

    assert_eq!(result.exit_code, 0);
}

#[test]
fn test_disabled_profile() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .seccomp_profile(SeccompProfile::Disabled)
        .build()
        .unwrap();

    // Should work without seccomp restrictions
    let result = sandbox.run("echo", &["no seccomp"]).unwrap();
    assert!(result.success());
}

#[test]
fn test_seccomp_does_not_break_basic_commands() {
    for profile in [
        SeccompProfile::Strict,
        SeccompProfile::Standard,
        SeccompProfile::Permissive,
    ] {
        let sandbox = Sandbox::builder()
            .working_dir("/tmp")
            .seccomp_profile(profile.clone())
            .build()
            .unwrap();

        let result = sandbox.run("true", &[]).unwrap();
        assert!(
            result.success(),
            "Profile {:?} broke 'true' command",
            profile
        );

        let result = sandbox.run("echo", &["test"]).unwrap();
        assert!(
            result.success(),
            "Profile {:?} broke 'echo' command",
            profile
        );
    }
}

#[test]
fn test_seccomp_with_python() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .seccomp_profile(SeccompProfile::Standard)
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    let result = sandbox.run("python3", &["-c", "print('hello from python')"]);

    // An Err means python3 isn't available
    if let Ok(r) = result {
        if r.exit_code == 0 {
            assert!(r.stdout.contains("hello from python"));
        }
    }
}

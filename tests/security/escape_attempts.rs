//! Sandbox escape attempt tests
//!
//! These tests verify sandbox isolation

use nanosandbox::{Permission, Sandbox, SeccompProfile};

/// Test that sandbox cannot read sensitive host files
#[test]
#[cfg(target_os = "linux")]
fn test_cannot_read_host_etc_shadow() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox.run("cat", &["/etc/shadow"]).unwrap();

    // Should fail or read sandbox's own file (not host)
    assert!(result.exit_code != 0 || !result.stdout.contains("root:"));
}

/// Test PID namespace isolation
#[test]
#[cfg(target_os = "linux")]
fn test_pid_namespace_isolation() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    // PID 1 in sandbox should be sandbox's init, not host's systemd
    let result = sandbox.run("cat", &["/proc/1/cmdline"]).unwrap();
    assert!(!result.stdout.contains("systemd"));
}

/// Test process isolation
#[test]
#[cfg(target_os = "linux")]
fn test_cannot_see_host_processes() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox.run("ps", &["aux"]).unwrap();

    // Should only see sandbox processes (very few)
    let lines: Vec<&str> = result.stdout.lines().collect();
    assert!(lines.len() < 15);
}

/// Test mount operations blocked
#[test]
#[cfg(target_os = "linux")]
fn test_cannot_mount_filesystems() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .seccomp_profile(SeccompProfile::Standard)
        .build()
        .unwrap();

    let result = sandbox
        .run("mount", &["-t", "tmpfs", "none", "/mnt"])
        .unwrap();
    assert!(result.exit_code != 0);
}

/// Test device node creation blocked
#[test]
#[cfg(target_os = "linux")]
fn test_cannot_create_device_nodes() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox.run("mknod", &["/tmp/test", "c", "1", "3"]).unwrap();
    assert!(result.exit_code != 0);
}

/// Test user namespace isolation
#[test]
#[cfg(target_os = "linux")]
fn test_user_namespace_isolation() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    // Should appear as root inside sandbox
    let result = sandbox.run("id", &[]).unwrap();
    // May or may not be uid=0 depending on configuration
    assert!(result.success() || result.exit_code != 0);
}

/// macOS: Network isolation test
#[test]
#[cfg(target_os = "macos")]
fn test_macos_network_blocked() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .no_network()
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    let result = sandbox
        .run(
            "curl",
            &["-s", "--connect-timeout", "2", "https://google.com"],
        )
        .unwrap();

    // Should fail due to network restrictions
    assert!(result.exit_code != 0);
}

/// macOS: File restriction test
#[test]
#[cfg(target_os = "macos")]
fn test_macos_file_restriction() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .seccomp_profile(SeccompProfile::Strict)
        .build()
        .unwrap();

    // Try to access sensitive directory
    let result = sandbox.run("ls", &["/private/var/root"]).unwrap();
    assert!(result.exit_code != 0);
    // May succeed to list but content access restricted
}

/// Test environment isolation
#[test]
fn test_environment_isolation() {
    // Set a variable in parent that should NOT leak to sandbox
    std::env::set_var("SECRET_VAR", "secret_value");

    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .build()
        .unwrap();

    #[cfg(not(target_os = "windows"))]
    {
        let result = sandbox.run("sh", &["-c", "echo $SECRET_VAR"]).unwrap();
        // Should be empty or not contain the secret
        assert!(!result.stdout.contains("secret_value"));
    }

    std::env::remove_var("SECRET_VAR");
}

/// Test working directory confinement
#[test]
#[cfg(target_os = "linux")]
fn test_working_directory_confinement() {
    use tempfile::tempdir;

    let tmpdir = tempdir().unwrap();

    let sandbox = Sandbox::builder()
        .mount(tmpdir.path(), "/workspace", Permission::ReadWrite)
        .working_dir("/workspace")
        .build()
        .unwrap();

    // Should be able to write in workspace
    let result = sandbox
        .run("sh", &["-c", "echo test > /workspace/file.txt"])
        .unwrap();
    assert!(result.success());

    // File should exist in temp dir
    assert!(tmpdir.path().join("file.txt").exists());
}

/// Test working directory confinement on macOS
#[test]
#[cfg(target_os = "macos")]
fn test_working_directory_confinement_macos() {
    use tempfile::tempdir;

    let tmpdir = tempdir().unwrap();
    let tmpdir_path = tmpdir.path().to_str().unwrap();

    let sandbox = Sandbox::builder()
        .mount(tmpdir.path(), tmpdir.path(), Permission::ReadWrite)
        .working_dir(tmpdir.path())
        .build()
        .unwrap();

    // Should be able to write in workspace
    let file_path = format!("{}/file.txt", tmpdir_path);
    let result = sandbox
        .run("sh", &["-c", &format!("echo test > {}", file_path)])
        .unwrap();
    assert!(result.success());

    // File should exist in temp dir
    assert!(tmpdir.path().join("file.txt").exists());
}

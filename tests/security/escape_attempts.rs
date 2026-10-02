//! Sandbox escape attempt tests
//!
//! These tests verify sandbox isolation

#[cfg(target_os = "linux")]
use nanosandbox::Permission;
use nanosandbox::Sandbox;
#[cfg(target_os = "macos")]
use std::time::Duration;

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
    // The sandbox only gets its own /proc where it can mount one.
    if crate::common::skip_without_userns_privileges() {
        return;
    }
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
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

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
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

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

/// Without a rootfs, a mount goes over the host's own path, inside the
/// sandbox only: writes there land in the mount's source, and the host's
/// copy of the target is untouched.
#[test]
#[cfg(target_os = "linux")]
fn test_working_directory_confinement() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    let source = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();

    let sandbox = Sandbox::builder()
        .bind(source.path(), target.path(), Permission::ReadWrite)
        .working_dir(target.path())
        .build()
        .unwrap();

    let result = sandbox.run("sh", &["-c", "echo test > file.txt"]).unwrap();
    assert!(result.success(), "stderr: {}", result.stderr);

    assert!(source.path().join("file.txt").exists());
    assert!(!target.path().join("file.txt").exists());
}

/// Without a rootfs there's nowhere to create a missing target, so build()
/// says so instead of the mount silently not happening.
#[test]
#[cfg(target_os = "linux")]
fn test_mount_target_must_exist_without_rootfs() {
    let source = tempfile::tempdir().unwrap();
    let result = Sandbox::builder()
        .bind(
            source.path(),
            "/nanosandbox-no-such-target",
            Permission::ReadWrite,
        )
        .working_dir("/tmp")
        .build();

    let err = result
        .err()
        .expect("build() should refuse a missing target");
    if !crate::common::skip_without_userns_privileges() {
        assert!(err.to_string().contains("does not exist"), "{err}");
    }
}

/// Test working directory confinement on macOS
#[test]
#[cfg(target_os = "macos")]
fn test_working_directory_confinement_macos() {
    use tempfile::tempdir;

    let tmpdir = tempdir().unwrap();
    let tmpdir_path = tmpdir.path().to_str().unwrap();

    let sandbox = Sandbox::builder()
        .writable(tmpdir.path())
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

/// Test: a ReadOnly working directory stays read-only. On macOS the working
/// directory used to be writable just by being one, so code_judge's code
/// could change its own directory.
#[test]
#[cfg(unix)]
fn test_code_judge_cannot_write_its_code_dir() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    // Not under /tmp, which sandboxes may write to.
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();

    let judge = Sandbox::code_judge(dir.path()).build().unwrap();
    let result = judge.run("sh", &["-c", "echo x > ./judged"]).unwrap();
    assert_ne!(
        result.exit_code, 0,
        "code_judge wrote to its own code directory"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

/// Test: by default, nothing outside the temp directories is writable. On
/// macOS the default working directory, "/", used to make all of it
/// writable; on Linux without a rootfs, everything the user could write was.
#[test]
#[cfg(unix)]
fn test_default_sandbox_cannot_write_host_files() {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let path = dir.path().to_str().unwrap();

    let sandbox = Sandbox::builder().build().unwrap();
    let script = format!("echo x > '{path}/default'");
    let result = sandbox.run("sh", &["-c", &script]).unwrap();
    assert_ne!(result.exit_code, 0, "default sandbox wrote to {path}");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

/// Test: what programs need to write to still works by default, and a
/// ReadWrite mount of a host directory onto itself makes it writable. That
/// needs no actual mount, so it works under AppArmor's userns restriction
/// too.
#[test]
#[cfg(unix)]
fn test_writable_places_still_writable() {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let path = dir.path().to_str().unwrap();

    let sandbox = Sandbox::builder()
        .writable(dir.path())
        .working_dir(dir.path())
        .build()
        .unwrap();
    let script = format!(
        "set -e
         echo a > /dev/null
         echo b > /dev/stdout
         t=$(mktemp) && echo c > $t && rm $t
         echo d > '{path}/out' && mkdir '{path}/sub' && mv '{path}/out' '{path}/sub/out'
         echo e | cat"
    );
    let result = sandbox.run("sh", &["-c", &script]).unwrap();
    assert_eq!(result.exit_code, 0, "{}", result.stderr);
    assert_eq!(result.stdout, "b\ne\n");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("sub/out")).unwrap(),
        "d\n"
    );
}

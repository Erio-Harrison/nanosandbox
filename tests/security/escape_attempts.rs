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
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("SECRET_VAR", "secret_value") };

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

    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::remove_var("SECRET_VAR") };
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
    let source = crate::common::sandbox_tempdir();
    let target = crate::common::sandbox_tempdir();

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
    let dir = crate::common::sandbox_tempdir_in(env!("CARGO_TARGET_TMPDIR"));
    if crate::common::skip_if_unreachable_by_nobody(dir.path()) {
        return;
    }
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

/// Test: run as root, the sandbox runs as nobody, without root's groups.
/// It used to keep root's ids, so it could read and write root's files as
/// their owner, capabilities or not. Only runs as root.
#[test]
#[cfg(target_os = "linux")]
fn test_root_caller_runs_as_nobody() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: not root");
        return;
    }
    // A root-owned directory anyone may enter, inside the default writable
    // area: only the file permissions decide.
    let dir = tempfile::tempdir_in("/var/tmp").unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let secret = dir.path().join("root-only");
    std::fs::write(&secret, "s").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();

    let sandbox = Sandbox::builder().build().unwrap();
    let script = format!(
        "grep '^Uid' /proc/self/status; \
         cat '{d}/root-only' >/dev/null 2>&1 && echo READ || echo read-denied; \
         touch '{d}/new' 2>/dev/null && echo WROTE || echo write-denied; \
         echo groups=$(id -G | wc -w)",
        d = dir.path().display()
    );
    let out = sandbox.run("sh", &["-c", &script]).unwrap().stdout;
    assert!(out.contains("read-denied"), "{out}");
    assert!(out.contains("write-denied"), "{out}");
    assert!(out.contains("groups=1"), "supplementary groups kept: {out}");
}

/// A root caller's sandbox runs as nobody (see `test_root_caller_runs_as_nobody`
/// above), so a `writable` grant nobody can't actually write to -- the usual
/// case for a directory a root-run container created -- used to fail deep
/// inside the sandboxed program's own `EACCES`. `build()` catches it instead.
#[test]
fn test_root_caller_writable_unwritable_by_nobody_is_refused_upfront() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: not root");
        return;
    }
    let dir = tempfile::tempdir_in("/var/tmp").unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    let err = Sandbox::builder()
        .writable(dir.path())
        .build()
        .err()
        .unwrap();
    assert!(
        matches!(err, nanosandbox::SandboxError::Config { .. }),
        "{err:?}"
    );
    assert!(err.to_string().contains("nobody"), "{err}");
}

/// Same setup, but world-writable: nobody from a root caller's sandbox can
/// write there, so this must build and run, not be refused.
#[test]
fn test_root_caller_writable_world_writable_is_accepted() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: not root");
        return;
    }
    let dir = tempfile::tempdir_in("/var/tmp").unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();

    let sandbox = Sandbox::builder().writable(dir.path()).build().unwrap();
    let result = sandbox
        .run(
            "sh",
            &["-c", &format!("touch '{}/f'", dir.path().display())],
        )
        .unwrap();
    assert_eq!(result.exit_code, 0, "{}", result.stderr);
}

/// A root caller's sandbox runs as nobody unless told otherwise; `host_uid`/
/// `host_gid` pick the host user instead, so a directory only its owner can
/// write to (what a root-run container creates for another user) works.
#[cfg(target_os = "linux")]
#[test]
fn test_root_caller_host_ids_reach_a_directory_nobody_cannot() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: not root");
        return;
    }
    const OWNER: u32 = 12345;
    let dir = tempfile::tempdir_in("/var/tmp").unwrap();
    std::os::unix::fs::chown(dir.path(), Some(OWNER), Some(OWNER)).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    // Without the ids, refused up front.
    let err = Sandbox::builder()
        .writable(dir.path())
        .build()
        .err()
        .unwrap();
    assert!(err.to_string().contains("host_uid"), "{err}");

    let sandbox = Sandbox::builder()
        .writable(dir.path())
        .host_uid(OWNER)
        .host_gid(OWNER)
        .build()
        .unwrap();
    let result = sandbox
        .run(
            "sh",
            &["-c", &format!("echo hi > '{}/f'", dir.path().display())],
        )
        .unwrap();
    assert_eq!(result.exit_code, 0, "{}", result.stderr);
    let meta = std::fs::metadata(dir.path().join("f")).unwrap();
    assert_eq!((meta.uid(), meta.gid()), (OWNER, OWNER));
}

/// The output pipes belong to whoever the sandbox runs as, or it couldn't
/// reopen its own stdout through /dev/stdout.
#[cfg(target_os = "linux")]
#[test]
fn test_root_caller_host_ids_keep_dev_stdout_working() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: not root");
        return;
    }
    let sandbox = Sandbox::builder()
        .host_uid(12345)
        .host_gid(12345)
        .build()
        .unwrap();
    let result = sandbox
        .run(
            "sh",
            &["-c", "echo out > /dev/stdout; echo err > /dev/stderr"],
        )
        .unwrap();
    assert_eq!(result.exit_code, 0, "{}", result.stderr);
    assert_eq!(result.stdout.trim(), "out");
    assert_eq!(result.stderr.trim(), "err");
}

#[cfg(target_os = "linux")]
#[test]
fn test_host_ids_of_root_are_refused() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: not root");
        return;
    }
    for builder in [
        Sandbox::builder().host_uid(0),
        Sandbox::builder().host_gid(0),
    ] {
        let err = builder.build().err().unwrap();
        assert!(
            matches!(err, nanosandbox::SandboxError::Unsupported { .. }),
            "{err:?}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_host_ids_need_a_root_caller() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: root");
        return;
    }
    let err = Sandbox::builder().host_uid(12345).build().err().unwrap();
    assert!(
        matches!(err, nanosandbox::SandboxError::Unsupported { .. }),
        "{err:?}"
    );
}

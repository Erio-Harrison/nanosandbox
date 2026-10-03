//! Custom rootfs tests (Linux): mounts, tmpfs and pivot_root.

use crate::common::skip_without_userns_privileges;
use nanosandbox::{Permission, Sandbox};
use std::path::Path;

/// A rootfs that borrows the host's /usr, read-only.
fn minimal_rootfs(root: &Path) -> nanosandbox::SandboxBuilder {
    for link in ["bin", "lib", "lib64", "sbin"] {
        if Path::new("/").join(link).exists() {
            std::os::unix::fs::symlink(format!("usr/{link}"), root.join(link)).unwrap();
        }
    }
    Sandbox::builder()
        .rootfs(root)
        .bind("/usr", "/usr", Permission::ReadOnly)
        .working_dir("/")
}

#[test]
fn test_readonly_mount_rejects_writes() {
    if skip_without_userns_privileges() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let sandbox = minimal_rootfs(root.path())
        .bind(data.path(), "/data", Permission::ReadOnly)
        .build()
        .unwrap();

    let result = sandbox
        .run("/bin/sh", &["-c", "echo pwned > /data/x"])
        .unwrap();

    assert_ne!(result.exit_code, 0, "write to a ReadOnly mount succeeded");
    assert!(
        !data.path().join("x").exists(),
        "write landed on the host directory"
    );
}

#[test]
fn test_readwrite_mount_and_tmpfs() {
    if skip_without_userns_privileges() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let sandbox = minimal_rootfs(root.path())
        .bind(data.path(), "/data", Permission::ReadWrite)
        .tmpfs("/scratch", 16 * 1024 * 1024)
        .build()
        .unwrap();

    let result = sandbox
        .run(
            "/bin/sh",
            &["-c", "echo hi > /scratch/f && cat /scratch/f > /data/out"],
        )
        .unwrap();

    assert!(result.success(), "stderr: {}", result.stderr);
    assert_eq!(
        std::fs::read_to_string(data.path().join("out")).unwrap(),
        "hi\n"
    );
}

/// A tmpfs nested inside a bind's target (no rootfs): the bind, being the
/// shallower mount, has to land first, or the tmpfs mounted at the literal
/// host path gets shadowed once the bind covers it. Mounting tmpfs before
/// all binds unconditionally (instead of by depth) broke exactly this.
#[test]
fn test_tmpfs_nested_inside_a_bind_target() {
    if skip_without_userns_privileges() {
        return;
    }
    // Not under /tmp, which private_tmp (on by default) covers with its
    // own tmpfs.
    let source = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    std::fs::create_dir(source.path().join("scratch")).unwrap();
    std::fs::write(source.path().join("scratch/sentinel"), "from source").unwrap();
    std::fs::write(source.path().join("other"), "from source").unwrap();

    let target = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    // Must exist on the host already: check_mounts requires every tmpfs
    // target to, the same as a bind target.
    std::fs::create_dir(target.path().join("scratch")).unwrap();

    let sandbox = Sandbox::builder()
        .bind(source.path(), target.path(), Permission::ReadOnly)
        .tmpfs(target.path().join("scratch"), 16 * 1024 * 1024)
        .working_dir(target.path())
        .build()
        .unwrap();

    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                "cat other; \
                 echo -n ' scratch:'; cat scratch/sentinel 2>&1; \
                 echo -n ' write:'; (echo hi > scratch/f && echo ok) 2>&1",
            ],
        )
        .unwrap();
    assert!(result.success(), "stderr: {}", result.stderr);
    assert!(
        result.stdout.starts_with("from source"),
        "{}",
        result.stdout
    );
    // The tmpfs, not the bind's own scratch/sentinel, is what's there.
    assert!(
        result.stdout.contains("scratch:cat:") || result.stdout.contains("No such file"),
        "the bind's scratch content was still visible: {}",
        result.stdout
    );
    assert!(result.stdout.contains("write:ok"), "{}", result.stdout);
}

/// Every sandbox used to pivot_root through one shared `<rootfs>/old_root`
/// directory, so concurrent runs on the same rootfs failed setup.
#[test]
fn test_concurrent_sandboxes_share_rootfs() {
    if skip_without_userns_privileges() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    minimal_rootfs(root.path());
    let root = std::sync::Arc::new(root);

    let handles: Vec<_> = (0..16)
        .map(|i| {
            let root = root.clone();
            std::thread::spawn(move || {
                for _ in 0..5 {
                    let sandbox = Sandbox::builder()
                        .rootfs(root.path())
                        .bind("/usr", "/usr", Permission::ReadOnly)
                        .working_dir("/")
                        .env("ID", i.to_string())
                        .build()
                        .unwrap();
                    let result = sandbox.run("/bin/sh", &["-c", "echo $ID"]).unwrap();
                    assert_eq!(
                        result.stdout.trim(),
                        i.to_string(),
                        "stderr: {}",
                        result.stderr
                    );
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
}

/// Commands are looked up in the rootfs, not on the host. They used to be
/// resolved against the host's PATH first: a command only the rootfs had
/// wasn't found, and one only the host had was run from the rootfs's path.
#[test]
fn test_path_lookup_happens_in_the_rootfs() {
    if skip_without_userns_privileges() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("opt/tools")).unwrap();
    let tool = root.path().join("opt/tools/only-in-rootfs");
    std::fs::write(&tool, "#!/bin/sh\necho from-rootfs\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();

    let sandbox = minimal_rootfs(root.path())
        .env("PATH", "/opt/tools:/usr/bin:/bin")
        .build()
        .unwrap();
    let result = sandbox.run("only-in-rootfs", &[]).unwrap();
    assert_eq!(result.stdout, "from-rootfs\n", "{}", result.stderr);

    // On the host's PATH, not in the rootfs.
    let result = sandbox.run("cargo", &["--version"]).unwrap();
    assert_eq!(result.exit_code, 127, "{}", result.stdout);
}

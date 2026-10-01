//! Custom rootfs tests (Linux): mounts, tmpfs and pivot_root.

use nanosandbox::{Permission, Sandbox};
use std::path::Path;

/// Ubuntu 23.10+ confines a fresh unprivileged user namespace to AppArmor's
/// `unprivileged_userns` profile, which denies the mounts a rootfs needs.
/// There is nothing to test there, so say so instead of failing.
fn rootfs_unsupported() -> bool {
    let restricted =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
    if restricted && unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "skipping: kernel.apparmor_restrict_unprivileged_userns=1 denies unprivileged mounts"
        );
        return true;
    }
    false
}

/// A rootfs that borrows the host's /usr, read-only.
fn minimal_rootfs(root: &Path) -> nanosandbox::SandboxBuilder {
    for link in ["bin", "lib", "lib64", "sbin"] {
        if Path::new("/").join(link).exists() {
            std::os::unix::fs::symlink(format!("usr/{link}"), root.join(link)).unwrap();
        }
    }
    Sandbox::builder()
        .rootfs(root)
        .mount("/usr", "/usr", Permission::ReadOnly)
        .working_dir("/")
}

#[test]
fn test_readonly_mount_rejects_writes() {
    if rootfs_unsupported() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let sandbox = minimal_rootfs(root.path())
        .mount(data.path(), "/data", Permission::ReadOnly)
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
    if rootfs_unsupported() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let sandbox = minimal_rootfs(root.path())
        .mount(data.path(), "/data", Permission::ReadWrite)
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

/// Every sandbox used to pivot_root through one shared `<rootfs>/old_root`
/// directory, so concurrent runs on the same rootfs failed setup.
#[test]
fn test_concurrent_sandboxes_share_rootfs() {
    if rootfs_unsupported() {
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
                        .mount("/usr", "/usr", Permission::ReadOnly)
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

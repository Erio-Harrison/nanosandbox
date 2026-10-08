//! `/var/tmp` and `/dev/shm` are in landlock's `DEFAULT_WRITABLE`
//! unconditionally (not tied to `private_tmp`), so without their own
//! private tmpfs they're the host's real, shared, persistent paths --
//! writable by every sandbox and the host alike. See `MountPlan::tmpfs_mounts`.

#![cfg(target_os = "linux")]

use nanosandbox::Sandbox;
use std::time::Duration;

fn sandbox() -> Sandbox {
    Sandbox::builder()
        .working_dir("/")
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap()
}

/// A file left in /var/tmp or /dev/shm isn't visible to another sandbox, or
/// to the host, and isn't there on the next run either.
#[test]
fn test_var_tmp_and_dev_shm_are_private_per_run() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    for path in ["/var/tmp", "/dev/shm"] {
        let marker = format!("nsb-shared-tmp-probe-{}", std::process::id());
        let first = sandbox();
        let out = first
            .run(
                "sh",
                &[
                    "-c",
                    &format!("echo secret > {path}/{marker} && echo wrote"),
                ],
            )
            .unwrap();
        assert!(out.stdout.contains("wrote"), "{path}: {out:?}");

        // Not visible from a second, independent sandbox...
        let second = sandbox();
        let check = second
            .run(
                "sh",
                &[
                    "-c",
                    &format!("cat {path}/{marker} 2>/dev/null || echo missing"),
                ],
            )
            .unwrap();
        assert_eq!(
            check.stdout.trim(),
            "missing",
            "{path}: a second sandbox saw the first one's file"
        );

        // ...and not on the real host path either.
        assert!(
            !std::path::Path::new(path).join(&marker).exists(),
            "{path}/{marker} leaked onto the host"
        );
    }
}

/// An explicit `writable()`/`bind()` naming `/var/tmp` or `/dev/shm`
/// overrides the private default: the caller asked for the real, shared one.
#[test]
fn test_explicit_writable_grant_overrides_the_private_default() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    for path in ["/var/tmp", "/dev/shm"] {
        let marker = format!("nsb-shared-tmp-explicit-{}", std::process::id());
        let sandbox = Sandbox::builder()
            .working_dir("/")
            .writable(path)
            .wall_time_limit(Duration::from_secs(10))
            .build()
            .unwrap();
        let out = sandbox
            .run(
                "sh",
                &[
                    "-c",
                    &format!("echo secret > {path}/{marker} && echo wrote"),
                ],
            )
            .unwrap();
        assert!(out.stdout.contains("wrote"), "{path}: {out:?}");

        let host_path = std::path::Path::new(path).join(&marker);
        assert!(
            host_path.exists(),
            "{path}: explicit writable() should reach the real host path"
        );
        let _ = std::fs::remove_file(&host_path);
    }
}

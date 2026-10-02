//! tmpfs("/tmp", size) gives each run a private, size-limited /tmp that's
//! gone afterwards: a real tmpfs on Linux where mounting works, a private
//! directory that TMPDIR points to elsewhere (macOS, and Linux under
//! AppArmor's userns restriction). Programs here find it as
//! `${TMPDIR:-/tmp}`, which covers both.

use nanosandbox::{Sandbox, MB};
use std::time::Duration;

fn sandbox(size: u64) -> Sandbox {
    Sandbox::builder()
        .working_dir("/")
        .tmpfs("/tmp", size)
        .wall_time_limit(Duration::from_secs(20))
        .build()
        .unwrap()
}

/// A file one run leaves in its /tmp isn't there for the next run, nor on
/// the host afterwards.
#[test]
#[cfg(unix)]
fn test_private_tmp_is_per_run_and_removed() {
    let sandbox = sandbox(16 * MB);
    let name = format!("nsb-private-tmp-{}", std::process::id());

    let script = format!("f=\"${{TMPDIR:-/tmp}}/{name}\"; echo secret > \"$f\" && echo \"$f\"");
    let first = sandbox.run("sh", &["-c", &script]).unwrap();
    assert_eq!(first.exit_code, 0, "{}", first.stderr);
    let path = first.stdout.trim().to_string();
    assert!(
        !std::path::Path::new(&path).exists(),
        "{path} outlived the run"
    );

    let script = format!("cat \"${{TMPDIR:-/tmp}}/{name}\" 2>/dev/null || echo missing");
    let second = sandbox.run("sh", &["-c", &script]).unwrap();
    assert_eq!(second.stdout.trim(), "missing", "the next run saw it");
}

/// Writing more than the size fails the run: with ENOSPC on a real tmpfs,
/// by being killed where it's emulated.
#[test]
#[cfg(unix)]
fn test_private_tmp_size_is_limited() {
    let sandbox = sandbox(MB);
    let script = "dd if=/dev/zero of=\"${TMPDIR:-/tmp}/big\" bs=1048576 count=8 2>/dev/null \
                  || exit 3; sleep 3";
    let result = sandbox.run("sh", &["-c", script]).unwrap();
    assert!(!result.success(), "8MB fit in a 1MB /tmp: {result:?}");
    assert!(
        result.exit_code == 3 || result.killed_by_tmp_limit,
        "{result:?}"
    );
    assert!(!result.killed_by_timeout);
}

/// Only /tmp can be emulated: there's no putting a private directory at
/// another path without a mount namespace.
#[test]
#[cfg(target_os = "macos")]
fn test_tmpfs_elsewhere_refused_on_macos() {
    let err = Sandbox::builder()
        .tmpfs("/var/tmp", MB)
        .build()
        .err()
        .expect("tmpfs at /var/tmp was accepted");
    assert!(err.to_string().contains("tmpfs"), "{err}");
}

//! private_tmp(size), on by default, gives each run a private, size-limited
//! temp directory that's gone afterwards: a tmpfs at /tmp on Linux where
//! mounting works, a private directory elsewhere (macOS, and Linux under
//! AppArmor's userns restriction). Programs find it through $TMPDIR.

use nanosandbox::{Sandbox, MB};
use std::time::Duration;

fn sandbox(size: u64) -> Sandbox {
    Sandbox::builder()
        .working_dir("/")
        .private_tmp(size)
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

    let script = format!("f=\"${{TMPDIR}}/{name}\"; echo secret > \"$f\" && echo \"$f\"");
    let first = sandbox.run("sh", &["-c", &script]).unwrap();
    assert_eq!(first.exit_code, 0, "{}", first.stderr);
    let path = first.stdout.trim().to_string();
    assert!(
        !std::path::Path::new(&path).exists(),
        "{path} outlived the run"
    );

    let script = format!("cat \"${{TMPDIR}}/{name}\" 2>/dev/null || echo missing");
    let second = sandbox.run("sh", &["-c", &script]).unwrap();
    assert_eq!(second.stdout.trim(), "missing", "the next run saw it");
}

/// Writing more than the size fails the run: with ENOSPC on a real tmpfs,
/// by being killed where it's emulated.
#[test]
#[cfg(unix)]
fn test_private_tmp_size_is_limited() {
    let sandbox = sandbox(MB);
    let script = "dd if=/dev/zero of=\"${TMPDIR}/big\" bs=1048576 count=8 2>/dev/null \
                  || exit 3; sleep 3";
    let result = sandbox.run("sh", &["-c", script]).unwrap();
    assert!(!result.success(), "8MB fit in a 1MB /tmp: {result:?}");
    assert!(
        result.exit_code == 3 || result.killed_by_tmp_limit,
        "{result:?}"
    );
    assert!(!result.killed_by_timeout);
}

/// On by default, and TMPDIR always points to it.
#[test]
#[cfg(unix)]
fn test_private_tmp_on_by_default() {
    let sandbox = Sandbox::builder().build().unwrap();
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                "test -n \"$TMPDIR\" && touch \"$TMPDIR/x\" && echo ok",
            ],
        )
        .unwrap();
    assert_eq!(result.stdout.trim(), "ok", "{}", result.stderr);
}

/// Without it, there's no TMPDIR, and no private directory.
#[test]
#[cfg(unix)]
fn test_no_private_tmp() {
    let sandbox = Sandbox::builder().no_private_tmp().build().unwrap();
    let result = sandbox.run("sh", &["-c", "echo \"[$TMPDIR]\""]).unwrap();
    assert_eq!(result.stdout.trim(), "[]");
}

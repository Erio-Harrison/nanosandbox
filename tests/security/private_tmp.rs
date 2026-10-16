//! private_tmp(size), on by default, gives each run a private, size-limited temp dir that's gone afterwards:
//! a tmpfs at /tmp on Linux where mounting works, a private directory elsewhere. Found via $TMPDIR.

use nanosandbox::{MB, Sandbox};
use std::time::Duration;

fn sandbox(size: u64) -> Sandbox {
    Sandbox::builder()
        .working_dir("/")
        .private_tmp(size)
        .wall_time_limit(Duration::from_secs(20))
        .build()
        .unwrap()
}

/// A file left in a run's /tmp isn't there for the next run or on the host.
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

/// Writing past the size fails the run: ENOSPC on a real tmpfs, a kill where emulated.
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

/// One run can't read, list into, write, remove or rename another's private dir (which, where not
/// a tmpfs, used to sit in the world-writable temp directory).
#[test]
#[cfg(unix)]
fn test_a_run_cannot_reach_another_runs_private_tmp() {
    use std::sync::mpsc;
    let a = sandbox(16 * MB);
    let (tx, rx) = mpsc::channel();
    let victim = std::thread::spawn(move || {
        // Writes a secret, keeps running so its directory stays, then checks the secret is unchanged.
        let out = a
            .run(
                "sh",
                &[
                    "-c",
                    "echo secret > \"$TMPDIR/s.txt\"; echo \"$TMPDIR\" > /dev/stderr; \
                     i=0; while [ $i -lt 60 ] && [ ! -e \"$TMPDIR/go\" ]; do sleep 0.1; i=$((i+1)); done; \
                     cat \"$TMPDIR/s.txt\"; ls \"$TMPDIR\" | sort | tr '\\n' ' '",
                ],
            )
            .unwrap();
        let _ = tx.send(());
        out
    });
    // The victim's $TMPDIR, read from the host: its directory appears under the container.
    let container = {
        let t = std::env::temp_dir();
        let t = t.canonicalize().unwrap_or(t);
        if cfg!(target_os = "macos") {
            t.join("nanosandbox-tmp")
        } else if let Some(r) = std::env::var_os("XDG_RUNTIME_DIR") {
            std::path::PathBuf::from(r).join("nanosandbox-tmp")
        } else {
            std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
                .join(".cache")
                .join("nanosandbox-tmp")
        }
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let a_dir = loop {
        let found = std::fs::read_dir(&container).ok().and_then(|d| {
            d.flatten()
                .map(|e| e.path())
                .find(|p| p.join("s.txt").exists())
        });
        if let Some(p) = found {
            break p;
        }
        if std::time::Instant::now() > deadline {
            // A tmpfs: nothing on the host, invisible to other sandboxes.
            let _ = std::fs::write(container.join("go"), "");
            eprintln!("skipping: the private directory is not a directory on the host");
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let b = sandbox(16 * MB);
    let d = a_dir.display();
    let out = b
        .run(
            "sh",
            &[
                "-c",
                &format!(
                    "cat {d}/s.txt 2>&1; echo cat=$?; ls {d} 2>&1 | head -3; echo ls=$?; \
                     echo EVIL > {d}/s.txt 2>&1; echo write=$?; echo x > {d}/planted 2>&1; echo plant=$?; \
                     rm -rf {d} 2>&1; echo rm=$?; mv {d} {d}.x 2>&1; echo mv=$?; \
                     echo ok > \"$TMPDIR/mine\"; echo own=$?"
                ),
            ],
        )
        .unwrap();
    let _ = std::fs::write(a_dir.join("go"), "");
    let _ = rx.recv_timeout(Duration::from_secs(10));
    let a_out = victim.join().unwrap();
    assert!(
        !out.stdout.contains("secret"),
        "read another run's file: {out:?}"
    );
    for ok in ["write=0", "plant=0", "rm=0", "mv=0"] {
        assert!(!out.stdout.contains(ok), "{ok}: {out:?}");
    }
    assert!(
        out.stdout.contains("own=0"),
        "its own directory must work: {out:?}"
    );
    assert!(
        a_out.stdout.starts_with("secret\n"),
        "the victim's file was changed: {a_out:?}"
    );
    assert!(
        !a_out.stdout.contains("planted"),
        "a file was planted in the victim's dir: {a_out:?}"
    );
}

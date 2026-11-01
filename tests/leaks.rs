//! Soak: many runs ending in every way a run can end, then the host's own books are compared
//! with what they were before: open descriptors, threads, child processes, and the temp
//! directories and markers the library keeps. Its own test binary, so no other test's runs
//! or descriptors are counted. `NANOSANDBOX_SOAK_ROUNDS` sets how many rounds.

#![cfg(unix)]

use nanosandbox::Sandbox;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// Marks this test's own long sleeps, so a survivor can be found by its command line.
const SLEEP_SECS: &str = "4242";

fn rounds() -> usize {
    std::env::var("NANOSANDBOX_SOAK_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6)
}

fn open_fds() -> usize {
    let dir = if Path::new("/proc/self/fd").exists() {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
}

fn threads() -> usize {
    if let Ok(tasks) = std::fs::read_dir("/proc/self/task") {
        return tasks.count();
    }
    let out = Command::new("ps")
        .args(["-M", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .count()
        .saturating_sub(1)
}

fn pgrep(args: &[&str]) -> Vec<String> {
    let out = Command::new("pgrep").args(args).output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(String::from)
        .collect()
}

/// Everything the library keeps on disk, wherever it puts it.
fn library_files() -> BTreeSet<PathBuf> {
    fn walk(dir: &Path, depth: usize, inside: bool, out: &mut BTreeSet<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let ours = inside
                || path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().contains("nanosandbox"));
            if ours {
                out.insert(path.clone());
            }
            if depth > 0 && path.is_dir() && !path.is_symlink() {
                walk(&path, depth - 1, ours, out);
            }
        }
    }
    let uid = unsafe { libc::geteuid() };
    let mut roots = vec![
        std::env::temp_dir(),
        PathBuf::from(format!("/run/user/{uid}")),
    ];
    if let Ok(home) = std::env::var("HOME") {
        roots.push(PathBuf::from(home).join(".cache"));
    }
    let mut out = BTreeSet::new();
    for root in roots {
        walk(&root, 3, false, &mut out);
    }
    out
}

fn sandbox() -> Sandbox {
    Sandbox::builder().working_dir("/tmp").build().unwrap()
}

/// One of each way a run ends. Errors are fine (a host may not support one of these): what
/// is checked is what they leave behind.
fn round(n: usize) -> [bool; 4] {
    let sleep = format!("sleep {SLEEP_SECS}");

    let ran = sandbox().run("true", &[]).is_ok_and(|r| r.exit_code == 0);
    let _ = sandbox().run("sh", &["-c", "echo out; echo err >&2; exit 3"]);

    // Output far over the cap.
    let _ = Sandbox::builder()
        .working_dir("/tmp")
        .max_output(10_000)
        .build()
        .unwrap()
        .run(
            "sh",
            &["-c", "yes | head -c 3000000; yes | head -c 3000000 >&2"],
        );

    // Wall limit, with grandchildren that must die with it.
    let timed_out = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_millis(300))
        .build()
        .unwrap()
        .run("sh", &["-c", &format!("{sleep} & {sleep} & wait")])
        .is_ok_and(|r| r.killed_by_timeout);

    // CPU limit.
    let cpu_limited = Sandbox::builder()
        .working_dir("/tmp")
        .cpu_time_limit(Duration::from_millis(300))
        .wall_time_limit(Duration::from_secs(20))
        .build()
        .unwrap()
        .run("sh", &["-c", "while :; do :; done"])
        .is_ok_and(|r| r.killed_by_cpu_limit || r.signal == Some(libc::SIGXCPU));
    // (macOS has only the per-process rlimit, which ends it with SIGXCPU.)

    // Private temp over its limit.
    let tmp_limited = Sandbox::builder()
        .working_dir("/tmp")
        .private_tmp(64 << 10)
        .wall_time_limit(Duration::from_secs(20))
        .build()
        .unwrap()
        .run(
            "sh",
            &[
                "-c",
                "head -c 4000000 /dev/zero > \"$TMPDIR/big\" || exit 7; sleep 5",
            ],
        )
        .is_ok_and(|r| r.killed_by_tmp_limit || r.exit_code == 7);
    // (A tmpfs refuses the write itself; a directory is watched and the run killed.)

    // Private temp, a directory the command can't list left behind.
    let _ = Sandbox::builder()
        .working_dir("/tmp")
        .private_tmp(1 << 20)
        .build()
        .unwrap()
        .run(
            "sh",
            &[
                "-c",
                "mkdir \"$TMPDIR/d\" && touch \"$TMPDIR/d/f\" && chmod 000 \"$TMPDIR/d\"",
            ],
        );

    // Stdin fed to a command that has already gone.
    let _ = sandbox().run_with_input("true", &[], Some(&vec![b'x'; 2 << 20]));

    // spawn, then kill; spawn, then drop; spawn with the streams dropped first.
    if let Ok(mut child) = sandbox().spawn("sh", &["-c", &sleep]) {
        let _ = child.kill();
        let _ = child.wait();
    }
    drop(sandbox().spawn("sh", &["-c", &format!("{sleep} & {sleep} & wait")]));
    if let Ok(mut child) = sandbox().spawn("sh", &["-c", "yes"]) {
        drop(child.stdout.take());
        drop(child.stdin.take());
        let _ = child.kill();
        let _ = child.wait();
    }
    if let Ok(mut child) = sandbox().spawn("cat", &[]) {
        drop(child.stdin.take());
        let _ = child.wait();
    }
    if let Ok(child) = sandbox().spawn_pty("sh", &["-c", &sleep], 24, 80) {
        drop(child);
    }

    // The proxy: a listener, its tasks, a refused request, a run killed with a tunnel open.
    // (Refused to build where the host can't give the run its own network.)
    if let Ok(proxied) = Sandbox::builder()
        .working_dir("/tmp")
        .allow_network(&["example.invalid"])
        .wall_time_limit(Duration::from_secs(20))
        .build()
    {
        let _ = proxied.run("true", &[]);
        let _ = proxied.run(
            "sh",
            &[
                "-c",
                "(exec 3<>/dev/tcp/127.0.0.1/1; true) 2>/dev/null; true",
            ],
        );
        if let Ok(mut child) = proxied.spawn("sh", &["-c", &sleep]) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    // Built and never run.
    drop(sandbox());
    let _ = n;
    [ran, timed_out, cpu_limited, tmp_limited]
}

/// What is left of everything started so far.
fn settle() {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let children = pgrep(&["-P", &std::process::id().to_string()]);
        let sleepers = pgrep(&["-f", &format!("sleep {SLEEP_SECS}")]);
        if (children.is_empty() && sleepers.is_empty()) || Instant::now() > deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn test_many_runs_leave_no_descriptor_thread_process_or_file_behind() {
    // The first rounds start whatever is started once and kept (a runtime, a sweeper).
    for n in 0..2 {
        // Each way of ending has to really happen, or the books below prove nothing.
        assert_eq!(round(n), [true; 4], "ran, timed out, cpu limit, tmp limit");
    }
    settle();
    std::thread::sleep(Duration::from_secs(1));
    let (fds, threads_before, files) = (open_fds(), threads(), library_files());

    for n in 0..rounds() {
        round(n);
    }
    settle();
    std::thread::sleep(Duration::from_secs(1));

    let children = pgrep(&["-P", &std::process::id().to_string()]);
    let sleepers = pgrep(&["-f", &format!("sleep {SLEEP_SECS}")]);
    assert!(children.is_empty(), "child processes left: {children:?}");
    assert!(
        sleepers.is_empty(),
        "a command's grandchildren survived: {sleepers:?}"
    );

    let after = library_files();
    let left: Vec<_> = after.difference(&files).collect();
    assert!(left.is_empty(), "files left behind: {left:?}");

    assert_eq!(open_fds(), fds, "descriptors leaked");
    let threads_after = threads();
    assert!(
        threads_after <= threads_before + 1,
        "threads: {threads_before} before, {threads_after} after"
    );
}

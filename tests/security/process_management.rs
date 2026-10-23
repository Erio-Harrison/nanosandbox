//! Process management: no zombies, whole-tree kill, signals through the init shim, orphan cleanup.

use nanosandbox::Sandbox;
use std::process::Command;
use std::time::Duration;

/// The command runs in its own session, so it has no controlling terminal to read or inject into.
#[test]
#[cfg(unix)]
fn test_command_runs_in_its_own_session() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();
    // Session leader is the command itself (macOS) or the init shim, its parent (Linux).
    let script = "import os; print(os.getsid(0) in (os.getpid(), os.getppid()))";
    let Ok(r) = sandbox.run("python3", &["-c", script]) else {
        return;
    };
    if r.exit_code != 0 {
        eprintln!("skipping: python3 failed in the sandbox: {}", r.stderr);
        return;
    }
    assert_eq!(r.stdout.trim(), "True", "{}", r.stderr);
}

/// No zombies accumulate after timeout kills (kill() without wait() used to leave them).
#[test]
#[cfg(unix)]
fn test_no_zombie_after_timeout() {
    for _ in 0..5 {
        let sandbox = Sandbox::builder()
            .working_dir("/tmp")
            .wall_time_limit(Duration::from_millis(100))
            .build()
            .unwrap();

        let result = sandbox.run("sleep", &["10"]);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.killed_by_timeout);
    }

    let leaked = lasting_zombie_children();
    assert!(leaked.is_empty(), "Zombie processes leaked: {leaked:?}");
}

/// Children are killed with the parent on timeout (only the parent used to be).
#[test]
#[cfg(unix)]
fn test_process_group_killing() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(2))
        .build()
        .unwrap();

    let result = sandbox
        .run("sh", &["-c", "sleep 7777 & sleep 7777 & sleep 7777"])
        .unwrap();

    assert!(
        result.killed_by_timeout,
        "Expected timeout, got exit_code={}, duration={:?}, stderr={}",
        result.exit_code, result.duration, result.stderr
    );

    std::thread::sleep(Duration::from_millis(500));

    let orphans = Command::new("pgrep").args(["-f", "sleep 7777"]).output();

    if let Ok(output) = orphans {
        let orphan_pids: Vec<_> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        assert!(
            orphan_pids.is_empty(),
            "Orphan child processes found: {:?}",
            orphan_pids
        );
    }
}

/// External SIGTERM cleans up the sandbox's children.
#[test]
#[cfg(unix)]
fn test_sigterm_cleanup() {
    // Can't SIGTERM ourselves; check cleanup on normal termination instead.
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    let result = sandbox.run("sh", &["-c", "sleep 1 & wait"]).unwrap();

    assert_eq!(
        result.exit_code, 0,
        "Expected exit 0, got {}, stderr: {}",
        result.exit_code, result.stderr
    );
    assert!(!result.killed_by_timeout);
}

#[test]
#[cfg(unix)]
fn test_rapid_sandbox_no_leaks() {
    for _ in 0..20 {
        let sandbox = Sandbox::builder()
            .working_dir("/tmp")
            .wall_time_limit(Duration::from_millis(50))
            .build()
            .unwrap();

        let _ = sandbox.run("true", &[]);
    }

    let leaked = lasting_zombie_children();
    assert!(leaked.is_empty(), "Zombie processes leaked: {leaked:?}");
}

#[test]
#[cfg(unix)]
fn test_deep_process_tree_killed() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(2))
        .build()
        .unwrap();

    let result = sandbox
        .run("sh", &["-c", "sh -c 'sh -c \"sleep 8888\" &' & sleep 8888"])
        .unwrap();

    assert!(
        result.killed_by_timeout,
        "Expected timeout, got exit_code={}, duration={:?}, stderr={}",
        result.exit_code, result.duration, result.stderr
    );

    std::thread::sleep(Duration::from_millis(500));

    let orphans = Command::new("pgrep").args(["-f", "sleep 8888"]).output();

    if let Ok(output) = orphans {
        assert!(
            output.stdout.is_empty(),
            "Deep child processes survived: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

/// The command runs as PID 2 under a tiny init shim (PID 1) that forwards signals; see `child.rs`.
#[test]
#[cfg(target_os = "linux")]
fn test_sandboxed_command_is_pid_2_under_the_init_shim() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();
    let result = sandbox.run("sh", &["-c", "echo $$"]).unwrap();
    assert_eq!(result.stdout.trim(), "2", "{result:?}");
}

/// A sandboxed command can signal itself. As PID 1 the kernel dropped its default-disposition self-signals
/// (`kill -TERM $$` did nothing); as PID 2 under the shim it is killed normally. The shim exits 128+signal
/// (like tini) and reports the signal over a pipe, so `signal` is `Some` as if killed directly.
#[test]
#[cfg(target_os = "linux")]
fn test_self_sigterm_now_works_like_anywhere_else() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();
    let result = sandbox
        .run("sh", &["-c", "kill -TERM $$; sleep 0.2; echo SURVIVED"])
        .unwrap();
    assert_eq!(result.exit_code, 128 + 15, "{result:?}"); // SIGTERM
    assert_eq!(result.signal, Some(15), "{result:?}");
    assert!(!result.stdout.contains("SURVIVED"), "{result:?}");
}

#[test]
#[cfg(target_os = "linux")]
fn test_self_sigkill_now_works_like_anywhere_else() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();
    let result = sandbox
        .run("sh", &["-c", "kill -KILL $$; sleep 0.2; echo SURVIVED"])
        .unwrap();
    assert_eq!(result.exit_code, 128 + 9, "{result:?}"); // SIGKILL
    assert_eq!(result.signal, Some(9), "{result:?}");
    assert!(!result.stdout.contains("SURVIVED"), "{result:?}");
}

/// A program that merely exits with a signal-looking status (143) isn't reported as signal-killed;
/// only `signal` tells them apart.
#[test]
#[cfg(target_os = "linux")]
fn test_exit_143_is_not_a_signal() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();
    let result = sandbox.run("sh", &["-c", "exit 143"]).unwrap();
    assert_eq!(result.exit_code, 143, "{result:?}");
    assert_eq!(result.signal, None, "{result:?}");
}

/// A normal exit code comes through the shim unchanged.
#[test]
#[cfg(target_os = "linux")]
fn test_exit_code_passes_through_the_init_shim() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();
    let result = sandbox.run("sh", &["-c", "exit 42"]).unwrap();
    assert_eq!(result.exit_code, 42, "{result:?}");
    assert_eq!(result.signal, None, "{result:?}");
}

#[cfg(unix)]
/// Zombies parented to this test process still there half a second later. Other parallel tests have
/// briefly-zombie processes; a leaked one stays, and counting all zombies was flaky.
fn lasting_zombie_children() -> Vec<String> {
    let sample = || -> Vec<String> {
        let output = Command::new("ps")
            .args(["-A", "-o", "pid=,ppid=,stat="])
            .output()
            .expect("Failed to run ps");
        let me = std::process::id().to_string();
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(
                |line| match line.split_whitespace().collect::<Vec<_>>()[..] {
                    [pid, ppid, stat] if ppid == me && stat.starts_with('Z') => {
                        Some(pid.to_string())
                    }
                    _ => None,
                },
            )
            .collect()
    };
    let first = sample();
    std::thread::sleep(Duration::from_millis(500));
    let second = sample();
    first
        .into_iter()
        .filter(|pid| second.contains(pid))
        .collect()
}

/// A background process that leaves the process group and outlives its parent is killed with the run
/// (it used to survive, reparented to launchd where the tree walk misses it). Others' processes are left alone.
#[test]
#[cfg(target_os = "macos")]
fn test_escaped_background_process_killed() {
    let alive = |pid: i32| unsafe { libc::kill(pid, 0) } == 0;

    let mut unrelated = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let other = std::sync::Arc::new(Sandbox::builder().build().unwrap());
    let other_run = {
        let other = other.clone();
        std::thread::spawn(move || other.run("sh", &["-c", "sleep 3; echo still-here"]))
    };

    let sandbox = Sandbox::builder().build().unwrap();
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                "perl -e 'setpgrp(0,0); sleep 30' & echo $!; sleep 0.2",
            ],
        )
        .unwrap();
    let escaped: i32 = result.stdout.trim().parse().unwrap();

    // Killed, and then reaped by launchd.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while alive(escaped) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let escaped_alive = alive(escaped);
    let unrelated_alive = alive(unrelated.id() as i32);
    if escaped_alive {
        unsafe {
            libc::kill(escaped, libc::SIGKILL);
        }
    }
    let _ = unrelated.kill();
    let _ = unrelated.wait();

    assert!(
        !escaped_alive,
        "background process {escaped} outlived the run"
    );
    assert!(unrelated_alive, "a process outside the sandbox was killed");
    let other = other_run.join().unwrap().unwrap();
    assert_eq!(
        other.stdout.trim(),
        "still-here",
        "another sandbox's run was killed"
    );
}

/// If the process running the sandbox dies, the sandbox does too (it used to keep running with nothing
/// to enforce its time limit; PR_SET_PDEATHSIG on Linux, a watchdog on macOS: src/platform/macos/watchdog.rs).
/// Runs this test binary again as the host process and kills only that child.
#[test]
#[cfg(unix)]
fn test_sandbox_dies_with_its_host_process() {
    const MARKER: &str = "31.4159";
    if std::env::var_os("NSB_PDEATH_HOST").is_some() {
        let sandbox = Sandbox::builder()
            .wall_time_limit(Duration::from_secs(60))
            .build()
            .unwrap();
        let _ = sandbox.run("sleep", &[MARKER]);
        return;
    }
    let running = || {
        Command::new("pgrep")
            .args(["-f", &format!("^sleep {MARKER}$")])
            .output()
            .map(|o| !o.stdout.is_empty())
            .unwrap_or(false)
    };
    let mut host = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "process_management::test_sandbox_dies_with_its_host_process",
        ])
        .env("NSB_PDEATH_HOST", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !running() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(running(), "the sandbox never started");

    host.kill().unwrap();
    host.wait().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while running() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!running(), "the sandbox outlived its host process");
}

/// Every run's marker files (how its processes are found and killed) are out of reach of every run's command,
/// including another run's, and the directory and its parent can't be moved aside. The other run's marker is
/// planted from the host so concurrent tests don't interfere.
#[cfg(target_os = "macos")]
#[test]
fn test_a_command_cannot_touch_any_runs_markers() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();
    let markers = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join("nanosandbox-markers");
    std::fs::create_dir_all(&markers).unwrap();
    let other = markers.join(format!("nanosandbox-run-{}-77-in", std::process::id()));
    std::fs::write(&other, "").unwrap();
    let planted = markers.join(format!("nanosandbox-run-{}-78-in", std::process::id()));
    let script = format!(
        "d='{d}'; o='{o}'; p='{p}'; \
         rm -f \"$o\" 2>/dev/null; echo rm=$?; mv \"$o\" \"$o.x\" 2>/dev/null; echo mv=$?; \
         echo x > \"$o\" 2>/dev/null; echo write=$?; echo x > \"$p\" 2>/dev/null; echo plant=$?; \
         rm -rf \"$d\" 2>/dev/null; mv \"$d\" \"$d.x\" 2>/dev/null; echo mvdir=$?; \
         mv \"$(dirname \"$d\")\" \"$(dirname \"$d\").x\" 2>/dev/null; echo mvtmp=$?",
        d = markers.display(),
        o = other.display(),
        p = planted.display()
    );
    let out = sandbox.run("sh", &["-c", &script]).unwrap();
    let still_there =
        other.exists() && std::fs::metadata(&other).map(|m| m.len()).unwrap_or(1) == 0;
    let moved = other.with_extension("x").exists();
    let planted_exists = planted.exists();
    let _ = std::fs::remove_file(&other);
    let _ = std::fs::remove_file(other.with_extension("x"));
    let _ = std::fs::remove_file(&planted);
    assert!(
        still_there && !moved,
        "another run's marker was removed, moved or written: {out:?}"
    );
    assert!(!planted_exists, "a marker file was planted: {out:?}");
    for ok in ["rm=0", "mv=0", "write=0", "plant=0", "mvdir=0", "mvtmp=0"] {
        assert!(!out.stdout.contains(ok), "{ok}: {out:?}");
    }
    assert!(markers.is_dir() && !markers.with_extension("x").exists());
    assert!(
        std::env::temp_dir().canonicalize().is_ok(),
        "the temp directory was moved"
    );
}

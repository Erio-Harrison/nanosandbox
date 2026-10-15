//! Windows: what a run's Job Object enforces, and what `build()` refuses
//! without the one-time install.

use nanosandbox::{MB, Sandbox, SandboxError};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn builder() -> nanosandbox::SandboxBuilder {
    crate::common::builder().working_dir(r"C:\Windows\Temp")
}

fn powershell(sandbox: &Sandbox, script: &str) -> nanosandbox::ExecutionResult {
    sandbox
        .run(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", script],
        )
        .unwrap()
}

#[test]
fn test_memory_limit_kills_the_run() {
    let sandbox = builder()
        .memory_limit(150 * MB)
        .wall_time_limit(Duration::from_secs(30))
        .build()
        .unwrap();
    let r = powershell(
        &sandbox,
        "$a = New-Object byte[] 400MB; $a[0] = 1; 'allocated'",
    );
    assert!(r.killed_by_oom, "not killed for memory: {r:?}");
    assert!(!r.stdout.contains("allocated"));
    assert!(!r.success());
    // Windows counts the refused 400MB into the Job's own peak; what's
    // reported is what was in use, never past the limit.
    let peak = r.peak_memory.unwrap();
    assert!(peak > 0 && peak <= 150 * MB, "peak {peak}");
}

/// The limit is the whole run's, not each process's: two processes that
/// each fit under it alone don't fit together.
#[test]
fn test_memory_limit_counts_every_process_of_the_run() {
    let alloc = "$a = New-Object byte[] 120MB; $a[0] = 1; Start-Sleep 3";
    let one = builder()
        .memory_limit(260 * MB)
        .wall_time_limit(Duration::from_secs(30))
        .build()
        .unwrap();
    let r = powershell(&one, alloc);
    assert!(!r.killed_by_oom, "one process alone should fit: {r:?}");

    let two = format!(
        "$p = Start-Process powershell -ArgumentList '-NoProfile','-Command','{alloc}' -PassThru -NoNewWindow; {alloc}; $p.WaitForExit()"
    );
    let r = powershell(&one, &two);
    assert!(r.killed_by_oom, "two together should not: {r:?}");
}

#[test]
fn test_max_pids_limits_the_process_count() {
    let sandbox = builder().max_pids(2).build().unwrap();
    // cmd itself is one; the first child is the second; the next can't start.
    let r = sandbox
        .run(
            "cmd",
            &[
                "/c",
                "start /b ping -n 3 127.0.0.1 >nul & ping -n 1 127.0.0.1 >nul && echo third ran",
            ],
        )
        .unwrap();
    assert!(!r.stdout.contains("third ran"), "{r:?}");
    assert!(r.stderr.contains("quota"), "{r:?}");
}

#[test]
fn test_cpu_time_limit_kills_the_run() {
    let sandbox = builder()
        .cpu_time_limit(Duration::from_secs(1))
        .wall_time_limit(Duration::from_secs(30))
        .build()
        .unwrap();
    let start = Instant::now();
    let r = powershell(&sandbox, "while ($true) {}");
    assert!(r.killed_by_cpu_limit, "{r:?}");
    assert!(start.elapsed() < Duration::from_secs(10));
    let used = r.cpu_time.unwrap();
    assert!(
        used >= Duration::from_secs(1) && used < Duration::from_secs(3),
        "{used:?}"
    );
}

/// A batch file that starts a descendant, which writes `started` at once and
/// `alive` after `alive_after` seconds; it waits for `started`, then runs
/// `then`. So the descendant has surely run, and only its being killed keeps
/// `alive` from appearing. cmd, not PowerShell: that can take seconds to
/// start on a fresh CI machine.
fn descendant_script(dir: &Path, alive_after: u32, then: &str) -> PathBuf {
    let script = dir.join("run.bat");
    let ping = alive_after + 1; // ping -n N waits N - 1 seconds
    std::fs::write(
        &script,
        format!(
            "@echo off\r\ncd /d \"%~dp0\"\r\n\
             start /b cmd /c \"echo x>started& ping -n {ping} 127.0.0.1 >nul& echo x>alive\"\r\n\
             :wait\r\nif not exist started (ping -n 1 127.0.0.1 >nul& goto wait)\r\n\
             {then}\r\n"
        ),
    )
    .unwrap();
    script
}

#[test]
fn test_wall_time_limit_kills_descendants_too() {
    let dir = tempfile::tempdir().unwrap();
    let script = descendant_script(dir.path(), 5, "ping -n 30 127.0.0.1 >nul");
    let sandbox = builder()
        .wall_time_limit(Duration::from_secs(3))
        .build()
        .unwrap();
    let r = sandbox
        .run("cmd", &["/c", script.to_str().unwrap()])
        .unwrap();
    assert!(r.killed_by_timeout, "{r:?}");
    assert!(
        dir.path().join("started").exists(),
        "the descendant never ran"
    );
    std::thread::sleep(Duration::from_secs(5));
    assert!(
        !dir.path().join("alive").exists(),
        "a descendant outlived the run"
    );
}

/// A run ends when its command does: what it left running in the
/// background goes with it, as on Linux and macOS.
#[test]
fn test_background_processes_end_with_the_run() {
    let sandbox = builder()
        .wall_time_limit(Duration::from_secs(30))
        .build()
        .unwrap();

    // Control: left alive, the descendant does write `alive`.
    let control = tempfile::tempdir().unwrap();
    let wait_for_alive = ":alive\r\nif not exist alive (ping -n 1 127.0.0.1 >nul& goto alive)";
    let script = descendant_script(control.path(), 3, wait_for_alive);
    let r = sandbox
        .run("cmd", &["/c", script.to_str().unwrap()])
        .unwrap();
    assert!(r.success(), "control: {r:?}");

    let dir = tempfile::tempdir().unwrap();
    let script = descendant_script(dir.path(), 3, "echo root done");
    let start = Instant::now();
    let r = sandbox
        .run("cmd", &["/c", script.to_str().unwrap()])
        .unwrap();
    assert!(r.stdout.contains("root done"), "{r:?}");
    assert!(
        dir.path().join("started").exists(),
        "the descendant never ran"
    );
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "waited for the background process"
    );
    std::thread::sleep(Duration::from_secs(4));
    assert!(
        !dir.path().join("alive").exists(),
        "a background process outlived the run"
    );
}

/// stdin and output both far past a pipe's buffer: neither side stalls.
#[test]
fn test_large_stdin_and_output_do_not_deadlock() {
    let input: String = (0..50_000).map(|i| format!("line {i:08}\n")).collect();
    let sandbox = builder()
        .wall_time_limit(Duration::from_secs(30))
        .build()
        .unwrap();
    let r = sandbox
        .run_with_input("sort", &[], Some(input.as_bytes()))
        .unwrap();
    assert!(!r.killed_by_timeout);
    assert_eq!(r.stdout.lines().count(), 50_000);
}

#[test]
fn test_output_past_max_output_is_truncated() {
    let sandbox = builder().max_output(1000).build().unwrap();
    let r = sandbox
        .run("cmd", &["/c", "for /L %i in (1,1,2000) do @echo line %i"])
        .unwrap();
    assert!(r.output_truncated);
    assert_eq!(r.stdout.len(), 1000);
    assert!(r.success());
}

/// clear_env leaves out the host's variables, but not the few Windows
/// programs can't start without.
#[test]
fn test_clear_env_keeps_what_windows_needs() {
    // SAFETY: tests in this binary don't read this variable concurrently.
    unsafe { std::env::set_var("NANOSANDBOX_TEST_SECRET", "hunter2") };
    let sandbox = builder().build().unwrap();
    let r = sandbox.run("cmd", &["/c", "set"]).unwrap();
    assert!(!r.stdout.contains("hunter2"), "{}", r.stdout);
    assert!(
        r.stdout.to_ascii_lowercase().contains("systemroot="),
        "{}",
        r.stdout
    );
    // And the network stack starts, which needs SystemRoot.
    let r = sandbox.run("ping", &["-n", "1", "127.0.0.1"]).unwrap();
    assert!(r.success(), "{r:?}");
}

#[test]
fn test_accounting_is_reported() {
    let sandbox = builder().build().unwrap();
    let r = sandbox.run("cmd", &["/c", "echo hi"]).unwrap();
    assert!(r.peak_memory.is_some_and(|p| p > 0));
    assert!(r.cpu_time.is_some());
}

#[test]
fn test_what_needs_the_install_is_refused() {
    let unsupported =
        |b: nanosandbox::SandboxBuilder| matches!(b.build(), Err(SandboxError::Unsupported { .. }));
    // no_network() is the default.
    assert!(unsupported(
        Sandbox::builder().working_dir(r"C:\Windows\Temp")
    ));
    assert!(unsupported(builder().writable(r"C:\Windows\Temp")));
    assert!(unsupported(builder().deny_read(r"C:\Windows\Temp")));
    assert!(unsupported(builder().cpu_limit(1.0)));
    assert!(unsupported(builder().max_file_size(MB)));
    assert!(unsupported(builder().max_open_files(10)));
}

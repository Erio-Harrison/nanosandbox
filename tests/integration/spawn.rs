//! `spawn()`: streaming I/O, interactive stdin, no truncation, kill/drop, limits, and a PTY.

#![cfg(unix)]

use nanosandbox::Sandbox;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

fn sandbox() -> Sandbox {
    Sandbox::builder().working_dir("/tmp").build().unwrap()
}

/// Reads from `r` until `needle` appears, EOF, or `timeout` passes; returns everything read.
fn read_until<R: Read + AsRawFd>(r: &mut R, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while !String::from_utf8_lossy(&got).contains(needle) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let mut pfd = libc::pollfd {
            fd: r.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, left.as_millis() as i32) } <= 0 {
            continue;
        }
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => panic!("read: {e}"),
        }
    }
    String::from_utf8_lossy(&got).into_owned()
}

#[test]
fn test_output_streams_before_the_command_ends() {
    let sandbox = sandbox();
    let start = Instant::now();
    let mut child = sandbox
        .spawn("sh", &["-c", "echo first; sleep 1; echo second"])
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let first = read_until(&mut stdout, "first", Duration::from_secs(5));
    assert_eq!(first, "first\n");
    assert!(
        start.elapsed() < Duration::from_millis(900),
        "{:?}",
        start.elapsed()
    );

    let second = read_until(&mut stdout, "second", Duration::from_secs(5));
    assert_eq!(second, "second\n");
    let result = child.wait().unwrap();
    assert_eq!(result.exit_code, 0);
}

#[test]
fn test_stdin_is_interactive() {
    let sandbox = sandbox();
    let mut child = sandbox.spawn("cat", &[]).unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    stdin.write_all(b"hello\n").unwrap();
    assert_eq!(
        read_until(&mut stdout, "hello", Duration::from_secs(5)),
        "hello\n"
    );
    stdin.write_all(b"again\n").unwrap();
    assert_eq!(
        read_until(&mut stdout, "again", Duration::from_secs(5)),
        "again\n"
    );
    drop(stdin); // EOF: cat exits
    let result = child.wait().unwrap();
    assert_eq!(result.exit_code, 0);
}

/// `run()` keeps `max_output` and drops the rest; `spawn()` hands every byte to the caller, and
/// a program that writes faster than the caller reads simply waits on its pipe.
#[test]
fn test_spawned_output_is_never_truncated() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .max_output(16)
        .build()
        .unwrap();
    let args = ["-c", "head -c 1000000 /dev/zero"];
    assert!(sandbox.run("sh", &args).unwrap().output_truncated);

    let mut child = sandbox.spawn("sh", &args).unwrap();
    let mut all = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut all).unwrap();
    assert_eq!(all.len(), 1_000_000);
    let result = child.wait().unwrap();
    assert_eq!(result.exit_code, 0);
    assert!(!result.output_truncated);
}

#[test]
fn test_wait_with_output_collects_what_was_not_read() {
    let sandbox = sandbox();
    let child = sandbox
        .spawn("sh", &["-c", "echo out; echo err >&2; exit 3"])
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.stdout, "out\n");
    assert_eq!(result.stderr, "err\n");
    assert_eq!(result.exit_code, 3);
}

#[test]
fn test_kill_ends_the_run() {
    let sandbox = sandbox();
    let mut child = sandbox.spawn("sleep", &["30"]).unwrap();
    let start = Instant::now();
    child.kill().unwrap();
    let result = child.wait().unwrap();
    assert!(start.elapsed() < Duration::from_secs(5));
    assert_eq!(result.signal, Some(libc::SIGKILL));
    assert_eq!(result.exit_code, 128 + libc::SIGKILL);
    assert!(!result.killed_by_timeout);
}

#[test]
fn test_dropping_a_child_kills_and_reaps_it() {
    let sandbox = sandbox();
    let child = sandbox.spawn("sleep", &["30"]).unwrap();
    let pid = child.id() as libc::pid_t;
    assert_eq!(unsafe { libc::kill(pid, 0) }, 0);
    drop(child);
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "pid {pid} still exists");
}

#[test]
fn test_try_wait_reports_the_end_once() {
    let sandbox = sandbox();
    let mut child = sandbox.spawn("sh", &["-c", "sleep 0.2; exit 7"]).unwrap();
    assert!(child.try_wait().unwrap().is_none());
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = loop {
        if let Some(r) = child.try_wait().unwrap() {
            break r;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(result.exit_code, 7);
    assert_eq!(child.wait().unwrap().exit_code, 7);
}

#[test]
fn test_limits_apply_to_a_spawned_command() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_millis(300))
        .build()
        .unwrap();
    let child = sandbox.spawn("sleep", &["30"]).unwrap();
    let result = child.wait().unwrap();
    assert!(result.killed_by_timeout);
    assert!(result.duration < Duration::from_secs(5));
}

#[test]
fn test_pty_is_a_terminal_of_the_given_size() {
    let sandbox = sandbox();
    let child = sandbox
        .spawn_pty("sh", &["-c", "stty size; tty"], 24, 80)
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.exit_code, 0, "{result:?}");
    assert!(result.stdout.contains("24 80"), "{:?}", result.stdout);
    assert!(!result.stdout.contains("not a tty"), "{:?}", result.stdout);
    assert!(result.stderr.is_empty());
}

#[test]
fn test_pty_runs_an_interactive_shell() {
    let sandbox = sandbox();
    let mut child = sandbox.spawn_pty("sh", &[], 24, 80).unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    assert!(child.stderr.is_none());
    // A shell may flush pending input as it sets the terminal up: type after the prompt.
    let prompt = read_until(&mut stdout, "$ ", Duration::from_secs(5));
    assert!(prompt.ends_with("$ "), "{prompt:?}");
    stdin.write_all(b"echo hi-$((20+3))\n").unwrap();
    let seen = read_until(&mut stdout, "hi-23\r\n", Duration::from_secs(5));
    assert!(seen.contains("hi-23\r\n"), "{seen:?}");
    // Resize with the shell idle at its prompt (SIGWINCH makes readline redraw it), and ask
    // again if the shell answers before it has taken the new size in.
    read_until(&mut stdout, "$ ", Duration::from_secs(5));
    child.resize(40, 100).unwrap();
    let mut seen = String::new();
    for _ in 0..5 {
        stdin.write_all(b"stty size\n").unwrap();
        seen = read_until(&mut stdout, "$ ", Duration::from_secs(5));
        if seen.contains("40 100") {
            break;
        }
    }
    assert!(seen.contains("40 100"), "{seen:?}");
    stdin.write_all(b"exit 5\n").unwrap();
    // The caller took stdout, so it's the caller's to drain: a shell restoring the terminal on
    // exit waits for its output to be read (macOS).
    stdout.read_to_end(&mut Vec::new()).unwrap();
    let result = child.wait().unwrap();
    assert_eq!(result.exit_code, 5);
}

#[test]
fn test_a_pty_command_has_its_own_terminal_not_the_hosts() {
    let sandbox = sandbox();
    // TIOCSTI into its own terminal only reaches itself; /dev/tty is that terminal.
    let child = sandbox
        .spawn_pty("sh", &["-c", "ps -o tty= -p $$; echo done"], 24, 80)
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.stdout.contains("done"), "{result:?}");
}

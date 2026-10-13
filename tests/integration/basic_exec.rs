//! Cross-platform basic execution tests

use nanosandbox::Sandbox;

#[test]
fn test_echo() {
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .build()
        .unwrap();

    #[cfg(target_os = "windows")]
    let result = sandbox.run("cmd", &["/c", "echo hello world"]).unwrap();
    #[cfg(not(target_os = "windows"))]
    let result = sandbox.run("echo", &["hello", "world"]).unwrap();

    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.contains("hello"));
}

#[test]
fn test_exit_code_propagation() {
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .build()
        .unwrap();

    for code in [0, 1, 42] {
        #[cfg(target_os = "windows")]
        let result = sandbox
            .run("cmd", &["/c", &format!("exit {}", code)])
            .unwrap();
        #[cfg(not(target_os = "windows"))]
        let result = sandbox
            .run("sh", &["-c", &format!("exit {}", code)])
            .unwrap();

        assert_eq!(result.exit_code, code);
    }
}

#[test]
fn test_stderr_capture() {
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .build()
        .unwrap();

    #[cfg(target_os = "windows")]
    let result = sandbox.run("cmd", &["/c", "echo error 1>&2"]).unwrap();
    #[cfg(not(target_os = "windows"))]
    let result = sandbox.run("sh", &["-c", "echo error >&2"]).unwrap();

    assert!(result.stderr.contains("error"));
}

#[test]
fn test_stdin_input() {
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .build()
        .unwrap();

    let input = b"hello\nworld\n";

    #[cfg(not(target_os = "windows"))]
    {
        let result = sandbox.run_with_input("cat", &[], Some(input)).unwrap();
        assert!(result.stdout.contains("hello"));
    }
}

/// HOME points at the run's private temp directory, so programs that keep
/// caches and config under it (npm, pip, git, ...) have somewhere to write
/// instead of looking the user up and finding a home they can't use.
#[test]
#[cfg(unix)]
fn test_home_is_the_private_temp_directory() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                "echo \"$HOME|$TMPDIR\"; cd && pwd; echo x > .cache-probe && echo writable",
            ],
        )
        .unwrap();
    assert!(result.success(), "{}", result.stderr);
    let lines: Vec<&str> = result.stdout.lines().collect();
    let (home, tmpdir) = lines[0].split_once('|').unwrap();
    assert!(!home.is_empty());
    assert_eq!(home, tmpdir);
    assert_eq!(lines[1], home, "`cd` with no argument goes to HOME");
    assert_eq!(lines[2], "writable");
}

/// A command killed by a signal reports 128 + signal as its exit code and
/// the signal itself, the same on every platform (macOS used to say -1, and
/// Linux, with its init shim, left `signal` out). A program that only exits
/// with that number isn't mistaken for one.
#[test]
#[cfg(unix)]
fn test_killed_by_a_signal_reports_128_plus_the_signal() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();
    for (script, code, signal) in [("kill -TERM $$", 143, 15), ("kill -KILL $$", 137, 9)] {
        let result = sandbox.run("sh", &["-c", script]).unwrap();
        assert_eq!(result.exit_code, code, "{script}: {result:?}");
        assert_eq!(result.signal, Some(signal), "{script}: {result:?}");
        assert!(!result.success());
        assert_eq!(
            result.failure_reason().as_deref(),
            Some(format!("Killed by signal {signal}").as_str())
        );
    }

    let result = sandbox.run("sh", &["-c", "exit 143"]).unwrap();
    assert_eq!(result.exit_code, 143);
    assert_eq!(
        result.signal, None,
        "an exit status isn't a signal: {result:?}"
    );
    assert_eq!(result.failure_reason().as_deref(), Some("Exit code 143"));
}

#[test]
#[cfg(unix)]
fn test_a_home_the_caller_sets_wins() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .env("HOME", "/somewhere/else")
        .build()
        .unwrap();
    let result = sandbox.run("sh", &["-c", "echo $HOME"]).unwrap();
    assert_eq!(result.stdout.trim(), "/somewhere/else");
}

#[test]
#[cfg(unix)]
fn test_no_home_without_a_private_temp_directory() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .no_private_tmp()
        .build()
        .unwrap();
    let result = sandbox
        .run("sh", &["-c", "echo \"[${HOME-unset}]\""])
        .unwrap();
    assert_eq!(result.stdout.trim(), "[unset]");
}

#[test]
fn test_environment_variables() {
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .env("FOO", "bar")
        .env("BAZ", "qux")
        .build()
        .unwrap();

    #[cfg(target_os = "windows")]
    let result = sandbox.run("cmd", &["/c", "echo %FOO% %BAZ%"]).unwrap();
    #[cfg(not(target_os = "windows"))]
    let result = sandbox.run("sh", &["-c", "echo $FOO $BAZ"]).unwrap();

    assert!(result.stdout.contains("bar"));
    assert!(result.stdout.contains("qux"));
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_working_directory() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox.run("pwd", &[]).unwrap();
    assert!(result.stdout.contains("/tmp") || result.stdout.contains("/private/tmp"));
}

#[test]
fn test_command_not_found() {
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .build()
        .unwrap();

    let result = sandbox.run("nonexistent_command_12345", &[]);
    assert!(result.is_err() || !result.unwrap().success());
}

#[test]
fn test_long_output() {
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .build()
        .unwrap();

    #[cfg(not(target_os = "windows"))]
    {
        let result = sandbox
            .run(
                "sh",
                &["-c", "for i in $(seq 1 1000); do echo line$i; done"],
            )
            .unwrap();
        assert!(result.success());
        assert!(result.stdout.contains("line1"));
        assert!(result.stdout.contains("line1000"));
    }
}

#[test]
fn test_binary_output() {
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .build()
        .unwrap();

    #[cfg(not(target_os = "windows"))]
    {
        // Output some binary data
        let result = sandbox
            .run("sh", &["-c", "printf '\\x00\\x01\\x02'"])
            .unwrap();
        assert!(result.success());
    }
}

/// clear_env(false) passes this process's environment through, with env()
/// on top; by default the program starts with only what env() sets.
#[test]
#[cfg(unix)]
fn test_clear_env() {
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("NSB_INHERITED_PROBE", "from-host") };
    let script = "echo \"${NSB_INHERITED_PROBE:-unset} $NSB_SET\"";

    let cleared = Sandbox::builder().env("NSB_SET", "set").build().unwrap();
    let result = cleared.run("sh", &["-c", script]).unwrap();
    assert_eq!(result.stdout.trim(), "unset set");

    let inherited = Sandbox::builder()
        .clear_env(false)
        .env("NSB_SET", "set")
        .build()
        .unwrap();
    let result = inherited.run("sh", &["-c", script]).unwrap();
    assert_eq!(result.stdout.trim(), "from-host set");
}

/// A lot of output comes back quickly, and past max_output it's cut off,
/// flagged, while the program still runs to the end. It used to be read at
/// about 400 KB/s on Linux, with no limit.
#[test]
#[cfg(unix)]
fn test_large_output_fast_and_capped() {
    let sandbox = Sandbox::builder()
        .wall_time_limit(std::time::Duration::from_secs(30))
        .build()
        .unwrap();
    // 24 MB on stdout, past the 16 MB default.
    let start = std::time::Instant::now();
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                "head -c 25165824 /dev/zero | tr '\\0' x; echo done >&2",
            ],
        )
        .unwrap();
    // Generous margin: this is checking that capped output doesn't create
    // backpressure that stalls the producer, not a tight perf budget -- a
    // real regression here would be orders of magnitude slower, not just a
    // loaded CI runner's variance.
    assert!(
        start.elapsed() < std::time::Duration::from_secs(25),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(result.exit_code, 0);
    assert!(result.output_truncated);
    assert_eq!(result.stdout.len() as u64, nanosandbox::DEFAULT_MAX_OUTPUT);
    assert_eq!(result.stderr, "done\n");

    let small = Sandbox::builder().max_output(4).build().unwrap();
    let result = small
        .run("sh", &["-c", "echo hello; echo world >&2"])
        .unwrap();
    assert_eq!(
        (result.stdout.as_str(), result.stderr.as_str()),
        ("hell", "worl")
    );
    assert!(result.output_truncated);
    let result = small.run("echo", &["hi"]).unwrap();
    assert!(!result.output_truncated);
}

/// A program gets SIGPIPE's default action: `yes` stops quietly when `head`
/// is done. It used to inherit this process's "ignore", and complain.
#[test]
#[cfg(unix)]
fn test_sigpipe_default() {
    let sandbox = Sandbox::builder().build().unwrap();
    let result = sandbox.run("sh", &["-c", "yes | head -1"]).unwrap();
    assert_eq!(result.stdout, "y\n");
    assert_eq!(result.stderr, "", "SIGPIPE ignored in the sandbox");
}

// A missing command: see test_error_command_not_found in
// tests/integration/error_handling.rs, which asserts the actual public
// contract (Err(SandboxError::CommandNotFound), not Ok() with exit 127 --
// that was itself the bug this file's version of the test used to assert).

/// With no stdin given, the command gets /dev/null, not this process's own
/// stdin: it could otherwise read it, and a flag it set on it (node puts
/// its stdin in non-blocking mode) would apply to this process's reads too,
/// since they share the open file description.
#[test]
#[cfg(unix)]
fn test_the_command_does_not_get_the_hosts_stdin() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();
    let out = sandbox
        .run(
            "sh",
            &[
                "-c",
                "python3 -c \"import os; a = os.fstat(0); b = os.stat('/dev/null'); \
                 print('devnull' if a.st_rdev and a.st_rdev == b.st_rdev else 'not')\"; \
                 python3 -c 'import fcntl, os; fcntl.fcntl(0, fcntl.F_SETFL, os.O_NONBLOCK)'",
            ],
        )
        .unwrap();
    assert_eq!(out.stdout.trim(), "devnull", "{out:?}");
    let flags = unsafe { libc::fcntl(0, libc::F_GETFL) };
    assert!(
        flags < 0 || flags & libc::O_NONBLOCK == 0,
        "the host's stdin was put in non-blocking mode"
    );
}

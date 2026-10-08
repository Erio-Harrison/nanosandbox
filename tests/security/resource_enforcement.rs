//! P0: Resource Limits Enforcement Tests
//!
//! Tests for:
//! - setrlimit actually being called (macOS)
//! - cgroup cleanup after execution (Linux)
//! - OOM detection from cgroup events (Linux)

use nanosandbox::Sandbox;
use std::time::Duration;

/// Test: Memory limit is enforced on macOS by polling the process group footprint
#[test]
#[cfg(target_os = "macos")]
fn test_macos_memory_limit_enforced() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .memory_limit(50 * 1024 * 1024)
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    let ok = sandbox.run("sh", &["-c", "echo within_limit"]).unwrap();
    assert_eq!(ok.exit_code, 0);
    assert!(!ok.killed_by_oom);

    let result = sandbox
        .run("perl", &["-e", "$x = 'a' x 200_000_000; sleep 5"])
        .unwrap();
    assert!(
        result.killed_by_oom,
        "200MB allocation should exceed the 50MB limit"
    );
    assert!(!result.success());
    assert!(!result.killed_by_timeout);
}

/// Test: A child that leaves the process group still counts toward the memory limit
#[test]
#[cfg(target_os = "macos")]
fn test_macos_memory_limit_counts_escaped_child() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .memory_limit(50 * 1024 * 1024)
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    // A variable length keeps perl from folding the allocation into the parent at compile time.
    let script = "use POSIX; if (fork() == 0) { POSIX::setsid(); $n = 200_000_000; $x = 'a' x $n; sleep 5; exit 0 } sleep 6;";
    let result = sandbox.run("perl", &["-e", script]).unwrap();
    assert!(
        result.killed_by_oom,
        "escaped child's memory should be counted"
    );
    assert!(result.duration < Duration::from_secs(4));
}

/// Test: memory_limit counts a daemonized descendant too -- not just one
/// that left the process group while its parent is still alive (the
/// previous test), but one orphaned to launchd by a double fork, the
/// classic daemonize pattern. The live polling check used to walk the
/// process tree by parent links, which a reparented process isn't in;
/// confirmed for real, it finished clean under a 5x-over allocation.
#[test]
#[cfg(target_os = "macos")]
fn test_macos_memory_limit_counts_daemonized_descendant() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .memory_limit(64 * 1024 * 1024)
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    let script = "
        python3 -c \"
import os, time
if os.fork() == 0:
    if os.fork() == 0:
        os.setsid()
        x = bytearray(300 * 1024 * 1024)
        for i in range(0, len(x), 4096):
            x[i] = 1
        time.sleep(7)
        os._exit(0)
    os._exit(0)
os.wait()
time.sleep(8)
print('top-level done', flush=True)
\"
    ";
    let result = sandbox.run("sh", &["-c", script]).unwrap();
    assert!(
        result.killed_by_oom,
        "a daemonized descendant's memory should still be counted: {result:?}"
    );
    assert!(!result.killed_by_timeout);
    assert!(
        result.duration < Duration::from_secs(5),
        "{:?}",
        result.duration
    );
}

/// Test: The timeout kill also reaches a child that left the process group
#[test]
#[cfg(target_os = "macos")]
fn test_macos_timeout_kills_escaped_child() {
    let pid_file = format!("/tmp/nanosandbox_escape_{}", std::process::id());
    let _ = std::fs::remove_file(&pid_file);
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(1))
        .build()
        .unwrap();

    let script = format!(
        "use POSIX; if (fork() == 0) {{ POSIX::setsid(); open(F, '>', '{pid_file}'); print F $$; close(F); sleep 30; exit 0 }} sleep 30;"
    );
    let result = sandbox.run("perl", &["-e", &script]).unwrap();
    assert!(result.killed_by_timeout);
    assert!(
        result.duration < Duration::from_secs(5),
        "run() should return right after the timeout, took {:?}",
        result.duration
    );

    let pid = std::fs::read_to_string(&pid_file).expect("child should have written its pid");
    let pid = pid.trim();
    std::thread::sleep(Duration::from_millis(300));
    let alive = std::process::Command::new("kill")
        .args(["-0", pid])
        .status()
        .unwrap()
        .success();
    if alive {
        let _ = std::process::Command::new("kill")
            .args(["-9", pid])
            .status();
    }
    let _ = std::fs::remove_file(&pid_file);
    assert!(!alive, "escaped child survived the timeout kill");
}

/// Test: A rejected setrlimit names the setting instead of a bare errno
#[test]
#[cfg(target_os = "macos")]
fn test_macos_rejected_rlimit_names_the_setting() {
    // root may raise the hard limit, so the value below would be accepted
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .max_file_size(u64::MAX)
        .build()
        .unwrap();

    let err = sandbox.run("true", &[]).unwrap_err().to_string();
    assert!(
        err.contains("max_file_size") && err.contains("RLIMIT_FSIZE"),
        "error should name the rejected limit, got: {err}"
    );
}

/// Test: Max processes limit on macOS
///
/// RLIMIT_NPROC on macOS counts every process the user has, not just the
/// sandbox's, so it can't be used, and there's nothing else: build()
/// refuses max_pids rather than accept it and not enforce it.
#[test]
#[cfg(target_os = "macos")]
fn test_macos_max_pids_refused() {
    let result = Sandbox::builder().max_pids(5).build();
    assert!(matches!(
        result,
        Err(nanosandbox::SandboxError::Unsupported { .. })
    ));
}

/// Test: Max open files limit should be enforced via setrlimit
#[test]
#[cfg(unix)]
fn test_max_open_files_enforced() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .max_open_files(20)
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    // Check ulimit value
    let result = sandbox.run("sh", &["-c", "ulimit -n"]).unwrap();
    let output = result.stdout.trim();

    // Should show our limit
    if output != "unlimited" {
        let limit: u32 = output.parse().unwrap_or(0);
        assert!(limit <= 20, "RLIMIT_NOFILE should be 20, got {}", limit);
    }
}

/// Test: Cgroup directories should be cleaned up after execution (Linux)
///
/// Current bug: cgroups accumulate in /sys/fs/cgroup/nanosandbox-*
/// Expected: Cgroup directory deleted after sandbox exits
#[test]
#[cfg(target_os = "linux")]
fn test_linux_cgroup_cleanup() {
    use std::fs;

    let cgroup_base = "/sys/fs/cgroup";

    // Count existing nanosandbox cgroups
    let count_nanosandbox_cgroups = || -> usize {
        if let Ok(entries) = fs::read_dir(cgroup_base) {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with("nanosandbox-"))
                .count()
        } else {
            0
        }
    };

    let initial_count = count_nanosandbox_cgroups();

    // Run several sandboxes
    for _ in 0..5 {
        let sandbox = Sandbox::builder()
            .working_dir("/tmp")
            .memory_limit(64 * 1024 * 1024)
            .build()
            .unwrap();

        let _ = sandbox.run("echo", &["hello"]);
    }

    // Wait for cleanup
    std::thread::sleep(Duration::from_millis(500));

    let final_count = count_nanosandbox_cgroups();

    // Should not accumulate (allow 1 transient)
    assert!(
        final_count <= initial_count + 1,
        "Cgroups leaked: before={}, after={}",
        initial_count,
        final_count
    );
}

/// Test: cpu_time_limit counts the whole cgroup, not just one process.
/// RLIMIT_CPU (set per process too) wouldn't catch a program that forks:
/// each child gets its own copy of the same limit, so N children could use
/// close to N times the configured budget before any one of them, on its
/// own, used enough to hit it. Confirmed for real: 10 busy-loop children
/// under a 2s limit finished in well under a second once the cgroup-wide
/// check was added, each individually nowhere near its own 2s.
#[test]
#[cfg(target_os = "linux")]
fn test_linux_cpu_time_limit_counts_the_whole_cgroup() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .cpu_time_limit(Duration::from_secs(2))
        .wall_time_limit(Duration::from_secs(15))
        .build()
        .unwrap();

    let script = "for i in $(seq 1 10); do \
                     ( i=0; while [ $i -lt 999999999 ]; do i=$((i+1)); done ) & \
                   done; wait";
    let start = std::time::Instant::now();
    let result = sandbox.run("sh", &["-c", script]).unwrap();
    assert!(result.killed_by_cpu_limit, "{result:?}");
    assert!(!result.killed_by_timeout);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
}

/// Test: a single process over cpu_time_limit is still caught by
/// RLIMIT_CPU, same as before the cgroup-wide check above was added.
///
/// The kernel sends the SIGKILL straight to the command (PID 2, under the
/// init shim -- see child.rs), not to anything wait.rs controls, so the
/// shim is the one reporting it onward: 128+signal as a normal exit code,
/// same as `sh -c "kill -9 $$"` would from inside the sandbox now. Not
/// `Some(9)`: the shim can't reproduce a true signal-death on itself.
#[test]
#[cfg(target_os = "linux")]
fn test_linux_cpu_time_limit_single_process_unaffected() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .cpu_time_limit(Duration::from_secs(2))
        .wall_time_limit(Duration::from_secs(15))
        .build()
        .unwrap();

    let result = sandbox
        .run(
            "sh",
            &["-c", "i=0; while [ $i -lt 999999999 ]; do i=$((i+1)); done"],
        )
        .unwrap();
    assert_eq!(result.exit_code, 128 + 9, "{result:?}"); // SIGKILL
    assert_eq!(result.signal, None, "{result:?}");
    assert!(!result.killed_by_cpu_limit, "{result:?}");
}

/// Test: going over memory_limit ends in an OOM kill, reported as one,
/// soon. It used to end as a timeout more often than not: memory.high, at
/// 90% of the limit, throttled the program instead, and swap let it go past
/// the limit.
#[test]
#[cfg(target_os = "linux")]
fn test_linux_oom_detection() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .memory_limit(64 * 1024 * 1024)
        .wall_time_limit(Duration::from_secs(20))
        .build()
        .unwrap();

    // 256 MB, written: allocated and touched, not just reserved.
    let start = std::time::Instant::now();
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                "command -v python3 >/dev/null || { echo NO_PYTHON; exit 0; }
                 python3 -c 'x = b\"x\" * (256 * 1024 * 1024); print(len(x))'",
            ],
        )
        .unwrap();
    if result.stdout.trim() == "NO_PYTHON" {
        eprintln!("skipping: no python3");
        return;
    }
    assert!(result.killed_by_oom, "not an OOM kill: {result:?}");
    assert!(!result.killed_by_timeout);
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );
}

/// Test: Peak memory should be collected (Linux via cgroup, macOS via rusage)
///
/// Current bug: peak_memory is always None
/// Expected: peak_memory contains actual peak RSS
#[test]
#[cfg(unix)]
fn test_peak_memory_collection() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .memory_limit(256 * 1024 * 1024)
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    // Allocate known amount of memory
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                r#"
        # Allocate ~10MB
        dd if=/dev/zero bs=1M count=10 2>/dev/null | cat > /dev/null
        echo "done"
    "#,
            ],
        )
        .unwrap();

    assert_eq!(result.exit_code, 0);

    // Peak memory should be populated
    assert!(
        result.peak_memory.is_some(),
        "peak_memory should be collected, got None"
    );

    if let Some(peak) = result.peak_memory {
        // Should be at least a few MB (shell + dd overhead)
        assert!(
            peak > 1024 * 1024,
            "peak_memory seems too low: {} bytes",
            peak
        );
    }
}

/// Test: CPU time should be collected
///
/// Current bug: cpu_time is always None
/// Expected: cpu_time contains actual CPU time used
#[test]
#[cfg(unix)]
fn test_cpu_time_collection() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    // Do some CPU work
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                r#"
        # Burn some CPU
        i=0
        while [ $i -lt 100000 ]; do
            i=$((i + 1))
        done
        echo "done"
    "#,
            ],
        )
        .unwrap();

    assert_eq!(result.exit_code, 0);

    // CPU time should be populated
    assert!(
        result.cpu_time.is_some(),
        "cpu_time should be collected, got None"
    );

    if let Some(cpu_time) = result.cpu_time {
        // Should have used some CPU time
        assert!(
            cpu_time > Duration::from_micros(100),
            "cpu_time seems too low: {:?}",
            cpu_time
        );
    }
}

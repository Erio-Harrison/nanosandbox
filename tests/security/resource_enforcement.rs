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
    assert!(result.killed_by_oom, "200MB allocation should exceed the 50MB limit");
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
    assert!(result.killed_by_oom, "escaped child's memory should be counted");
    assert!(result.duration < Duration::from_secs(4));
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
        let _ = std::process::Command::new("kill").args(["-9", pid]).status();
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
/// NOTE: RLIMIT_NPROC on macOS affects the ENTIRE USER, not just the sandbox.
/// This makes it unsuitable for sandboxing, so we intentionally do NOT use it.
/// On Linux, we use cgroups pids controller instead.
#[test]
#[cfg(target_os = "macos")]
fn test_macos_max_pids_not_enforced_intentionally() {
    // This test documents that max_pids is NOT enforced via RLIMIT_NPROC on macOS
    // because RLIMIT_NPROC limits processes for the entire user, not per-sandbox
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .max_pids(5)
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    // On macOS, max_pids is accepted but not enforced via RLIMIT_NPROC
    // This is by design - use Linux cgroups for proper pid limiting
    let result = sandbox.run("sh", &["-c", "echo ok"]).unwrap();
    assert_eq!(result.exit_code, 0);
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
        assert!(
            limit <= 20,
            "RLIMIT_NOFILE should be 20, got {}",
            limit
        );
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
    use std::path::Path;

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

/// Test: OOM kills should be detected via cgroup memory.events (Linux)
///
/// Current bug: killed_by_oom is always false
/// Expected: killed_by_oom is true when process exceeds memory limit
#[test]
#[cfg(target_os = "linux")]
fn test_linux_oom_detection() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .memory_limit(32 * 1024 * 1024) // 32MB - very tight
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    // Force an OOM condition
    let result = sandbox.run("sh", &["-c", r#"
        # Allocate memory until we OOM
        data=""
        while true; do
            data="${data}$(head -c 1048576 /dev/zero | tr '\0' 'x')"
        done
    "#]).unwrap();

    // Should be killed (by OOM or timeout)
    assert!(
        result.exit_code != 0 || result.killed_by_timeout,
        "Process should have been killed"
    );

    // Ideally, killed_by_oom should be true
    // This test documents expected behavior once OOM detection is implemented
    if !result.killed_by_timeout {
        assert!(
            result.killed_by_oom,
            "OOM kill not detected. Exit code: {}, signal: {:?}",
            result.exit_code,
            result.signal
        );
    }
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
    let result = sandbox.run("sh", &["-c", r#"
        # Allocate ~10MB
        dd if=/dev/zero bs=1M count=10 2>/dev/null | cat > /dev/null
        echo "done"
    "#]).unwrap();

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
    let result = sandbox.run("sh", &["-c", r#"
        # Burn some CPU
        i=0
        while [ $i -lt 100000 ]; do
            i=$((i + 1))
        done
        echo "done"
    "#]).unwrap();

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

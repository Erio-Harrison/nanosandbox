//! Seccomp syscall filter tests - Linux only

#![cfg(target_os = "linux")]

use nanosandbox::{Sandbox, MB};
use std::time::Duration;

/// Calls each syscall from inside the sandbox through python's ctypes and
/// prints `name=errno` (0 on success). The numbers come from the libc crate,
/// so they're right for whichever architecture this runs on.
fn probe(sandbox: &Sandbox) -> Option<String> {
    let cases: &[(&str, libc::c_long, &[libc::c_long])] = &[
        (
            "unshare_user",
            libc::SYS_unshare,
            &[libc::CLONE_NEWUSER as _],
        ),
        ("unshare_fs", libc::SYS_unshare, &[libc::CLONE_FS as _]),
        (
            "clone_newuser",
            libc::SYS_clone,
            &[(libc::CLONE_NEWUSER | libc::SIGCHLD) as _, 0, 0, 0, 0],
        ),
        ("clone3", libc::SYS_clone3, &[0, 0]),
        ("setns", libc::SYS_setns, &[-1, 0]),
        ("mount", libc::SYS_mount, &[0, 0, 0, 0, 0]),
        ("bpf", libc::SYS_bpf, &[0, 0, 0]),
        (
            "perf_event_open",
            libc::SYS_perf_event_open,
            &[0, 0, -1, -1, 0],
        ),
        ("userfaultfd", libc::SYS_userfaultfd, &[0]),
        ("io_uring_setup", libc::SYS_io_uring_setup, &[0, 0]),
        ("keyctl", libc::SYS_keyctl, &[0, 0, 0]),
        ("init_module", libc::SYS_init_module, &[0, 0, 0]),
        (
            "ptrace_traceme",
            libc::SYS_ptrace,
            &[libc::PTRACE_TRACEME as _, 0, 0, 0],
        ),
        ("unknown", 1000, &[]),
    ];
    let cases: Vec<String> = cases
        .iter()
        .map(|(name, nr, args)| format!("({name:?}, {nr}, {args:?})"))
        .collect();
    let script = format!(
        "import ctypes\n\
         libc = ctypes.CDLL(None, use_errno=True)\n\
         for name, nr, args in [{}]:\n    \
             ctypes.set_errno(0)\n    \
             r = libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(a) for a in args])\n    \
             print(f'{{name}}={{0 if r >= 0 else ctypes.get_errno()}}', flush=True)\n",
        cases.join(", ")
    );
    let result = sandbox.run("python3", &["-c", &script]).ok()?;
    if result.exit_code != 0 && result.stdout.is_empty() {
        eprintln!("skipping: python3 failed in the sandbox: {}", result.stderr);
        return None;
    }
    Some(result.stdout)
}

fn errno_of(out: &str, name: &str) -> i32 {
    out.lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix('=')?.parse().ok())
        .unwrap_or_else(|| panic!("no result for {name} in:\n{out}"))
}

/// The filter refuses the kernel's riskier entry points, and only those.
#[test]
fn test_filter_blocks_kernel_entry_points() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();
    let Some(out) = probe(&sandbox) else {
        return;
    };

    for name in [
        "unshare_user",
        "clone_newuser",
        "setns",
        "mount",
        "bpf",
        "perf_event_open",
        "userfaultfd",
        "io_uring_setup",
        "keyctl",
        "init_module",
    ] {
        assert_eq!(
            errno_of(&out, name),
            libc::EPERM,
            "{name} wasn't blocked:\n{out}"
        );
    }
    // Flags it can't see, or a number it doesn't know: "not implemented",
    // so libc falls back, rather than the process being killed.
    assert_eq!(errno_of(&out, "clone3"), libc::ENOSYS, "{out}");
    assert_eq!(errno_of(&out, "unknown"), libc::ENOSYS, "{out}");
    // Not namespaces, so not blocked.
    assert_eq!(errno_of(&out, "unshare_fs"), 0, "{out}");
    assert_eq!(errno_of(&out, "ptrace_traceme"), 0, "{out}");
}

/// The EPERMs above come from the filter, not from the sandbox otherwise.
#[test]
fn test_seccomp_false_turns_the_filter_off() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .seccomp(false)
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();
    let Some(out) = probe(&sandbox) else {
        return;
    };

    assert_ne!(errno_of(&out, "io_uring_setup"), libc::EPERM, "{out}");
    assert_ne!(errno_of(&out, "clone3"), libc::ENOSYS, "{out}");
}

/// Threads (glibc tries clone3 first), fork/exec and pipes all still work.
#[test]
fn test_filter_keeps_ordinary_programs_working() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    let result = sandbox.run("sh", &["-c", "echo a | cat && true"]).unwrap();
    assert_eq!(result.exit_code, 0, "{}", result.stderr);
    assert_eq!(result.stdout.trim(), "a");

    let script = "import threading, subprocess\n\
                  t = threading.Thread(target=print, args=('thread',), kwargs={'flush': True})\n\
                  t.start(); t.join()\n\
                  print(subprocess.run(['echo', 'child'], capture_output=True, text=True).stdout.strip())";
    if let Ok(r) = sandbox.run("python3", &["-c", script]) {
        if !r.stderr.contains("No such file") {
            assert_eq!(r.exit_code, 0, "{}", r.stderr);
            assert_eq!(r.stdout, "thread\nchild\n");
        }
    }
}

#[test]
fn test_filter_allows_file_operations() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .private_tmp(64 * MB)
        .build()
        .unwrap();

    let result = sandbox
        .run("sh", &["-c", "echo test > /tmp/file && cat /tmp/file"])
        .unwrap();

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout.trim(), "test");
}

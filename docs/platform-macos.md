# macOS Platform Implementation

## Technology Stack

macOS uses **sandbox-exec** (Seatbelt) for sandboxing:

```
┌─────────────────────────────────────────┐
│              MacOSExecutor               │
├─────────────────────────────────────────┤
│     sandbox-exec -p "SBPL Profile"      │
├─────────────────────────────────────────┤
│   Sandbox Profile Language (SBPL)        │
│   - File access rules                    │
│   - Network access rules                 │
│   - IPC rules                            │
│   - Mach service rules                   │
└─────────────────────────────────────────┘
```

## sandbox-exec Introduction

sandbox-exec is macOS's built-in sandbox tool, using SBPL (Sandbox Profile Language) to define rules:

```bash
# Basic usage
sandbox-exec -p "(version 1)(deny default)(allow file-read*)" /bin/ls
```

## SBPL Syntax

### Basic Structure

```lisp
(version 1)                    ; Version declaration
(deny default)                 ; Deny all by default
(allow process-fork)           ; Allow fork
(allow process-exec)           ; Allow exec
```

### File Access Rules

```lisp
; Allow reading entire directory tree
(allow file-read* (subpath "/usr"))

; Allow read-write to specific directory
(allow file-write* (subpath "/tmp"))

; Allow reading a single file
(allow file-read* (literal "/etc/passwd"))
```

### Network Rules

```lisp
; Allow all network
(allow network*)

; Deny network (default)
; Simply don't add network rules
```

### Mach Service Rules

```lisp
; Required for inter-process communication
(allow mach-lookup)
(allow mach-register)
```

## Nanosandbox Implementation

`MacOSExecutor::execute()` (`src/platform/macos/mod.rs`) builds the SBPL
profile, spawns `sandbox-exec -p <profile> -D key=value... -- cmd args...`,
and waits for the result. Split across a few files by subsystem:

- `mod.rs`: `execute()`/`check_support()`, the resource-limit `pre_exec`
  closure, and `FORK_LOCK`/`cloexec_pipe` (see Process Lifetime below).
- `profile.rs`: `generate_profile()`.
- `wait.rs`: the wait loop, process-tree killing, memory polling.
- `watchdog.rs`, `run_marker.rs`: see their own sections below.

### Profile Generation

`generate_profile()` returns the policy text plus a list of `-D key=value`
pairs, not a single self-contained string: every path from the config
(writable roots, denied-read paths, the run's marker files) becomes a
parameter referenced as `(param "KEY")`, never spliced into the policy text
directly. A mount source containing something that looks like SBPL (e.g. a
path literally named `x") (allow file-write* (subpath "/`) can't be parsed
as a rule that way -- it's always just a string value.

## Process Lifetime

macOS has nothing like Linux's `PR_SET_PDEATHSIG` (see
[platform-linux.md](platform-linux.md)), so a sandbox used to keep running
after a crashed or killed host process, with nothing left to enforce its
time limit. A small watchdog process stands in: it holds the read end of a
pipe whose write end only the host process has, and kills the run's process
group the moment that pipe closes -- whether the host closed it on an
ordinary run end or died and took it down with it. See
`src/platform/macos/watchdog.rs`.

Every pipe this crate opens for itself (the watchdog's, and the one the
child reports a rejected `setrlimit` over) goes through one `cloexec_pipe`
helper, holding `FORK_LOCK` for writing around `pipe()`+`fcntl()`: macOS
has no atomic `pipe2(O_CLOEXEC)`, so a concurrent `execute()` call forking
in that gap would otherwise inherit a plain copy, leaking it into an
unrelated sandboxed process. Confirmed for real: ~1 in 5 tries without the
lock.

## Feature Limitations

### Compared to Linux

| Feature | Linux | macOS | Reason |
|---------|-------|-------|--------|
| Hard memory limit | ✅ cgroups | ❌ | macOS has no cgroups |
| CPU limit | ✅ cgroups | ❌ | macOS has no cgroups |
| Process limit | ✅ cgroups | ❌ | macOS has no cgroups |
| PID isolation | ✅ namespace | ❌ | macOS has no namespaces |
| User mapping | ✅ user ns | ❌ | macOS has no namespaces |
| Filesystem isolation | ✅ mount ns | ⚠️ SBPL | SBPL is policy, not isolation |
| Network isolation | ✅ network ns | ⚠️ SBPL | SBPL is policy, not isolation |

### tmpfs

macOS has no tmpfs and no mount namespace, so there's no giving one process
its own directory at a path, and no `tmpfs()`, `bind()` or `rootfs()`.

`private_tmp(size)`, on by default, is a fresh directory per run, readable only by
the calling user, with `TMPDIR` pointing to it (unless `env` sets `TMPDIR`).
Programs that use `TMPDIR` get what the tmpfs promises: private to the run,
removed afterwards, and limited to `size`. The size is measured every 250ms
while the program runs, and the program is killed if it's over
(`ExecutionResult::killed_by_tmp_limit`), since nothing can make a write
fail with `ENOSPC` here. A short burst can go over before the next check,
but not fill the disk.

If the host process is killed, its directory is left behind. Each directory
holds an exclusive `flock` for the run, which the kernel drops when the
process dies however it dies. Whichever process next creates a directory
(at most every 5 minutes) removes the ones in `$TMPDIR` that are named
`nanosandbox-tmp-*`, are real directories of its own uid, are over 2 minutes
old, and whose lock it can take. A directory a live agent holds is never
touched, so several agents on one machine don't affect each other. A process
ID is never used for this: it can be reused, or belong to another namespace.
It looks in `$TMPDIR` and the system's default temp directory, since `TMPDIR`
may have been different when the dead run started. To do it now, call
`nanosandbox::clean_stale_tmp()` or run `nanosandbox-mcp --clean-tmp`. File
systems that can't lock (some NFS mounts) are never swept, and another user's
directories are left to that user.

A program that writes to `/tmp` by name gets the host's `/tmp`. By default
that stays writable, because making it read-only breaks some programs (below).

Apple's developer tools launched through `xcrun` (`/usr/bin/python3`,
`/usr/bin/clang`, `cc`, `make`, `git` and the rest of the `/usr/bin` shims)
reset `TMPDIR` to the user's own temp directory (`/var/folders/.../T/`) when
they run inside `sandbox-exec`, and so don't use the private one. The same
tools outside the sandbox, or run by their real path under
`/Library/Developer/CommandLineTools/usr/bin`, keep it; so do Homebrew's and
other non-`xcrun` programs. That directory is writable by default, as it
was before.

#### `shared_tmp(false)`

With the default, `/tmp`, `/private/tmp`, `/private/var/tmp` and
`/private/var/folders` are the host's own: a program writing there leaves
the file after the run, other sandboxes see it, and it can modify the user's
other temp files. `shared_tmp(false)` (`--strict-tmp` in `nanosandbox-mcp`)
makes them read-only, leaving only the run's private directory writable. It
needs `private_tmp`, which is on unless turned off.

Tried on 15 common cases, three break:

- A program that writes to `/tmp` by name (`Operation not permitted`).
- `mktemp -t`, which uses the user's own temp directory, not `$TMPDIR`.
  `mktemp "$TMPDIR/x.XXXXXX"` works.
- The `xcrun` shims that need a scratch file, `/usr/bin/clang` and `cc`
  (`unable to make temporary file`). Compile with the real binary instead:
  `$(xcode-select -p)/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang -isysroot $(xcrun --show-sdk-path) ...`.

Working: Python and Node by their real paths or from Homebrew, `git`
(`/usr/bin` and Homebrew), `make`, shell here-documents, `$TMPDIR` by hand.
One that works differently: `/usr/bin/python3` is a shim, so `tempfile`
finds nothing writable in `TMPDIR`, `/tmp` or `/var/tmp` and falls back to
the working directory, so its temp files land in the workspace.

That list is the 15 cases tried, not a guarantee: `swiftc`, `ld`,
`xcodebuild` and anything that needs the network weren't. Linux has no
equivalent option, since there `/tmp`, `/var/tmp` and `/dev/shm` already get
a private tmpfs per run where the kernel allows mounting.

### Local servers

A sandboxed program can neither bind a loopback port nor connect to one
(`Operation not permitted`), the host's included. That's deliberate: the host
shares its loopback with the sandbox, so allowing it would let the program
reach the user's databases, dev servers and anything else listening on
`127.0.0.1`. The proxy's own port is the only exception. The cost is that a
program can't start a server and test it in the same run, and test suites that
open a local socket fail. Linux has a network namespace of its own, so there
loopback can be private to the sandbox (see
[platform-linux.md](platform-linux.md#network-namespace)).

### Process Cleanup

When a run ends, by exiting, a timeout or the memory limit, every process
it started is killed. Walking the process tree from the first process isn't
enough: a child that leaves the process group (`setpgrp`) and outlives its
parent belongs to launchd by then, and there are no cgroups to find it by.

What every process of a run keeps is its sandbox, which it can't leave. So
each run's profile denies `file-read-metadata` on one file made for that
run, and allows it on a second one next to it. At the end, `sandbox_check`
asks each of the user's sandboxed processes about both, and the ones denied
the first and allowed the second are the run's. Asking about only one isn't
enough: apps' own sandboxes can't read the temp directory at all. If the
check doesn't behave as expected on this process itself, nothing is killed.

The same lookup also finds every process of the run *while it's still
running*, for `memory_limit`'s own periodic check (below): walking the
process tree from the root the same way used to miss a daemonized
descendant's memory entirely, for as long as the run lasted -- confirmed
for real, a double fork into 300MB with a 64MB limit finished clean.

### Reading

The profile allows reading everything, then denies `file-read-data` (file
contents and directory listings) for credentials in the home directory,
`deny_read` paths, and with `hide_home` the whole home directory. Paths the
config names inside those are allowed again with `file-read-data`: an allow
of `file-read*` doesn't override a deny of the more specific operation,
whatever the order.

### Resource Limits

`max_open_files`, `max_file_size` and `cpu_time_limit` are plain
`setrlimit` calls (`RLIMIT_NOFILE`, `RLIMIT_FSIZE`, `RLIMIT_CPU`), applied
from `Command::pre_exec` between `fork()` and `exec()`.

`memory_limit` can't go through `setrlimit`: the kernel rejects
`RLIMIT_AS`. Instead, the wait loop polls physical footprint
(`proc_pid_rusage`) summed over every process of the run (see Process
Cleanup, above) every 2-10 ms, and kills the run once it's over.
`RLIMIT_NPROC` for `max_pids` isn't used either, for an unrelated reason:
it counts every process the user has, not just the sandbox's -- there's no
macOS equivalent to cgroups' `pids.max`, so `max_pids` is refused instead
of accepted and not enforced.

## Security Model

### sandbox-exec Limitations

1. **Deprecation warning**: Apple marked sandbox-exec as deprecated in macOS 10.15+
2. **Incomplete isolation**: SBPL is policy checking, not true isolation
3. **Cannot limit resources**: Can only limit access, not resource usage

### Recommendations

For production macOS sandboxing, consider:

1. **Use virtualization**: Such as Virtualization.framework
2. **Containerization**: Use Docker Desktop for Mac
3. **Limit use cases**: Only use for development/testing environments

## Testing

```rust
#[test]
fn test_macos_sandbox_file_restriction() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .build()
        .unwrap();

    // Can read system files
    let result = sandbox.run("cat", &["/etc/passwd"]);
    assert!(result.is_ok());

    // Cannot write to system files (if SBPL configured correctly)
    let result = sandbox.run("touch", &["/etc/test"]);
    assert!(result.unwrap().exit_code != 0);
}

#[test]
fn test_macos_sandbox_network() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .no_network()
        .build()
        .unwrap();

    // Network should be blocked
    let result = sandbox.run("curl", &["https://example.com"]);
    assert!(result.unwrap().exit_code != 0);
}
```

## References

- [Apple Sandbox Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/)
- [SBPL Syntax Reference](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf)
- [sandbox-exec man page](https://www.manpagez.com/man/1/sandbox-exec/)

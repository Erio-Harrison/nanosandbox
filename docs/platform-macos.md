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

### MacOSExecutor

```rust
pub struct MacOSExecutor {
    _private: (),
}

impl PlatformExecutor for MacOSExecutor {
    fn execute(
        &self,
        config: &SandboxConfig,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<ExecutionResult> {
        // 1. Generate SBPL profile
        let profile = self.generate_profile(config);

        // 2. Execute using sandbox-exec
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.arg("-p").arg(&profile);
        command.arg(cmd);
        command.args(args);

        // 3. Set environment and working directory
        command.current_dir(&config.working_dir);

        // 4. Execute and wait for result
        // ...
    }
}
```

### Profile Generation

```rust
fn generate_profile(&self, config: &SandboxConfig) -> String {
    let mut profile = String::new();

    // Basic rules
    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n");

    // Process operations
    profile.push_str("(allow process-fork)\n");
    profile.push_str("(allow process-exec)\n");

    // Mach services
    profile.push_str("(allow mach-lookup)\n");

    // File reading (allow reading from anywhere)
    profile.push_str("(allow file-read* (subpath \"/\"))\n");

    // File writing (only allow specific directories)
    profile.push_str("(allow file-write* (subpath \"/tmp\"))\n");

    // Write permissions for custom mount points
    for mount in &config.mounts {
        if mount.permission == Permission::ReadWrite {
            profile.push_str(&format!(
                "(allow file-write* (subpath \"{}\"))\n",
                mount.source.to_string_lossy()
            ));
        }
    }

    // Network rules
    match &config.network_mode {
        NetworkMode::None => { /* Deny by default */ }
        NetworkMode::Host => {
            profile.push_str("(allow network*)\n");
        }
    }

    profile
}
```

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

A program that writes to `/tmp` by name gets the host's `/tmp`. Making that
read-only instead would break it.

Apple's developer tools launched through `xcrun` (`/usr/bin/python3`,
`/usr/bin/clang`, `cc`, `make`, `git` and the rest of the `/usr/bin` shims)
reset `TMPDIR` to the user's own temp directory (`/var/folders/.../T/`) when
they run inside `sandbox-exec`, and so don't use the private one. The same
tools outside the sandbox, or run by their real path under
`/Library/Developer/CommandLineTools/usr/bin`, keep it; so do Homebrew's and
other non-`xcrun` programs. That directory is writable by default, as it
was before.

### Resource Limit Alternatives

macOS can use `setrlimit` to provide soft limits:

```rust
// Called from Command::pre_exec, after fork() but before exec()
fn apply_resource_limits(config: &SandboxConfig) {
    if let Some(memory) = config.memory_limit {
        let rlim = libc::rlimit { rlim_cur: memory, rlim_max: memory };
        unsafe { libc::setrlimit(libc::RLIMIT_AS, &rlim) };
    }
}
```

However, these are **soft limits** and may be ignored by processes.

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

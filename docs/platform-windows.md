# Windows Platform Implementation

## Technology Stack

Windows uses Job Objects and Restricted Tokens for sandboxing:

```
┌─────────────────────────────────────────┐
│            WindowsExecutor               │
├─────────────────────────────────────────┤
│   ┌─────────────┐  ┌─────────────────┐  │
│   │ Job Objects │  │ Restricted      │  │
│   │ (Resources) │  │ Tokens (Perms)  │  │
│   └─────────────┘  └─────────────────┘  │
├─────────────────────────────────────────┤
│              Windows API                 │
└─────────────────────────────────────────┘
```

## Job Objects

Job Objects are the core of Windows process group management:

### Features

| Feature | API |
|---------|-----|
| Memory limit | `ProcessMemoryLimit` |
| CPU limit | `CpuRateControlInformation` |
| Process count limit | `ActiveProcessLimit` |
| Process termination | `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` |

### Implementation

```rust
impl WindowsExecutor {
    #[cfg(windows)]
    fn apply_job_limits(
        &self,
        child: &std::process::Child,
        config: &SandboxConfig,
    ) -> Result<()> {
        use windows::Win32::System::JobObjects::*;

        unsafe {
            // Create Job Object
            let job = CreateJobObjectW(None, None)?;

            // Set basic limits
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            // Memory limit
            if let Some(memory) = config.memory_limit {
                limits.BasicLimitInformation.LimitFlags |=
                    JOB_OBJECT_LIMIT_PROCESS_MEMORY;
                limits.ProcessMemoryLimit = memory as usize;
            }

            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _,
                std::mem::size_of_val(&limits) as u32,
            )?;

            // CPU limit
            if let Some(cpu) = config.cpu_limit {
                let cpu_rate = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
                    ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
                        | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                    CpuRate: (cpu * 10000.0) as u32,
                };

                SetInformationJobObject(
                    job,
                    JobObjectCpuRateControlInformation,
                    &cpu_rate as *const _ as *const _,
                    std::mem::size_of_val(&cpu_rate) as u32,
                )?;
            }

            // Add process to Job
            let process_handle = child.as_raw_handle();
            AssignProcessToJobObject(job, process_handle)?;
        }

        Ok(())
    }
}
```

## Restricted Tokens

Restricted Tokens are used to lower process privileges:

### Features

| Feature | Description |
|---------|-------------|
| Disable SIDs | Remove group memberships |
| Restrict SIDs | Limit access checks |
| Delete privileges | Remove admin privileges |

### Implementation (Conceptual)

```rust
// Note: Full implementation requires more types from windows-rs
fn create_restricted_token() -> Result<HANDLE> {
    unsafe {
        let mut token = HANDLE::default();

        // Get current process token
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ALL_ACCESS,
            &mut token
        )?;

        // Create restricted token
        let mut restricted_token = HANDLE::default();
        CreateRestrictedToken(
            token,
            DISABLE_MAX_PRIVILEGE,  // Disable privileges
            0,                       // Number of SIDs to disable
            std::ptr::null(),        // SIDs to disable
            0,                       // Number of privileges to delete
            std::ptr::null(),        // Privileges to delete
            0,                       // Number of SIDs to restrict
            std::ptr::null(),        // SIDs to restrict
            &mut restricted_token
        )?;

        Ok(restricted_token)
    }
}
```

## What's Enforced Today

Only the Job Object's memory and CPU limits. The process runs as the calling
user, with that user's file system and network access; Restricted Tokens and
AppContainer below are design notes, not implemented. So `build()` refuses
what can't be enforced instead of quietly running without it:

- `no_network()` (the default) and `allow_network()`: call `host_network()`.
- `rootfs`, `mount` and `tmpfs`.

## Feature Limitations

### Compared to Linux

| Feature | Linux | Windows | Notes |
|---------|-------|---------|-------|
| Filesystem isolation | ✅ mount ns | ⚠️ Limited | Can only restrict access, not isolate |
| Network isolation | ✅ network ns | ❌ | Windows has no network namespaces |
| PID isolation | ✅ PID ns | ❌ | Windows has no PID isolation |
| Memory limit | ✅ cgroups | ✅ Job | Equivalent functionality |
| CPU limit | ✅ cgroups | ✅ Job | Equivalent functionality |
| Process count limit | ✅ cgroups | ✅ Job | Equivalent functionality |

### Windows-Specific Issues

1. **No true process isolation**: Child processes can see all processes in the system
2. **No network namespaces**: Cannot create isolated network environments
3. **Limited filesystem restrictions**: Mainly relies on ACLs, not isolation

## AppContainer (Optional)

Windows 8+ provides AppContainer for stronger isolation:

```rust
// AppContainer provides stronger isolation
// But requires special manifest and permission configuration
fn create_app_container() -> Result<()> {
    // 1. Create AppContainer profile
    // 2. Set capabilities
    // 3. Start process in container
    todo!()
}
```

AppContainer provides:
- Filesystem isolation (can only access AppContainer directory)
- Registry isolation
- Network restrictions (requires capability declaration)

However, implementation complexity is high, and the current version does not implement this.

## Testing

```rust
#[cfg(windows)]
#[test]
fn test_windows_job_memory_limit() {
    let sandbox = Sandbox::builder()
        .memory_limit(100 * MB)
        .build()
        .unwrap();

    // Try to allocate more memory than the limit
    let result = sandbox.run("cmd", &[
        "/c",
        "powershell",
        "-Command",
        "[byte[]]$a = New-Object byte[] 200MB"
    ]);

    // Should fail or be terminated
    assert!(!result.unwrap().success());
}

#[cfg(windows)]
#[test]
fn test_windows_job_timeout() {
    let sandbox = Sandbox::builder()
        .wall_time_limit(Duration::from_secs(1))
        .build()
        .unwrap();

    let result = sandbox.run("cmd", &["/c", "timeout", "10"]).unwrap();

    assert!(result.killed_by_timeout);
}
```

## References

- [Job Objects](https://docs.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [Access Tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [AppContainer Isolation](https://docs.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
- [Windows Sandbox](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-overview)

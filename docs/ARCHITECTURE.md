# Nanosandbox Architecture

This document describes the internal architecture of nanosandbox and how it implements sandboxing on each platform.

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      User Application                        │
├─────────────────────────────────────────────────────────────┤
│                    nanosandbox Public API                        │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │   Sandbox   │  │SandboxBuilder│  │ ExecutionResult   │  │
│  └─────────────┘  └──────────────┘  └───────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                   Platform Abstraction                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  PlatformExecutor                    │   │
│  │         execute(config) -> ExecutionResult           │   │
│  └─────────────────────────────────────────────────────┘   │
├──────────────┬──────────────────┬───────────────────────────┤
│    Linux     │      macOS       │         Windows           │
│  ┌────────┐  │  ┌────────────┐  │  ┌─────────────────┐     │
│  │Namespace│  │  │sandbox-exec│  │  │   Job Objects   │     │
│  │Cgroups  │  │  │   (SBPL)   │  │  │Restricted Token │     │
│  │Seccomp  │  │  │ setrlimit  │  │  └─────────────────┘     │
│  └────────┘  │  └────────────┘  │                           │
└──────────────┴──────────────────┴───────────────────────────┘
```

## Core Components

### 1. SandboxBuilder

Builder pattern for configuring sandbox parameters:

```rust
pub struct SandboxBuilder {
    config: SandboxConfig,
}

pub struct SandboxConfig {
    // Filesystem
    pub mounts: Vec<Mount>,
    pub tmpfs_mounts: Vec<(PathBuf, u64)>,
    pub working_dir: PathBuf,
    pub rootfs: Option<PathBuf>,

    // Resource limits
    pub memory_limit: Option<u64>,      // bytes
    pub cpu_limit: Option<f64>,         // CPU cores (0.0-N.0)
    pub wall_time_limit: Option<Duration>,
    pub cpu_time_limit: Option<Duration>,
    pub max_pids: Option<u32>,
    pub max_file_size: Option<u64>,
    pub max_open_files: Option<u32>,

    // Network
    pub network_mode: NetworkMode,      // None/Host/Proxied

    // Security
    pub seccomp_profile: SeccompProfile,
    pub uid: Option<u32>,
    pub gid: Option<u32>,

    // Environment
    pub env: HashMap<String, String>,
    pub clear_env: bool,
    pub hostname: String,
}
```

### 2. Sandbox

Main execution unit. Each Sandbox instance has a unique ID.

```rust
pub struct Sandbox {
    config: SandboxConfig,
    id: String,                          // "<unix_timestamp>-<counter>"
    executor: Box<dyn PlatformExecutor>,
}
```

There is no separate `NetworkManager` field: the `Proxied` network mode is set up
per-execution inside each platform executor's `execute()` call.

### 3. PlatformExecutor Trait

Platform abstraction layer:

```rust
pub trait PlatformExecutor: Send + Sync {
    fn execute(
        &self,
        config: &SandboxConfig,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<ExecutionResult>;

    fn check_support(&self, config: &SandboxConfig) -> Result<()>;
}
```

---

## Linux Implementation

Linux provides the strongest isolation using kernel namespaces, cgroups v2, and seccomp-BPF.

### Namespaces

```
┌─────────────────────────────────────────────┐
│              Parent Process                  │
│                                             │
│  clone(CLONE_NEWUSER | CLONE_NEWPID |      │
│        CLONE_NEWNS | CLONE_NEWUTS |        │
│        CLONE_NEWIPC | CLONE_NEWNET)        │
│                    │                        │
│                    ▼                        │
│  ┌─────────────────────────────────────┐   │
│  │         Child (PID 1 in ns)         │   │
│  │                                     │   │
│  │  UID namespace: 0 (root in ns)     │   │
│  │  PID namespace: isolated           │   │
│  │  Mount namespace: private mounts   │   │
│  │  Network namespace: no network     │   │
│  │  UTS namespace: custom hostname    │   │
│  │  IPC namespace: isolated IPC       │   │
│  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

**Namespace Types:**

| Namespace | Flag | Purpose |
|-----------|------|---------|
| User | `CLONE_NEWUSER` | UID/GID mapping, unprivileged containers |
| PID | `CLONE_NEWPID` | Process isolation, child is PID 1 |
| Mount | `CLONE_NEWNS` | Private mount table |
| Network | `CLONE_NEWNET` | Network isolation (optional) |
| UTS | `CLONE_NEWUTS` | Hostname isolation |
| IPC | `CLONE_NEWIPC` | IPC isolation |

### Cgroups v2

Resource limiting via unified cgroup hierarchy:

```
/sys/fs/cgroup/
└── nanobox/
    └── sandbox-{id}/
        ├── cgroup.procs      # Add process PID here
        ├── cgroup.freeze     # Freeze for cleanup
        ├── memory.max        # Memory limit (bytes)
        ├── memory.high       # Soft limit (90% of max)
        ├── memory.current    # Current usage
        ├── memory.peak       # Peak usage
        ├── memory.events     # OOM events (oom_kill counter)
        ├── cpu.max           # CPU quota (quota period)
        ├── cpu.stat          # CPU statistics (usage_usec)
        └── pids.max          # Process limit
```

**Cgroup Lifecycle:**

```rust
impl CgroupManager {
    // 1. Create cgroup directory
    pub fn create(sandbox_id: &str) -> Result<Self>;

    // 2. Set limits
    pub fn set_memory_limit(&self, bytes: u64) -> Result<()>;
    pub fn set_cpu_limit(&self, cpus: f64) -> Result<()>;
    pub fn set_pids_limit(&self, max: u32) -> Result<()>;

    // 3. Add process
    pub fn add_process(&self, pid: u32) -> Result<()>;

    // 4. Collect stats (before cleanup!)
    pub fn get_memory_stats(&self) -> Result<MemoryStats>;
    pub fn get_cpu_stats(&self) -> Result<CpuStats>;
    pub fn was_oom_killed(&self) -> bool;

    // 5. Cleanup
    pub fn cleanup(&self) {
        self.kill_all();  // Freeze + SIGKILL all
        fs::remove_dir(&self.path);
    }
}
```

### OOM Detection

```rust
// Read /sys/fs/cgroup/nanobox/{id}/memory.events
// Format: "oom 0\noom_kill 1\noom_group_kill 0\n"
pub fn was_oom_killed(&self) -> bool {
    self.get_memory_events()
        .map(|e| e.oom_kill > 0 || e.oom_group_kill > 0)
        .unwrap_or(false)
}
```

### Execution Flow (Linux)

```
1. Create cgroup
2. Set resource limits (memory.max, cpu.max, pids.max)
3. clone() with namespace flags
4. Child:
   a. Pivot root to new filesystem
   b. Apply seccomp filter (if enabled)
   c. execve() target command
5. Parent:
   a. Add child to cgroup
   b. Wait with timeout
   c. On timeout: kill(-pid, SIGKILL) entire process group
   d. Collect stats from cgroup
   e. Cleanup cgroup
```

---

## macOS Implementation

macOS uses `sandbox-exec` with Seatbelt Profile Language (SBPL) for sandboxing.

### Architecture

```
┌─────────────────────────────────────────────┐
│              Parent Process                  │
│                                             │
│  1. Generate SBPL profile string            │
│  2. fork()                                  │
│                    │                        │
│                    ▼                        │
│  ┌─────────────────────────────────────┐   │
│  │           Child Process              │   │
│  │                                     │   │
│  │  pre_exec:                          │   │
│  │    setpgid(0, 0)  // New process group│   │
│  │    setrlimit(RLIMIT_AS, memory)     │   │
│  │    setrlimit(RLIMIT_NOFILE, fds)    │   │
│  │                                     │   │
│  │  exec: sandbox-exec -p "profile"    │   │
│  │        /bin/sh -c "command"         │   │
│  └─────────────────────────────────────┘   │
│                                             │
│  Parent waits with wait4() for rusage      │
└─────────────────────────────────────────────┘
```

### SBPL Profile Generation

Dynamic profile based on SandboxConfig:

```scheme
(version 1)
(deny default)

;; Allow basic operations
(allow process-fork)
(allow process-exec)
(allow signal (target self))

;; File system rules (based on mounts)
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/Library"))
(allow file-read* (subpath "/bin"))
(allow file-read* (subpath "/sbin"))
(allow file-read* (subpath "/private/var"))
(allow file-read* (subpath "/private/tmp"))

;; Working directory
(allow file-read* file-write* (subpath "/tmp/sandbox"))

;; User mounts
(allow file-read* (subpath "/data/input"))    ;; READ_ONLY
(allow file-read* file-write* (subpath "/data/output"))  ;; READ_WRITE

;; Network rules
;; NetworkMode::None -> no network rules (deny by default)
;; NetworkMode::Host -> (allow network*)
;; NetworkMode::Whitelist -> (allow network* (remote ip "127.0.0.1:*"))
```

### Resource Limits (setrlimit)

```rust
fn apply_resource_limits(config: &SandboxConfig) {
    // Memory limit (RLIMIT_AS = address space)
    if let Some(bytes) = config.memory_limit {
        setrlimit(RLIMIT_AS, bytes, bytes);
    }

    // File descriptor limit
    if let Some(fds) = config.max_open_files {
        setrlimit(RLIMIT_NOFILE, fds, fds);
    }

    // Note: RLIMIT_NPROC affects entire user, not used
}
```

### Process Group Management

Critical for killing all child processes on timeout:

```rust
// In pre_exec (child, before exec)
unsafe {
    libc::setpgid(0, 0);  // Create new process group, child is leader
}

// On timeout (parent)
fn kill_process_group(pid: i32) {
    unsafe {
        libc::kill(-pid, libc::SIGKILL);  // Negative PID = process group
    }
}
```

### Resource Collection (wait4)

```rust
let mut rusage: libc::rusage = std::mem::zeroed();
let mut status: i32 = 0;

loop {
    let result = libc::wait4(child_pid, &mut status, WNOHANG, &mut rusage);
    if result == child_pid {
        break;  // Child exited
    }
    if timeout_elapsed {
        kill_process_group(child_pid);
    }
    sleep(10ms);
}

// Extract metrics
let peak_memory = rusage.ru_maxrss as u64;  // Bytes on macOS
let cpu_time = Duration::from_secs(rusage.ru_utime.tv_sec)
    + Duration::from_micros(rusage.ru_utime.tv_usec)
    + Duration::from_secs(rusage.ru_stime.tv_sec)
    + Duration::from_micros(rusage.ru_stime.tv_usec);
```

---

## Windows Implementation

Windows uses Job Objects and Restricted Tokens (basic implementation).

### Job Objects

```rust
// Create job object
let job = CreateJobObjectW(null(), null());

// Set limits
let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
limits.BasicLimitInformation.LimitFlags =
    JOB_OBJECT_LIMIT_PROCESS_MEMORY |
    JOB_OBJECT_LIMIT_JOB_MEMORY |
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

limits.ProcessMemoryLimit = memory_bytes;
limits.JobMemoryLimit = memory_bytes;
limits.BasicLimitInformation.ActiveProcessLimit = max_pids;

SetInformationJobObject(job, JobObjectExtendedLimitInformation, ...);

// Assign process to job
AssignProcessToJobObject(job, process_handle);
```

### Restricted Tokens

```rust
// Create restricted token from current token
let mut restricted_token = HANDLE::default();
CreateRestrictedToken(
    current_token,
    DISABLE_MAX_PRIVILEGE,  // Remove all privileges
    0, null(),              // SIDs to disable
    0, null(),              // Privileges to delete
    0, null(),              // Restricted SIDs
    &mut restricted_token,
);

// Create process with restricted token
CreateProcessAsUserW(restricted_token, ...);
```

---

## Network Proxy

Domain-based network filtering via HTTP proxy:

```
┌─────────────────────────────────────────────────────────┐
│                    Sandbox Process                       │
│                                                         │
│  HTTP_PROXY=http://127.0.0.1:PORT                      │
│  HTTPS_PROXY=http://127.0.0.1:PORT                     │
│                                                         │
│  curl https://api.example.com  ─────┐                  │
│                                      │                  │
└──────────────────────────────────────┼──────────────────┘
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────┐
│                   Proxy Server                           │
│              (runs in parent process)                    │
│                                                         │
│  1. Parse Host header / CONNECT target                  │
│  2. Check domain against whitelist                      │
│     - Exact match: api.example.com                      │
│     - Wildcard: *.example.com                           │
│  3. If allowed: forward request                         │
│     If blocked: return 403 Forbidden                    │
│                                                         │
└──────────────────────────────────────────────────────────┘
```

### Whitelist Matching

```rust
fn is_domain_allowed(host: &str, whitelist: &[String]) -> bool {
    let host_lower = host.to_lowercase();

    for pattern in whitelist {
        if pattern.starts_with("*.") {
            // Wildcard: *.example.com matches sub.example.com
            let suffix = &pattern[1..];  // .example.com
            if host_lower.ends_with(suffix) {
                return true;
            }
        } else {
            // Exact match
            if host_lower == pattern.to_lowercase() {
                return true;
            }
        }
    }
    false
}
```

### Known Limitation: IP Bypass

Direct IP connections bypass the proxy. Mitigation requires:
- Linux: iptables/nftables rules
- macOS: PF firewall rules
- Currently marked as P0 TODO

---

## Execution Result

```rust
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration: Duration,           // Wall clock time
    pub cpu_time: Option<Duration>,   // User + System CPU time
    pub peak_memory: Option<u64>,     // Peak RSS in bytes
    pub killed_by_timeout: bool,
    pub killed_by_oom: bool,          // Linux: cgroup, macOS: signal
    pub signal: Option<i32>,          // If killed by signal
}
```

---

## Thread Safety

- `Sandbox` is `Send + Sync`
- Sandbox ID uses `AtomicU64` counter
- Each sandbox has independent resources (cgroup, job object)
- Proxy runs on unique port per sandbox

---

## Error Handling

```rust
pub enum SandboxError {
    // Configuration errors
    ConfigValidation(String),

    // Platform-specific
    UnsupportedPlatform(String),

    // Linux
    NamespaceCreation(String),
    CgroupCreation(String),
    CgroupSetting { controller, setting, value, reason },

    // macOS
    SandboxProfile(String),

    // Execution
    CommandNotFound(String),
    PermissionDenied(String),
    Timeout,

    // Internal
    Internal(String),
    Io(std::io::Error),
}
```

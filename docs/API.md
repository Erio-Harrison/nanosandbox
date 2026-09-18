# Nanosandbox API Reference

Complete API documentation for the nanosandbox sandbox library.

## Table of Contents

- [Sandbox](#sandbox)
- [SandboxBuilder](#sandboxbuilder)
- [ExecutionResult](#executionresult)
- [Configuration Types](#configuration-types)
- [Error Types](#error-types)
- [Constants](#constants)
- [Platform Functions](#platform-functions)

---

## Sandbox

The main sandbox execution unit.

### Creating a Sandbox

```rust
use nanosandbox::{Sandbox, Permission, MB};
use std::time::Duration;

// Using builder
let sandbox = Sandbox::builder()
    .working_dir("/tmp")
    .memory_limit(512 * MB)
    .wall_time_limit(Duration::from_secs(30))
    .build()?;

// Using presets
let sandbox = Sandbox::code_judge("/submissions/123").build()?;
```

### Methods

#### `run`

Execute a command in the sandbox.

```rust
pub fn run(&self, command: &str, args: &[&str]) -> Result<ExecutionResult>
```

**Parameters:**
- `command` - Path to executable or command name
- `args` - Command arguments

**Returns:** `Result<ExecutionResult>`

**Example:**
```rust
let result = sandbox.run("python3", &["-c", "print('hello')"])?;
println!("stdout: {}", result.stdout);
println!("exit code: {}", result.exit_code);
```

#### `run_with_input`

Execute a command with stdin input.

```rust
pub fn run_with_input(
    &self,
    command: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
) -> Result<ExecutionResult>
```

**Example:**
```rust
let input = b"hello world";
let result = sandbox.run_with_input("cat", &[], Some(input))?;
assert_eq!(result.stdout, "hello world");
```

#### `id`

Get the unique sandbox identifier.

```rust
pub fn id(&self) -> u64
```

**Example:**
```rust
println!("Sandbox ID: {}", sandbox.id());
```

### Static Factory Methods (Presets)

#### `Sandbox::code_judge`

Preset for code judging systems. Strict limits, no network.

```rust
pub fn code_judge(code_dir: impl Into<PathBuf>) -> SandboxBuilder
```

**Configuration:**
- Memory: 256 MB
- Wall time: 10 seconds
- Max PIDs: 10
- Max open files: 20
- Network: None
- Security: Strict

**Example:**
```rust
let sandbox = Sandbox::code_judge("/submissions/123")
    .wall_time_limit(Duration::from_secs(5))  // Override default
    .build()?;
```

#### `Sandbox::agent_executor`

Preset for AI agent code execution. Moderate limits, optional network.

```rust
pub fn agent_executor(workspace: impl Into<PathBuf>) -> SandboxBuilder
```

**Configuration:**
- Memory: 1 GB
- Wall time: 60 seconds
- Max PIDs: 50
- Network: None (add with `.allow_network()`)
- Security: Standard

#### `Sandbox::data_analysis`

Preset for data analysis workloads.

```rust
pub fn data_analysis(
    input_dir: impl Into<PathBuf>,
    output_dir: impl Into<PathBuf>,
) -> SandboxBuilder
```

**Configuration:**
- Memory: 2 GB
- Wall time: 300 seconds
- Input: Read-only mount
- Output: Read-write mount
- Network: None

#### `Sandbox::interactive`

Preset for interactive/REPL sessions.

```rust
pub fn interactive(workspace: impl Into<PathBuf>) -> SandboxBuilder
```

**Configuration:**
- Memory: 512 MB
- Wall time: 3600 seconds (1 hour)
- Workspace: Read-write
- Security: Permissive

---

## SandboxBuilder

Builder for configuring sandbox parameters.

### Creation

```rust
let builder = Sandbox::builder();
// or
let builder = SandboxBuilder::new();
```

### Configuration Methods

All methods return `Self` for chaining.

#### `working_dir`

Set the working directory for command execution.

```rust
pub fn working_dir(self, path: impl Into<PathBuf>) -> Self
```

**Example:**
```rust
builder.working_dir("/tmp/sandbox")
```

#### `mount`

Mount a host path into the sandbox.

```rust
pub fn mount(
    self,
    source: impl Into<PathBuf>,
    target: impl Into<PathBuf>,
    permission: Permission,
) -> Self
```

**Parameters:**
- `source` - Host path
- `target` - Path inside sandbox
- `permission` - `ReadOnly` or `ReadWrite`

**Example:**
```rust
builder
    .mount("/data/input", "/input", Permission::ReadOnly)
    .mount("/data/output", "/output", Permission::ReadWrite)
```

#### `tmpfs`

Mount a temporary filesystem (RAM-backed).

```rust
pub fn tmpfs(self, path: impl Into<PathBuf>, size_bytes: u64) -> Self
```

**Example:**
```rust
builder.tmpfs("/tmp", 64 * MB)
```

#### `memory_limit`

Set maximum memory usage in bytes.

```rust
pub fn memory_limit(self, bytes: u64) -> Self
```

**Platform behavior:**
- Linux: Hard limit via cgroups (process killed on exceed)
- macOS: Soft limit via setrlimit (may be exceeded)
- Windows: Hard limit via Job Object

**Example:**
```rust
builder.memory_limit(512 * MB)
```

#### `cpu_limit`

Set CPU core limit.

```rust
pub fn cpu_limit(self, cpus: f64) -> Self
```

**Platform behavior:**
- Linux: Hard limit via cgroups cpu.max
- macOS: Not supported
- Windows: Hard limit via Job Object

**Example:**
```rust
builder.cpu_limit(1.5)  // 1.5 CPU cores
```

#### `wall_time_limit`

Set maximum wall clock time.

```rust
pub fn wall_time_limit(self, duration: Duration) -> Self
```

**Example:**
```rust
builder.wall_time_limit(Duration::from_secs(30))
```

#### `max_pids`

Set maximum number of processes/threads.

```rust
pub fn max_pids(self, n: u32) -> Self
```

**Platform behavior:**
- Linux: Hard limit via cgroups pids.max
- macOS: Not enforced (RLIMIT_NPROC affects entire user)
- Windows: Hard limit via Job Object

#### `max_open_files`

Set maximum number of open file descriptors.

```rust
pub fn max_open_files(self, n: u32) -> Self
```

#### `no_network`

Disable all network access.

```rust
pub fn no_network(self) -> Self
```

**Platform behavior:**
- Linux: Network namespace isolation
- macOS: SBPL network deny rules
- Windows: Not fully supported

#### `allow_network`

Allow network access only to specified domains.

```rust
pub fn allow_network(self, domains: &[&str]) -> Self
```

**Supports wildcards:**
- `"api.example.com"` - Exact match
- `"*.example.com"` - Wildcard subdomain

**Implementation:** HTTP proxy with domain whitelist.

**Example:**
```rust
builder.allow_network(&["api.openai.com", "*.github.com"])
```

#### `env`

Set an environment variable.

```rust
pub fn env(self, key: impl Into<String>, value: impl Into<String>) -> Self
```

**Example:**
```rust
builder
    .env("PATH", "/usr/bin:/bin")
    .env("HOME", "/tmp")
```

#### `hostname`

Set the hostname (Linux only).

```rust
pub fn hostname(self, name: impl Into<String>) -> Self
```

#### `seccomp_profile`

Set the security profile.

```rust
pub fn seccomp_profile(self, profile: SeccompProfile) -> Self
```

**Profiles:**
- `Strict` - Minimal syscalls allowed
- `Standard` - Common syscalls allowed
- `Permissive` - Most syscalls allowed
- `Disabled` - No restrictions

#### `build`

Create the sandbox instance.

```rust
pub fn build(self) -> Result<Sandbox>
```

**Validates configuration and returns error if invalid.**

---

## ExecutionResult

Result of command execution.

### Fields

```rust
pub struct ExecutionResult {
    /// Standard output (lossy UTF-8)
    pub stdout: String,

    /// Standard error (lossy UTF-8)
    pub stderr: String,

    /// Process exit code (0 = success)
    pub exit_code: i32,

    /// Wall clock duration
    pub duration: Duration,

    /// CPU time (user + system), if available
    pub cpu_time: Option<Duration>,

    /// Peak memory usage in bytes, if available
    pub peak_memory: Option<u64>,

    /// True if killed due to timeout
    pub killed_by_timeout: bool,

    /// True if killed due to out-of-memory
    pub killed_by_oom: bool,

    /// Signal number if killed by signal
    pub signal: Option<i32>,
}
```

### Methods

#### `success`

Check if execution was successful.

```rust
pub fn success(&self) -> bool
```

Returns `true` if:
- `exit_code == 0`
- `!killed_by_timeout`
- `!killed_by_oom`
- `signal.is_none()`

#### `failure_reason`

Get human-readable failure reason.

```rust
pub fn failure_reason(&self) -> Option<String>
```

Returns:
- `"Execution timed out"` if timeout
- `"Out of memory"` if OOM
- `"Killed by signal {n}"` if signaled
- `"Exit code {n}"` if non-zero exit
- `None` if success

### Example

```rust
let result = sandbox.run("python3", &["script.py"])?;

if result.success() {
    println!("Output: {}", result.stdout);
    println!("Duration: {:?}", result.duration);
    if let Some(mem) = result.peak_memory {
        println!("Peak memory: {} MB", mem / MB);
    }
} else {
    eprintln!("Failed: {}", result.failure_reason().unwrap());
    eprintln!("stderr: {}", result.stderr);
}
```

---

## Configuration Types

### Permission

Mount permission level.

```rust
pub enum Permission {
    ReadOnly,   // Read-only access
    ReadWrite,  // Read and write access
}
```

### NetworkMode

Network access mode.

```rust
pub enum NetworkMode {
    None,                    // No network access (default)
    Host,                    // Full network access
    Whitelist(Vec<String>),  // Only allowed domains
}
```

### SeccompProfile

Security profile level.

```rust
pub enum SeccompProfile {
    Strict,      // Minimal syscalls (compute only)
    Standard,    // Common syscalls (file I/O, network)
    Permissive,  // Most syscalls allowed
    Disabled,    // No seccomp filtering
}
```

---

## Error Types

### SandboxError

```rust
pub enum SandboxError {
    /// Configuration validation failed
    ConfigValidation(String),

    /// Platform not supported
    UnsupportedPlatform(String),

    /// Linux namespace creation failed
    NamespaceCreation(String),

    /// Linux cgroup creation failed
    CgroupCreation(String),

    /// Linux cgroup setting failed
    CgroupSetting {
        controller: String,
        setting: String,
        value: String,
        reason: String,
    },

    /// macOS sandbox profile error
    SandboxProfile(String),

    /// Command not found
    CommandNotFound(String),

    /// Permission denied
    PermissionDenied(String),

    /// Execution timed out
    Timeout,

    /// Internal error
    Internal(String),

    /// I/O error
    Io(std::io::Error),
}
```

### Result Type

```rust
pub type Result<T> = std::result::Result<T, SandboxError>;
```

---

## Constants

Size constants for convenience:

```rust
pub const KB: u64 = 1024;
pub const MB: u64 = 1024 * 1024;
pub const GB: u64 = 1024 * 1024 * 1024;
```

**Example:**
```rust
use nanosandbox::{MB, GB};

builder
    .memory_limit(512 * MB)
    .tmpfs("/tmp", 1 * GB)
```

---

## Platform Functions

### `is_platform_supported`

Check if current platform is supported.

```rust
pub fn is_platform_supported() -> bool
```

### `platform_name`

Get current platform name.

```rust
pub fn platform_name() -> &'static str
```

Returns: `"linux"`, `"macos"`, or `"windows"`

### `get_platform_capabilities`

Get platform capability information.

```rust
pub fn get_platform_capabilities() -> PlatformCapabilities
```

**Example:**
```rust
let caps = get_platform_capabilities();
println!("Memory limit: {}", caps.memory_limit);  // "hard" or "soft"
println!("Network isolation: {}", caps.network_isolation);
```

---

## Python Bindings

```python
from nanosandbox import Sandbox, SandboxBuilder, Permission, MB, GB

# Create sandbox
sandbox = (Sandbox.builder()
    .working_dir("/tmp")
    .memory_limit(512 * MB)
    .wall_time_limit(30.0)  # seconds as float
    .build())

# Run command
result = sandbox.run("python3", ["-c", "print('hello')"])
print(result.stdout)
print(result.success())

# Presets
sandbox = Sandbox.code_judge("/code").build()
sandbox = Sandbox.agent_executor("/workspace").build()
```

---

## Node.js Bindings

```javascript
const { SandboxBuilder, Sandbox, Permission, MB, GB } = require('nanosandbox');

// Create sandbox
const builder = new SandboxBuilder();
builder.workingDir('/tmp');
builder.memoryLimit(512 * MB);
builder.wallTimeLimit(30.0);
const sandbox = builder.build();

// Run command
const result = sandbox.run('node', ['-e', "console.log('hello')"]);
console.log(result.stdout);
console.log(result.exitCode);

// Presets
const judge = SandboxBuilder.codeJudge('/code').build();
const agent = SandboxBuilder.agentExecutor('/workspace').build();
```

---

## Thread Safety

- `Sandbox` implements `Send + Sync`
- Safe to share across threads
- Each execution is independent
- Concurrent executions on same sandbox are serialized

```rust
use std::thread;

let sandbox = Arc::new(Sandbox::builder().working_dir("/tmp").build()?);

let handles: Vec<_> = (0..4).map(|i| {
    let sb = Arc::clone(&sandbox);
    thread::spawn(move || {
        sb.run("echo", &[&i.to_string()])
    })
}).collect();

for h in handles {
    let result = h.join().unwrap()?;
    println!("{}", result.stdout);
}
```

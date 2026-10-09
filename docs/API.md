# Nanosandbox API Reference

Complete API documentation for the nanosandbox sandbox library.

## Table of Contents

- [Sandbox](#sandbox)
- [SandboxBuilder](#sandboxbuilder)
- [ExecutionResult](#executionresult)
- [Configuration Types](#configuration-types)
- [Error Types](#error-types)
- [Constants](#constants)
- [Migrating from 0.1](#migrating-from-01)
- [Platform Functions](#platform-functions)

---

## Sandbox

The main sandbox execution unit. A `Sandbox` is configured once and can run
any number of commands, each in a fresh sandboxed process.

### Creating a Sandbox

```rust
use nanosandbox::{Sandbox, MB};
use std::time::Duration;

// Using builder
let sandbox = Sandbox::builder()
    .writable("/home/me/project")
    .working_dir("/home/me/project")
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
pub fn run(&self, cmd: &str, args: &[&str]) -> Result<ExecutionResult>
```

`cmd` is a path, or a name looked up in the sandbox's `PATH`.

```rust
let result = sandbox.run("python3", &["-c", "print('hello')"])?;
println!("stdout: {}", result.stdout);
println!("exit code: {}", result.exit_code);
```

#### `run_with_input`

Execute a command with stdin input.

```rust
pub fn run_with_input(&self, cmd: &str, args: &[&str], stdin: Option<&[u8]>)
    -> Result<ExecutionResult>
```

```rust
let result = sandbox.run_with_input("cat", &[], Some(b"hello world"))?;
assert_eq!(result.stdout, "hello world");
```

#### `id`

```rust
pub fn id(&self) -> &str
```

A unique identifier for this sandbox.

### Presets

Presets return a `SandboxBuilder`, so any setting can be changed before
`build()`. They only use settings that Linux and macOS both enforce.

CPU share and process count are left out on macOS, which can't limit them.

| Preset | Files | Private /tmp | Memory | CPU | Wall time | Processes |
|---|---|---|---|---|---|---|
| `code_judge(dir)` | `dir` read-only, working dir; rest of home hidden | 64 MB | 256 MB | 1 core, 5 s CPU time | 10 s | 10 |
| `agent_executor(ws)` | `ws` writable, working dir, `HOME` | 512 MB | 4 GB | 4 cores | 600 s | 256 |
| `data_analysis(in, out)` | `in` read-only, `out` writable and working dir | 256 MB | 2 GB | 2 cores | 300 s | 100 |
| `interactive(ws)` | `ws` writable, working dir, `HOME` | 1 GB | 8 GB | 4 cores | none | 512 |

All have no network; add it with `allow_network`.

```rust
let sandbox = Sandbox::code_judge("/submissions/123")
    .wall_time_limit(Duration::from_secs(5)) // override the preset
    .build()?;
```

---

## SandboxBuilder

Builder for configuring sandbox parameters. `Sandbox::builder()` or
`SandboxBuilder::new()`. All methods return `Self` for chaining; `build()`
checks the configuration and returns an error for anything the platform
can't enforce, instead of running without it.

### File System

A sandbox can read the system's files, but not the user's credentials. It
can write nothing it hasn't been given, except its private temp directory. These methods work the same on
Linux and macOS; Windows has no file system isolation and refuses them.

#### `read_only` / `writable`

```rust
pub fn read_only(self, path: impl Into<PathBuf>) -> Self
pub fn writable(self, path: impl Into<PathBuf>) -> Self
```

Let the sandbox read, or read and write, a host file or directory, at the
same path. Writes land on the host. The path must exist. On Linux run as
root, the sandbox runs as `nobody`, so a `writable` path must be writable by
uid 65534 (see [platform-linux.md](platform-linux.md#running-as-root)).

```rust
builder
    .read_only("/data/input")
    .writable("/data/output")
```

#### `private_tmp` / `no_private_tmp`

```rust
pub fn private_tmp(self, size_bytes: u64) -> Self
pub fn no_private_tmp(self) -> Self
```

A temp directory for each run: empty at the start, removed afterwards,
limited to `size_bytes`. **On by default**, at `DEFAULT_PRIVATE_TMP_SIZE`
(256 MB). Programs find it through `$TMPDIR`.

- On Linux it's a tmpfs at `/tmp`, so programs that use `/tmp` by name get
  it too. Going over the size fails the write (`ENOSPC`).
- On macOS, and on Linux under Ubuntu's AppArmor userns restriction, it's a
  private directory: `/tmp` by name is the host's. Going over the size kills
  the program (`ExecutionResult::killed_by_tmp_limit`). See
  [platform-macos.md](platform-macos.md#tmpfs).

#### What can't be read: `deny_read` / `hide_home`

```rust
pub fn deny_read(self, path: impl Into<PathBuf>) -> Self
pub fn hide_home(self) -> Self
```

By default the sandbox can read everything except credentials in the home
directory: `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.config/gcloud`,
`~/.kube`, `~/.docker/config.json`, `~/.netrc`, `~/.git-credentials`,
`~/.config/gh`, `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials*`, shell and
REPL histories, keyrings and browser profiles. Toolchains, package caches and
projects in the home directory stay readable, so builds work.

`deny_read(path)` adds a file or directory to that. `hide_home()` hides the
whole home directory instead, except what `read_only`, `writable` or
`working_dir` name. On Linux file names stay visible, only contents aren't.

#### `working_dir`

```rust
pub fn working_dir(self, path: impl Into<PathBuf>) -> Self
```

The directory the program starts in. It grants no access by itself.

#### Linux only: `bind`, `tmpfs`, `rootfs`

```rust
pub fn bind(self, source: impl Into<PathBuf>, target: impl Into<PathBuf>, permission: Permission) -> Self
pub fn tmpfs(self, path: impl Into<PathBuf>, size_bytes: u64) -> Self
pub fn rootfs(self, path: impl Into<PathBuf>) -> Self
```

These need a mount namespace, so they only exist on Linux (other platforms
don't compile calls to them), and Ubuntu's AppArmor userns restriction makes
`build()` refuse them.

- `bind` shows `source` at a different path, `target`. Without a rootfs,
  `target` must exist on the host, unless it's inside a tmpfs.
- `tmpfs` mounts an empty tmpfs at any path but `/tmp` (use `private_tmp`).
- `rootfs` runs in `path` as the root file system. `read_only`/`writable`
  paths are bound into it at the same path.

### Resource Limits

```rust
pub fn memory_limit(self, bytes: u64) -> Self
pub fn cpu_limit(self, cpus: f64) -> Self          // CPU share, e.g. 0.5 or 2.0 cores
pub fn wall_time_limit(self, d: Duration) -> Self  // killed after this long
pub fn cpu_time_limit(self, d: Duration) -> Self   // see below
pub fn max_pids(self, n: u32) -> Self
pub fn max_file_size(self, bytes: u64) -> Self
pub fn max_open_files(self, n: u32) -> Self
```

Where a platform can't enforce a limit, `build()` refuses it
(`SandboxError::Unsupported`) instead of running without it:

| | Linux | macOS | Windows |
|---|---|---|---|
| `memory_limit` | cgroup | checked every 10 ms, killed when over | Job Object |
| `cpu_limit` | cgroup | refused | Job Object |
| `wall_time_limit` | ✓ | ✓ | ✓ |
| `cpu_time_limit` | rlimit *and* cgroup total | rlimit | refused |
| `max_pids` | cgroup | refused | refused |
| `max_file_size`, `max_open_files` | rlimit | rlimit | refused |

The presets leave out `cpu_limit` and `max_pids` on macOS. Values that can't
work (`cpu_limit` under 0.01, NaN, a zero memory, process or file limit) are
refused too.

`cpu_time_limit` is `RLIMIT_CPU`, which only charges time to the one process
it's set on. On Linux that's on top of a second check, against the whole
cgroup's total CPU time, so a program that forks can't multiply its budget
by however many children it starts; macOS and Windows have no equivalent
for that second check.

### Network

```rust
pub fn no_network(self) -> Self                    // default
pub fn allow_network(self, domains: &[&str]) -> Self
pub fn host_network(self) -> Self
pub fn allow_private_destinations(self) -> Self     // with allow_network
```

`allow_network` routes all traffic through a local HTTP/HTTPS proxy that
only lets the listed domains through (`*.example.com` matches
`example.com` and its subdomains). The sandbox has no other way out: on
Linux it gets its own network namespace, on macOS the sandbox profile only
allows the proxy. `HTTP_PROXY`/`HTTPS_PROXY` are set for the program.

```rust
builder.allow_network(&["api.openai.com", "*.github.com"])
```

The proxy connects from the host's network. So an allowed name that
resolves to a loopback, private (10/8, 172.16/12, 192.168/16), link-local
(including cloud metadata at 169.254.169.254) or other non-public address is
refused with 403: it would reach the host's own services and internal
network. `allow_private_destinations()` allows it, for an internal API. The
proxy resolves each name once and connects to the address it checked, so
the name can't resolve to something else in between (DNS rebinding).

How requests are relayed:

- Request bodies, uploads and anything the client sends after `CONNECT`
  reach the server; a client that finishes sending still gets its answer.
- A connection is cut after 300 s with nothing sent either way. A transfer
  that keeps going has no time limit (the run's `wall_time_limit` still
  applies).
- Plain HTTP is one request per connection: the proxy sends
  `Connection: close`, and sets `Host` to the URL's host, whatever the
  client sent. HTTPS isn't decrypted, so what a client says inside TLS (its
  SNI, its `Host`) isn't checked against the `CONNECT` host.
- Each run has a proxy listener of its own, closed with the run along with
  its open connections. `ExecutionResult::blocked_hosts` lists the hosts it
  refused that run.

Windows only supports `host_network()`.

### Output

```rust
pub fn max_output(self, bytes: u64) -> Self
```

Keep at most `bytes` of stdout, and as much of stderr: by default
`DEFAULT_MAX_OUTPUT`, 16 MB each. The output is held in this process's memory.
Past the limit it's still read, so the program runs on, but dropped, and
`ExecutionResult::output_truncated` is set.

### Environment

```rust
pub fn env(self, key: impl Into<String>, value: impl Into<String>) -> Self
pub fn envs(self, envs: impl IntoIterator<Item = (String, String)>) -> Self
pub fn clear_env(self, clear: bool) -> Self
```

By default the program starts with only what `env` sets (plus a default
`PATH`, `TMPDIR` and the proxy variables). `clear_env(false)` starts from
this process's environment instead.

### Linux only: Identity and Syscall Filter

```rust
pub fn uid(self, uid: u32) -> Self
pub fn gid(self, gid: u32) -> Self
pub fn hostname(self, name: impl Into<String>) -> Self
pub fn seccomp(self, enabled: bool) -> Self
```

`seccomp` turns the syscall filter on or off; it's on by default. It blocks
creating namespaces, mounting, bpf, perf_event_open, userfaultfd, io_uring,
the keyring, kernel modules and kexec, with `EPERM`. Ordinary programs don't
use these. Turn it off for one that does, such as Chrome with its own
sandbox enabled.

### `build`

```rust
pub fn build(self) -> Result<Sandbox>
```

---

## ExecutionResult

Result of command execution. Marked `#[non_exhaustive]`: read its fields,
and construct one (in tests) with `ExecutionResult::new()` or `default()`.

```rust
pub struct ExecutionResult {
    pub stdout: String,                // lossy UTF-8
    pub stderr: String,                // lossy UTF-8
    pub exit_code: i32,
    pub duration: Duration,            // wall clock
    pub killed_by_timeout: bool,
    pub killed_by_oom: bool,
    pub killed_by_tmp_limit: bool,     // wrote more than private_tmp allows
    pub killed_by_cpu_limit: bool,     // Linux: the whole cgroup's CPU time, not just one process
    pub signal: Option<i32>,           // set when the host's own limit killed the run; a command killed by a signal on Linux reports 128+signal in exit_code instead
    pub peak_memory: Option<u64>,      // bytes
    pub cpu_time: Option<Duration>,    // user + system
    pub blocked_hosts: Vec<String>,    // refused by the allow_network proxy
    pub output_truncated: bool,        // stdout or stderr went past max_output
    pub proc_isolated: bool,           // Linux: false under AppArmor's userns restriction
}
```

`success()` is true when the exit code is 0 and nothing killed the
program. `failure_reason()` says why not, as text.

```rust
let result = sandbox.run("python3", &["script.py"])?;
if result.success() {
    println!("Output: {}", result.stdout);
} else {
    eprintln!("Failed: {}", result.failure_reason().unwrap());
    eprintln!("stderr: {}", result.stderr);
}
```

---

## Configuration Types

### Permission (Linux only)

For `bind`.

```rust
pub enum Permission {
    ReadOnly,
    ReadWrite,
}
```

---

## Error Types

### SandboxError

Marked `#[non_exhaustive]`, and most variants are themselves struct
variants carrying a `source` (`std::error::Error::source()` chains to it),
so matching one needs `{ .. }`. The ones to expect from `build()`:

- `Unsupported { setting, reason }`: this platform, or this system's
  configuration, can't enforce a setting. The reason says what to do.
- `Config { context, source }`: the settings contradict each other, such
  as a bind target that doesn't exist. `source` is set only where a real
  underlying error exists (e.g. a path with a NUL byte).
- `PathNotFound(PathBuf)`: a `read_only`/`writable`/`rootfs` path doesn't
  exist.
- `UserNamespaceDisabled`, `CgroupV2Unavailable`, `CgroupCreation`,
  `CgroupSetting`, `SandboxExecUnavailable`: the platform's sandboxing isn't
  available or set up.

From `run()`: `CommandNotFound` (the command doesn't exist, on every
platform -- on Linux and macOS this comes from the sandboxed child's own
failed lookup, not a host-side guess, so a `rootfs`'s or a `PATH` override's
own view of what exists is what's checked), `ExecutionFailed`, `NulError`
(a NUL byte in a command, argument or path), `Io`, `Internal`.

```rust
pub type Result<T> = std::result::Result<T, SandboxError>;
```

---

## Constants

```rust
pub const KB: u64 = 1024;
pub const MB: u64 = 1024 * 1024;
pub const GB: u64 = 1024 * 1024 * 1024;
pub const DEFAULT_PRIVATE_TMP_SIZE: u64 = 256 * MB;
pub const DEFAULT_MAX_OUTPUT: u64 = 16 * MB;
```

---

## Migrating from 0.1

| 0.1 | 0.2 |
|---|---|
| `.mount(p, p, Permission::ReadOnly)` | `.read_only(p)` |
| `.mount(p, p, Permission::ReadWrite)` | `.writable(p)` |
| `.mount(src, dst, perm)` | `.bind(src, dst, perm)` (Linux only) |
| `.tmpfs("/tmp", n)` | `.private_tmp(n)` (and it's on by default) |
| `.tmpfs(other, n)` | `.tmpfs(other, n)` (Linux only) |
| `.seccomp_profile(..)` | `.seccomp(bool)` (Linux only) |
| `.uid` / `.gid` / `.hostname` / `.rootfs` | unchanged, Linux only |
| `SandboxConfig`, `NetworkMode` | no longer public |
| `ExecutionResult { .. }` | `#[non_exhaustive]`; new field `killed_by_tmp_limit` |
| `SandboxError::PlatformFeatureUnavailable` | `SandboxError::Unsupported` |

The working directory no longer makes itself writable on macOS, and nothing
outside `writable` paths and temp directories is writable on Linux either:
add `.writable(dir)` where the program needs to write.

---

## Platform Functions

### `is_platform_supported`

Check if the current platform can run a sandbox with the default config.
On Linux that means user namespaces, Landlock and a seccomp filter for this
architecture (cgroup v2 only matters for configs that set a limit). A host
that says `false` may still run some configs -- a `rootfs` needs no Landlock,
`seccomp(false)` no filter -- so `build()` is what decides for a given one.

```rust
pub fn is_platform_supported() -> bool
```

### `platform_name`

Get current platform name.

```rust
pub fn platform_name() -> &'static str
```

Returns: `"linux"`, `"macos"`, or `"windows"`

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

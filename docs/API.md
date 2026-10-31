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

Input is fed as the program reads it. A program that exits before reading it
all gets what it read; the rest is dropped, and the host is never sent
`SIGPIPE` for it, whatever disposition the host runtime left the signal at.

#### `spawn` / `spawn_pty` (Linux, macOS)

Start a command and work with it while it runs. `run` is `spawn` plus
reading everything; the limits, the cleanup and the audit record are the
same.

```rust
pub fn spawn(&self, cmd: &str, args: &[&str]) -> Result<Child>
pub fn spawn_pty(&self, cmd: &str, args: &[&str], rows: u16, cols: u16) -> Result<Child>
```

`spawn` gives the command pipes: `Child::stdin`, `stdout` and `stderr`
implement `Write`/`Read` (and `AsRawFd`). Nothing is cut at `max_output`:
a command that writes faster than the caller reads waits on its pipe.

`spawn_pty` gives it a pseudo-terminal of `rows` by `cols` instead, its
own controlling terminal (never the caller's): `stdin` and `stdout` are the
terminal, `stderr` is `None`. For shells, REPLs, and programs that behave
differently on a tty. `Child::resize` changes the size; a terminal has no
EOF to send, so write `0x04` to end input. A shell may flush pending input
while it sets the terminal up, so type after its prompt.

```rust
use std::io::{BufRead, BufReader};

let mut child = sandbox.spawn("cargo", &["test"])?;
for line in BufReader::new(child.stderr.take().unwrap()).lines() {
    println!("{}", line?);
}
let result = child.wait()?;
```

#### `id`

```rust
pub fn id(&self) -> &str
```

A unique identifier for this sandbox.

## Child

What `spawn`/`spawn_pty` return.

```rust
pub struct Child {
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,   // None with a PTY
}

impl Child {
    pub fn id(&self) -> u32;                                   // host pid of its first process
    pub fn kill(&mut self) -> Result<()>;                      // SIGKILL; result has signal 9
    pub fn resize(&self, rows: u16, cols: u16) -> Result<()>;  // PTY only
    pub fn try_wait(&mut self) -> Result<Option<ExecutionResult>>;
    pub fn wait(self) -> Result<ExecutionResult>;
    pub fn wait_with_output(self) -> Result<ExecutionResult>;
}
```

`wait` reads and drops what the command still writes to the streams the
`Child` holds (so it can't block on them) and returns a result with empty
`stdout`/`stderr`; `wait_with_output` collects them (up to `max_output`
each) like `run`. A stream the caller took out is the caller's to drain.
`try_wait` doesn't block. Dropping a `Child` kills the command and waits
for its cleanup.

### Presets

Presets return a `SandboxBuilder`, so any setting can be changed before
`build()`. They only use settings that Linux and macOS both enforce.

CPU share and process count are left out on macOS, which can't limit them.

| Preset | Files | Private /tmp | Memory | CPU | Wall time | Processes |
|---|---|---|---|---|---|---|
| `code_judge(dir)` | `dir` read-only, working dir; rest of home hidden | 64 MB | 256 MB | 1 core, 5 s CPU time | 10 s | 10 |
| `agent_executor(ws)` | `ws` writable, working dir; rest of home hidden except toolchains (below) | 512 MB | 4 GB | 4 cores | 600 s | 256 |
| `data_analysis(in, out)` | `in` read-only, `out` writable and working dir; rest of home hidden except toolchains | 256 MB | 2 GB | 2 cores | 300 s | 100 |
| `interactive(ws)` | `ws` writable, working dir, `HOME` | 1 GB | 8 GB | 4 cores | none | 512 |

All have no network; add it with `allow_network`.

`agent_executor` and `data_analysis` hide the home directory but keep the
toolchains and caches in it readable: `~/.cargo`, `~/.rustup`, `~/.nvm`,
`~/.npm`, `~/.pyenv`, `~/.local`, `~/.cache`, `~/go`, `~/.m2`, `~/.gradle`,
`~/Library/Caches`, `~/Library/Developer` and the like, of those that exist,
the install root of every `bin`/`sbin` directory on `PATH` under home
(`~/.cargo/bin` brings `~/.cargo`, `~/dev/flutter/bin` brings `~/dev/flutter`;
a `PATH` entry that isn't a `bin` directory brings nothing), and git's
`~/.gitconfig` and `~/.config/git/{config,ignore,attributes}`. The credentials
hidden by default stay hidden inside them (`~/.cargo/credentials`). Since the
command's `HOME` is the run's private directory, `CARGO_HOME`, `RUSTUP_HOME`,
`GOPATH`, `NVM_DIR`, `PYENV_ROOT`, `BUN_INSTALL`, `DENO_INSTALL`, `VOLTA_HOME`,
`SDKMAN_DIR`, `GRADLE_USER_HOME` and `PNPM_HOME` are set for the ones that
exist, unless `env` set them. This is an opinion about what a developer's
machine looks like, which is why it lives in the presets and not in a builder
method: a caller composing its own policy uses `hide_home` and names what to
keep with `read_only`. A tool in an unusual place needs one `read_only`.

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
uid 65534 (see [platform-linux.md](platform-linux.md#running-as-root)), or
the host user `host_uid`/`host_gid` name.

A `read_only` path inside a `writable` one (the workspace, say) is read-only
again: it can't be changed, replaced or moved, and neither can the directories
above it, up to the writable one, nor can their mode, owner, flags or ACL be
changed (so the host isn't kept out of it; on Linux a `chmod` of those
directories isn't refused, see THREAT_MODEL). So a `chmod -R` from the
workspace root reports a failure for the root and those directories, and
changes everything else; a workspace with nothing protected inside can be
re-permissioned freely. The rest stays writable. That's how to keep
the project's own settings out of reach of the commands the sandbox runs (a
lockfile, a CI config, `.git/hooks`). On macOS it's a deny rule. On Linux it's a read-only mount, so
it needs mounting: `build()` refuses it where AppArmor's `unprivileged_userns`
restriction denies that, rather than leave the path writable.

The paths these name are resolved when the sandbox is built, and that is what
the rules are made from on every run; a relative path is made absolute then.
If one of them later leads somewhere else (it was moved, or replaced by a
symlink), `run` refuses with a `Config` error saying so, until the sandbox is
built again. Without that, a command could swap the writable directory, or a
directory above it, for a symlink to somewhere it may not write, and the next
run would grant that place. For the same reason a command can't remove or
rename a writable directory itself, or a directory above it: `rm -rf` of
everything inside it works, `rm -rf` of the directory doesn't. (On Linux
without mounting, the swap itself can't be stopped; the next run is refused.)

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

Where it is a directory rather than a tmpfs (macOS, and Linux under AppArmor's
`unprivileged_userns` restriction), it lives in a container directory that no
run's command can read or write except for its own directory in it: one run
can't see or touch another's temp files.

#### What can't be read: `deny_read` / `hide_home`

```rust
pub fn deny_read(self, path: impl Into<PathBuf>) -> Self
pub fn hide_home(self) -> Self
pub fn report_denials(self) -> Self
```

By default the sandbox can read everything except credentials in the home
directory: `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.config/gcloud`,
`~/.kube`, `~/.docker/config.json`, `~/.netrc`, `~/.git-credentials`,
`~/.config/gh`, `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials*`, `~/.env`, AI coding
tools' logins (`~/.codex`, `~/.claude`, `~/.cursor`, `~/.gemini`, ...), shell and
REPL histories, keyrings and browser profiles. Everything else in the home
directory stays readable: toolchains and caches, but also other projects and
their `.env` files, and whatever credential store isn't on the list.

`deny_read(path)` adds a file or directory to that; the path must exist, or
`build()` fails with `PathNotFound` (a typo would otherwise protect nothing).
`hide_home()` hides the whole home directory instead, except what `read_only`,
`writable` or `working_dir` name (the agent presets keep toolchains readable
on top of this, see [Presets](#presets)); naming home itself asks for all of
it, the credentials above excepted. A hidden path reads as "permission
denied", not as missing; a program that insists on reading one (git with a
`HOME` pointing at the real, hidden home) fails rather than carries on. On
Linux file names stay visible, only contents aren't. On macOS preferences are
served by `cfprefsd` from `~/Library/Preferences`, not read as files, so
`hide_home` also limits what that service answers to the global domain
(language, region, keyboard): `defaults read` of an application's domain
fails, and a program reading its own preferences through CoreFoundation gets
the defaults.

`report_denials()` puts the file accesses the sandbox refused into
`ExecutionResult::denied_paths`: each path with the operation refused
(`file-read-data`, `file-write-create`, `process-exec`...) and how many
times. That's how a caller finds out what a failing command wanted, and can
decide (or ask its user) whether to grant it with `read_only` and run again;
the decision and its memory belong to the caller, the sandbox only reports.
Off by default. On macOS it reads the unified log (`log stream`, no privileges
needed). The log delivers late and a fresh stream may be silent for a while, so
the sandbox probes it: a denial it provokes itself, at `build()` (which fails if
the probe never arrives) and after each run as a barrier, so the run's events
are all in before they're taken. That costs the log's delay at the end of each
run, tens of milliseconds. Each denial is attributed by pid: the run's process
tree is followed fork by fork (kqueue `NOTE_FORK`, then the children listed),
so other sandboxed programs' denials on the machine, and other runs', are never
taken for the run's; a child that exits within the moment between its fork and
the listing is missed. The log line is text in which the process's name and
the path are the command's to choose, so the pid is read as the one that is
the run's; a process named to look like a log line can garble the path
reported for its own denial, not hide the denial. The
kernel coalesces a denial repeated within about a second (same program,
operation and path), so `count` is a lower bound, and a run that repeats one
right after another run may not see it at all. Not reported on Linux yet
(Landlock denials aren't observable without privileges before kernel 6.15's
audit support); the field is empty there.

A hard link made on the host is another name for the same file, and every
rule here is by name. So at `build()` the denied files with more than one name
are looked for under the sandbox's directories and home (minus its bulk:
`Library`, `.cache`, `node_modules`, `target`, `.git`...), and the other names
are denied too, reading and writing. One that can't be found is refused with
`SandboxError::Config` naming the file: it's somewhere readable, and only the
host can remove it (`find / -samefile <file>`). GnuPG's lock files, which are
hard links to each other inside `~/.gnupg`, don't trigger this.
A denied path inside a `writable` directory can't be renamed, removed or
linked out from under the rule either. On Linux that takes a mount over it
(an empty read-only directory, or `/dev/null` for a file), so it's refused
where AppArmor denies mounting, like `read_only` inside a writable directory;
a path the config names inside such a denied path is refused too.

Nothing else in a `writable` directory is kept from the command: the workspace
is the command's output. Anything the host later runs against it that takes
instructions from files in it runs what the command wrote: git (hooks,
`core.hooksPath`, `core.fsmonitor`, `commondir`, submodule links...), `make`,
`npm install` scripts, `cargo` (`build.rs`, `.cargo/config.toml`), `direnv`,
`pre-commit`, an editor's task files. The sandbox confines the command's
processes; it doesn't police what the host does with the files afterwards, and
path rules for one tool's configuration don't cover the class (see
[THREAT_MODEL.md](THREAT_MODEL.md)). A file that must stay as it is, name
`read_only`; and treat a workspace an agent has run in as input to review, not
as a place to run tools unprompted (editors auto-detecting repositories do).

#### `working_dir`

```rust
pub fn working_dir(self, path: impl Into<PathBuf>) -> Self
```

The directory the program starts in. It grants no access by itself. A
relative path is made absolute when the sandbox is built.

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
  paths are bound into it at the same path. Symlinks in it resolve as if it
  were `/`, including while the mounts are set up, so one left there by an
  earlier run can't point the setup at the host. This needs `openat2(2)`
  (Linux 5.6); older kernels refuse a rootfs.

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
| `memory_limit` | cgroup | checked every 10 ms (2 ms near the limit), killed when over | Job Object |
| `cpu_limit` | cgroup | refused | refused |
| `wall_time_limit` | ✓ | ✓ | ✓ |
| `cpu_time_limit` | rlimit *and* cgroup total | rlimit | Job Object total |
| `max_pids` | cgroup | refused | Job Object |
| `max_file_size`, `max_open_files` | rlimit | rlimit | refused |

The presets leave out `cpu_limit` and `max_pids` on macOS, and `cpu_limit` on
Windows. Values that can't work (`cpu_limit` under 0.01, NaN, a zero memory,
process or file limit) are refused too.

`cpu_time_limit` is `RLIMIT_CPU`, which only charges time to the one process
it's set on. On Linux that's on top of a second check, against the whole
cgroup's total CPU time, so a program that forks can't multiply its budget
by however many children it starts. Windows checks only that total (its
Job Object); macOS has no equivalent.

### Network

```rust
pub fn no_network(self) -> Self                    // default
pub fn allow_network(self, entries: &[&str]) -> Self
pub fn deny_network(self, entries: &[&str]) -> Self            // with allow_network
pub fn deny_network_with_reason(self, entry: &str, reason: &str) -> Self
pub fn host_network(self) -> Self
pub fn allow_private_destinations(self) -> Self     // with allow_network
pub fn require_host_match(self) -> Self             // with allow_network
pub fn allow_trustd(self) -> Self                   // macOS, with allow_network
```

`allow_network` routes all traffic through a local proxy that only lets the
listed destinations through. An entry is a host (`example.com`),
`*.example.com` (it and its subdomains), or an IP address (an IPv6 one in
brackets if it has a port), with an optional `:port`: `api.example.com:443`
allows that port only, `api.example.com` any port. Names are compared
case-insensitively and without a trailing dot (`example.com.` is
`example.com`, in entries, requests and the result). `build()` refuses an
entry that could never match or would allow too much: a path or scheme, a
port of 0, `*` anywhere but a leading `*.`, or `*.` with a single label
(`*.com`). The sandbox has no other way out: on Linux it gets its own
network namespace, on macOS the sandbox profile only allows the proxy.

```rust
builder
    .allow_network(&["api.openai.com:443", "*.github.com"])
    .deny_network_with_reason("github.com:22", "SSH is blocked; use an https remote")
```

`deny_network` entries use the same syntax and are checked first, so a
deny can carve a port or a subdomain out of an allow. A reason given with
`deny_network_with_reason` is what the program is told, and what the result
records.

The proxy speaks HTTP (plain requests and `CONNECT` tunnels) and SOCKS5
(any TCP, with the name resolved by the proxy) on one port.
`HTTP_PROXY`/`HTTPS_PROXY` point programs at the first, `ALL_PROXY`
(`socks5h://...`) at the second: libcurl, Go's `x/net/proxy` and most
tools that honour a proxy at all use one of them. A program that ignores
them (plain `ssh`, a database driver) gets nowhere: there is no other route,
and no DNS inside the sandbox. UDP never leaves.

The proxy connects from the host's network. So an allowed name that
resolves to a loopback, private (10/8, 172.16/12, 192.168/16), link-local
(including cloud metadata at 169.254.169.254), Azure's platform endpoint
(168.63.129.16), one of this machine's own interface addresses, or other
non-public address is refused: it would reach the host's own services and internal
network. `allow_private_destinations()` allows it, for an internal API. The
proxy resolves each name once and connects to the address it checked, so
the name can't resolve to something else in between (DNS rebinding).

What a refused program sees: an HTTP `403` (or `502`/`504` when the
connection failed) with an `X-Proxy-Error` header giving the reason's code
and a one-line plain-text body saying what was refused and why
(`nanosandbox: github.com:22 is denied: SSH is blocked; use an https remote`);
over SOCKS5, reply 2, "connection not allowed by ruleset". The result's
`network_refusals` lists every destination the proxy didn't connect to,
with its port, the reason ([`RefusalReason`], whose `code()` is the header's
value: `not-allowed`, `denied`, `non-public-address`, `host-mismatch`,
`unreachable`, `timed-out`) and how many times it was asked;
`blocked_hosts` is the policy-refused hosts among them, each once.

How requests are relayed:

- Request bodies, uploads and anything the client sends after `CONNECT`
  reach the server; a client that finishes sending still gets its answer.
- A connection is cut after 300 s with nothing sent either way. A transfer
  that keeps going has no time limit (the run's `wall_time_limit` still
  applies).
- At most 256 connections are open per run at once; the next one waits for
  a slot rather than being dropped.
- Plain HTTP is one request per connection: the proxy sends
  `Connection: close`, sets `Host` to the URL's host, whatever the client
  sent, and forwards the body as its `Content-Length` or chunked framing
  says and nothing after it, so a pipelined second request (with a `Host`
  of its own) never reaches the server. A request whose body length is
  ambiguous (both headers, or a `Content-Length` that isn't one decimal) is
  refused with a `400`.
- HTTPS isn't decrypted. By default what a client says inside TLS (its
  SNI) isn't checked against the host the tunnel was opened to;
  `require_host_match()` cuts a tunnel whose handshake names another host
  (domain fronting through a CDN both share). Nothing the client sends is
  forwarded until its first bytes are either a complete ClientHello (even
  one spread over several TLS records) or plainly not TLS; a hello that
  can't be read is cut too. The server's bytes flow from the start, so a
  protocol where the server speaks first still works.
- Each run has a proxy listener of its own, closed with the run along with
  its open connections.

macOS: the proxied profile leaves out the system's certificate-verification
services (`trustd`, `ocspd`). They fetch a certificate's OCSP and issuer
URLs on the program's behalf, outside the allowlist, so a program could
carry data out in a certificate it asks the system to evaluate. Programs
that verify through Security.framework directly (Go, Swift) then fail TLS
verification under `allow_network`; the system's curl, and clients with
their own certificate store (Python, Node, Rust, Java), don't. `allow_trustd()`
puts the services back for the programs that need them, reopening that path.

Windows only supports `host_network()`.

### Output

```rust
pub fn max_output(self, bytes: u64) -> Self
```

Keep at most `bytes` of stdout, and as much of stderr: by default
`DEFAULT_MAX_OUTPUT`, 16 MB each. The output is held in this process's memory.
Past the limit it's still read, so the program runs on, but dropped, and
`ExecutionResult::output_truncated` is set.

### Audit

```rust
pub fn audit(self, sink: Arc<dyn AuditSink>) -> Self
```

Two events per `run`, handed to `sink` on the thread that ran it:

- `AuditSink::begin(&AuditStart)`, **before** the command starts: the command and
  arguments, the policy (network, paths, limits, environment variable names), and
  a run number. If it returns `Err`, or panics, the run is refused with
  `SandboxError::Audit`: nothing runs unrecorded.
- `AuditSink::end(&AuditEnd)`, after, with how it ended: exit code, signal,
  limits hit, output sizes, blocked hosts, or the error if it never ran. A
  panic here is caught, and the run's result still returned.

A start with no end means the host died while the command ran. No data from the
run is in an event: not stdin, not output, not environment values. In the
arguments, what looks like a secret (`--token=...`, an `Authorization:` header,
a password in a URL, `NAME=value` with a secret-sounding name) is replaced by
`<redacted>`; that is a pattern match, so keep secrets out of arguments. Events
are `Serialize`, with integer fields only. Both methods may be called from
several threads at once.

Keeping the events, and keeping them tamper-evident, is the sink's job.
`nanosandbox-mcp --audit-dir` writes hash chains.

### Environment

```rust
pub fn env(self, key: impl Into<String>, value: impl Into<String>) -> Self
pub fn envs(self, envs: impl IntoIterator<Item = (String, String)>) -> Self
pub fn clear_env(self, clear: bool) -> Self
```

By default the program starts with only what `env` sets (plus a default
`PATH`, the proxy variables, and `TMPDIR` and `HOME` when `private_tmp` is on).
`clear_env(false)` starts from this process's environment instead (an entry
that isn't UTF-8 is left out). A key must be non-empty and contain no `=` or
NUL, a value no NUL; `build()` refuses otherwise.

`HOME` is the run's private temp directory, so programs that keep caches and
config under it (npm, pip, git, ...) have somewhere to write that disappears
with the run. Without one they look the user up in the password database: on
macOS that finds the real home, which the sandbox can't write (npm fails with
`EPERM`); on Linux the sandbox's uid has no entry at all (Node throws
`ENOENT`). A `HOME` from `env`, or inherited with `clear_env(false)`, wins.
In proxied mode `NO_PROXY` names loopback, so a program's own local servers
aren't sent through the proxy (which would only refuse them as private
addresses). With `allow_private_destinations()` it's left unset: loopback then
goes through the proxy, to the host's own services.

### Linux only: Identity and Syscall Filter

```rust
pub fn uid(self, uid: u32) -> Self
pub fn gid(self, gid: u32) -> Self
pub fn host_uid(self, uid: u32) -> Self
pub fn host_gid(self, gid: u32) -> Self
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
    pub killed_by_tmp_limit: bool,     // wrote more than private_tmp allows ($TMPDIR only, where it's a directory)
    pub killed_by_cpu_limit: bool,     // Linux: the whole cgroup's CPU time, not just one process
    pub signal: Option<i32>,           // the signal that killed the process; see below
    pub peak_memory: Option<u64>,      // bytes
    pub cpu_time: Option<Duration>,    // user + system
    pub blocked_hosts: Vec<String>,    // hosts the allow_network proxy refused by policy
    pub network_refusals: Vec<NetworkRefusal>, // every refusal: host, port, reason, attempts
    pub denied_paths: Vec<DeniedPath>,  // refused file accesses, with report_denials (macOS)
    pub output_truncated: bool,        // stdout or stderr went past max_output
    pub proc_isolated: bool,           // Linux: false where the sandbox sees the host's /proc
}
```

`success()` is true when the exit code is 0 and nothing killed the
program. `failure_reason()` says why not, as text.

When a signal kills the program, `exit_code` is `128 + signal` on every
platform (143 for `SIGTERM`, 137 for `SIGKILL`), as a shell reports it, and
`signal` holds the number itself. That's how to tell a program killed by
`SIGTERM` from one that merely exited with 143: `signal` is `None` for the
latter.

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

### macOS only: Temp Directories

```rust
pub fn shared_tmp(self, shared: bool) -> Self
```

`true` by default: `/tmp`, `/private/tmp`, `/private/var/tmp` and the user's
own temp directory (`/private/var/folders/.../T`, where `mktemp -t` and the
`xcrun` shims write) are the host's own and writable; not the user's cache
directory (`.../C`, other programs' caches) or `.../0` (daemons' sockets and
state) next to it. `false` makes them read-only, leaving only `private_tmp`
(through `$TMPDIR`). It breaks programs
that write `/tmp` by name, `mktemp -t`, and Apple's `/usr/bin/clang`/`cc`
shims; see [platform-macos.md](platform-macos.md#shared_tmpfalse).

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

Every builder method consumes the builder and returns a new one, so chain
the calls (or keep each return value). `Permission` is only exported on Linux,
where `bind()` exists; import it under a platform check.

```python
import sys

from nanosandbox import Sandbox, SandboxBuilder, MB, GB

if sys.platform.startswith("linux"):
    from nanosandbox import Permission  # for SandboxBuilder.bind()

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

# Presets (the directories must exist)
sandbox = Sandbox.code_judge("/code").build()
sandbox = Sandbox.agent_executor("/workspace").build()
```

---

## Node.js Bindings

Each setter consumes the builder it is called on and returns a new one:
chain the calls, or keep every return value (`b = b.memoryLimit(...)`).
Calling a second method on a builder that was already passed on throws
"this builder was already consumed". `Permission` is only exported on Linux,
where `bind()` exists.

```javascript
const { SandboxBuilder, Sandbox, MB, GB } = require('nanosandbox');

// Create sandbox
const sandbox = new SandboxBuilder()
  .workingDir('/tmp')
  .memoryLimit(512 * MB)
  .wallTimeLimit(30.0)  // seconds
  .build();

// Run command. A bare name is looked up on the sandbox's default PATH, which
// has no Homebrew or nvm directories; this node's own path always works.
const node = process.execPath;
const result = sandbox.run(node, ['-e', "console.log('hello')"]);
console.log(result.stdout);
console.log(result.exitCode);

// run() blocks the event loop for the whole command; these don't. They run
// on libuv's thread pool (UV_THREADPOOL_SIZE, 4 by default) and return a
// Promise<ExecutionResult>.
const later = await sandbox.runAsync(node, ['-e', "console.log('hello')"]);
const piped = await sandbox.runWithInputAsync('cat', [], Buffer.from('hi'));

// Presets live on Sandbox, not SandboxBuilder. The directories must exist.
const judge = Sandbox.codeJudge('/code').build();
const agent = Sandbox.agentExecutor('/workspace').build();
```

Limits take plain numbers and throw an `InvalidArg` error on anything that
isn't a positive finite number of seconds (`wallTimeLimit`, `cpuTimeLimit`) or a
whole non-negative byte or process count (`memoryLimit`, `maxOutput`, ...), so
`maxOutput(-1)` is refused rather than silently dropping all output.

---

## Thread Safety

- `Sandbox` implements `Send + Sync`
- Safe to share across threads
- Each execution is independent
- Concurrent executions on the same sandbox run in parallel

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

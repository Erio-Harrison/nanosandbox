# Changelog

## 0.4.0

### Breaking

- `build()` refuses a `deny_read` path that doesn't exist (it would have left whatever is
  created there later readable), and `env` keys that are empty or contain `=` or NUL.
- `allow_network`: a wildcard matches DNS names only and needs two labels (`*.com` is refused),
  entries that can't work are refused at `build()`, and this machine's own interface addresses
  count as non-public.
- The `agent_executor` and `data_analysis` presets, and `nanosandbox-mcp`, hide the home
  directory except toolchains and caches. Logins of AI coding tools and `~/.env` join the
  default deny list.
- The proxy relays plain HTTP one request per connection (`Connection: close`, `Host` taken from
  the URL). A request with a control character or a lone CR in its head, a method that isn't a
  token, a version that isn't `HTTP/x.y`, or a destination that is neither a DNS name nor an IP
  address gets a `400`. At most 256 connections are open per run.
- The command runs in its own session: it can't read from, write to or type into the caller's
  terminal. Use `spawn_pty()` for a terminal.
- macOS: with `allow_network`, `trustd` and `ocspd` are left out of the profile, so programs that
  verify certificates through Security.framework (Go, Swift) fail TLS verification. `allow_trustd()`
  puts them back. Only the user's own `T/` under `/var/folders` is writable by default.
- Linux: `socket(AF_VSOCK, ...)` is denied by the syscall filter.
- Windows: `build()` refuses `cpu_limit` where the host's hypervisor scheduler ignores it.

### Security

- Linux: a `deny_read` path inside a workspace under `/tmp`, `/var/tmp` or `/dev/shm` was
  readable (also under a read-only grant). The workspace is bound into the tmpfs over those
  directories and the path was assumed hidden by it.
- A host descriptor opened without close-on-exec no longer reaches the command, so it can't
  write wherever the descriptor points. Both platforms.
- A run can't read, write or remove another run's private temp directory. macOS: the size limit
  and the removal hold against a subdirectory the command made unlistable.
- `require_host_match` reads a hello split over several TLS records, relays nothing before the
  hello is checked, and cuts one that names two hosts. Plain HTTP forwards only one request's
  body, so a pipelined second request with another `Host` never reaches the server, and
  `Connection` can't strip `Content-Length`. A lone CR in a header can't smuggle a second `Host`.
- Linux: with a `rootfs`, mount targets resolve inside it, so a planted symlink can't make the
  setup touch the host. A `read_only` path inside a writable one is judged by canonical paths, and
  a hard link to a denied file made on the host is denied too, or the build refused.
- macOS: `hide_home` limits preference reads to the global domain. A fork bomb is stopped
  completely when a run is killed, and leftover processes and markers of dead runs are swept
  by every run, not only by runs with a `private_tmp`.

### Added

- `spawn()` and `spawn_pty()` (Unix): stream a command's input and output while it runs, with no
  output cap and a terminal of its own. `Child` has `kill()`, `try_wait()`, `wait()` and `resize()`.
- Network rules: `host:port` entries, `deny_network()` and `deny_network_with_reason()` (deny, then
  allow), `require_host_match()`, and SOCKS5 on the proxy port. `ExecutionResult.network_refusals`
  lists every refusal with its port and reason; `RefusalReason` has `code()` and `by_policy()`.
- macOS: `report_denials()` and `ExecutionResult.denied_paths`; `allow_trustd()`.
- Windows: each command runs in a Job Object with memory, process-count and CPU-time limits.
- The Python and Node bindings take the new options, and Python ships type stubs.
  `nanosandbox-mcp` takes `--deny-network` and `--report-denials`.

### Fixed

- Limits and sizes are validated instead of panicking: Python raises `ValueError`, Node throws
  `InvalidArg` (it used to abort the process), the MCP server refuses them when parsing.
- Feeding stdin to a command that has already exited can't kill the host with `SIGPIPE`.
- Linux: a timeout that races a normal exit no longer reports a kill; a FIFO at a bind target
  fails instead of blocking the next run; the wait for the network setup is bounded; a
  non-UTF-8 environment variable is skipped instead of panicking.
- The proxy no longer stalls on small writes (Nagle with delayed ACK), and reads a SOCKS5
  request whole before refusing it.
- `hide_home` with the home directory itself granted keeps home readable.

## 0.3.0

### Breaking

- Linux: when the sandboxed command is killed by a signal, `ExecutionResult.exit_code` is now
  `128 + signal` and `signal` is `None` (it used to be `Some`). Kills by the host's own limits
  (`wall_time_limit`, ...) still set `signal`. This follows from the command now running as PID 2
  under a small init shim; see Security.
- Linux: `build()` refuses, for a root caller, a `writable`/`bind(ReadWrite)` source that `nobody`
  can't write to (with or without a `rootfs`), instead of failing at run time with `EACCES`. Set
  `host_uid`/`host_gid` to run as the source's owner.
- `is_platform_supported()` now requires, on Linux, Landlock and a seccomp filter for the
  architecture, and no longer requires cgroup v2. It answers whether the default config builds.
- Linux: `socket(AF_UNIX, ...)` is denied by the syscall filter. Programs that create Unix sockets
  (`multiprocessing.Manager`, `syslog()`) now fail; `socketpair()` and other families are unaffected.

### Security

- Linux: the command runs as PID 2 under an init shim that forwards signals and reaps orphans.
  As PID 1 it couldn't be signaled from inside its own sandbox (`kill -KILL $$` did nothing).
- Linux: `/var/tmp` and `/dev/shm` get a private tmpfs per run where mounting is possible, instead
  of being the host's shared paths. Still shared under AppArmor's `unprivileged_userns` restriction.
- Linux: closes connections to host services over Unix sockets (`docker.sock`, the systemd bus,
  `ssh-agent`).
- Linux: fixed an fd leak between concurrent runs that could leave a run's stdin never reaching EOF.

### Added

- `nanosandbox-mcp`: an MCP server (stdio) with one `run_command` tool, on npm, PyPI and
  crates.io. Limits are fixed at launch, not chosen by the model.
- Linux: `host_uid()`/`host_gid()` (also in the Python and Node bindings) for a root caller.
- Node: `runAsync()` and `runWithInputAsync()` return a Promise and leave the event loop free;
  `run()` and `runWithInput()` still block it for the whole command.

### Fixed

- Python: `run()` and `run_with_input()` release the GIL while the sandbox runs.
- Linux: cgroup v2 is only required for configs that set a cgroup-backed limit.

## 0.2.0

The published `0.1.0` was cut from this project's first commit, before
almost everything below existed. If you have `0.1.0` installed, treat this
as the first release with real sandboxing properties, not an incremental
update.

### Breaking

- `SandboxError`'s `Internal`, `ExecutionFailed`, `Config`, `CgroupCreation`,
  `NamespaceCreation` and `CgroupSetting` variants changed from a plain
  `String` payload to a struct variant carrying a `source` that chains to
  the real underlying error via `std::error::Error::source()`. Code
  matching these by position (e.g. `SandboxError::Config(msg)`) needs
  `{ context, .. }` instead.

### Security

- Linux: writes without a `rootfs` are now confined by Landlock, not left
  open to the calling user's whole file system.
- Linux: a real seccomp-BPF filter blocks `mount`, `setns`, `bpf`,
  `io_uring`, kernel module loading and other privilege-escalation-adjacent
  syscalls, fails closed on syscalls newer than the last one reviewed, and
  can be turned off per sandbox with `seccomp(false)`.
- Linux: `allow_network()` runs the sandbox in its own network namespace;
  previously a program that ignored the `HTTP_PROXY` env var could reach
  the network directly, bypassing the domain allowlist entirely.
- The `allow_network` proxy resolves each name once and connects to the
  resolved address, not the name again, closing a DNS-rebinding window; it
  also refuses destinations that resolve only to loopback, private,
  link-local or other non-public addresses unless
  `allow_private_destinations()` is set.
- Linux: `memory_limit` is now a hard limit (no `memory.high` throttling,
  no swap) -- going over it is reliably an OOM kill, not a slow crawl into
  the wall-time limit.
- Linux: a root caller's sandbox runs as `nobody`, with root's
  supplementary groups dropped, not as root inside the sandbox.
- macOS: a watchdog process kills the sandbox's process group if the host
  process dies or is killed, closing the "sandbox outlives its creator"
  window `PR_SET_PDEATHSIG` closes on Linux.
- Credentials and history files in the home directory are unreadable by
  default (`deny_read`, `hide_home`); file *names* stay visible.
- The proxy refuses requests using obsolete HTTP line folding, and caps
  header size (including a line landing exactly on the cap, which used to
  be read as end-of-headers instead of rejected).
- Fixed a fork-time race (macOS) where a concurrent `execute()` call could
  inherit a non-close-on-exec copy of an internal pipe, leaking it into an
  unrelated sandboxed program.
- Fixed a Linux cgroup cleanup path where a transient `cgroup.procs` read
  error was treated the same as "no processes left," which could end the
  kill retry loop with live processes never sent a `SIGKILL`.

### New

- `cpu_time_limit` is now also checked against the whole cgroup's total
  CPU time on Linux (`ExecutionResult::killed_by_cpu_limit`), not just
  charged to one process via `RLIMIT_CPU` -- a program that forks could
  otherwise multiply its CPU budget by however many children it starts.
- `ExecutionResult::proc_isolated`: whether the sandbox got its own private
  `/proc` (Linux only; `false` under Ubuntu 23.10+'s default AppArmor
  restriction on unprivileged user namespaces, which also skips the
  private hostname).
- `ExecutionResult::blocked_hosts`: hosts the `allow_network` proxy refused
  during the run.
- `ExecutionResult::killed_by_tmp_limit`, `output_truncated`.
- `private_tmp(size)` (on by default): a private `/tmp` per run, instead of
  the real one.
- Presets: `code_judge`, `data_analysis`, `agent_executor`, `interactive`.
- `read_only`/`writable`/`bind`/`tmpfs`/`rootfs` for filesystem setup,
  `deny_read`/`hide_home` for read restrictions.
- `max_pids`, `max_open_files`, `max_file_size`, `cpu_limit`.
- A setting a platform can't enforce is refused by `build()`
  (`SandboxError::Unsupported`), not silently ignored.
- Python bindings (`crates/nanosandbox-python`, PyO3), published to PyPI.
- Node.js bindings (`crates/nanosandbox-node`, napi-rs), published to npm.

### Fixed

Dozens of correctness and reliability fixes along the way, including: pipe
and fd leaks between runs, stdin/stdout deadlocks on >64KB of output,
zombie processes after a timeout, the child allocating memory between
`clone()` and `exec()` (a multi-threaded-process hang risk), `PATH` lookup
happening on the host instead of inside a `rootfs`, rootless cgroup
delegation under systemd, mount ordering when a `tmpfs` nests inside a
bind target (and the reverse), and more. See `git log` for the full list.

## 0.1.0

Initial prototype.

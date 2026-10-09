# Changelog

## Unreleased

### Security

- Linux: `/var/tmp` and `/dev/shm`, writable by default, each get their own
  private tmpfs per run where mounting is possible, instead of being the
  host's shared paths. (Still shared under AppArmor's `unprivileged_userns`
  restriction.)
- Linux: `socket(AF_UNIX, ...)` is denied, closing connections to host
  services over Unix sockets (`docker.sock`, the systemd bus, `ssh-agent`).
  `socketpair()` and other address families are unaffected.
- Linux: the sandboxed command runs as PID 2 under a small init shim
  instead of as PID 1, so it can signal itself and its children normally
  (before, `kill -KILL $$` inside the sandbox did nothing).

### Changed

- Linux: when the command is killed by a signal, `ExecutionResult.exit_code`
  is `128 + signal` and `signal` is `None` (before, `signal` was `Some`).
  Kills by the host's own limits (`wall_time_limit`, ...) still set it.
- Linux: `build()` refuses, for a root caller, a `writable`/`bind(ReadWrite)`
  source that `nobody` can't write to, with or without a `rootfs`, instead of
  failing at run time with `EACCES`.
- Linux: `is_platform_supported()` no longer requires cgroup v2, and now
  requires Landlock and a seccomp filter for this architecture, matching
  what building the default config needs.
- Linux: cgroup v2 is only required for configs that set a cgroup-backed
  limit.
- Python: `run()` and `run_with_input()` release the GIL while the sandbox
  runs.

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

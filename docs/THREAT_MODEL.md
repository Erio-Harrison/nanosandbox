# Threat Model

What nanosandbox protects against, on each platform, and what it doesn't.
Read this alongside [platform-linux.md](platform-linux.md),
[platform-macos.md](platform-macos.md) and
[platform-windows.md](platform-windows.md), which describe the mechanisms
this document makes claims about.

## Scope

nanosandbox runs a single command, or a tree of processes started by it, with
less access than the calling process has. It's built for: AI agents
executing tool calls, online-judge code execution, data-processing pipelines
over untrusted input -- cases where the caller controls the environment
(their own machine, their own server) and wants to run code they don't fully
trust, without that code reaching the rest of the system.

It is **not** built for multi-tenant isolation between mutually distrusting
customers on shared infrastructure (what Firecracker, gVisor or Kata exist
for). That tier of threat model assumes the host kernel itself may be
compromised by one tenant and must not affect another; nanosandbox's
boundary is enforced *by* the host kernel, not a second one underneath it.
If that's your requirement, use a VM-based sandbox instead.

## Attacker model

The attacker is the program being sandboxed, or code it runs. It has:

- Full control over its own argv, stdin, environment variables (within what
  `env`/`clear_env` pass through) and exit behavior.
- Whatever the sandbox's filesystem/network configuration grants it --
  `read_only`/`writable` mounts, `allow_network` domains, etc. are trust
  decisions the caller made, not things the attacker bypasses.
- The ability to fork, exec, spawn threads, background processes, and
  generally try to outlive or hide from the mechanisms below.

The attacker does **not** have a head start: no existing foothold on the
host, no ability to modify nanosandbox's own code or the config it's given.
This document is about what happens once untrusted code starts running
inside a sandbox built with a *correct* configuration -- not about whether
the caller configured it correctly (`writable("/")` is not a nanosandbox
bug).

## What "escapes" means here

The attacker succeeds if it can, from inside the sandbox:

- Read or write a host file/path the configuration didn't grant.
- See, signal, or otherwise affect a host process outside the sandbox's own
  process tree.
- Reach the network somewhere `allow_network`'s domain list didn't permit.
- Use more memory, CPU, wall time, or processes than configured, in a way
  that isn't eventually caught and killed.
- Outlive the sandbox's own lifetime (keep running after `run()` returns, or
  after the host process that created the sandbox dies).

## Linux

Mechanism stack: user/mount/PID/UTS/IPC/network namespaces, cgroups v2
resource accounting, a fixed fail-closed seccomp-BPF filter, Landlock for
filesystem writes outside a `rootfs`. See
[platform-linux.md](platform-linux.md) for how each is wired up.

| Claim | Mechanism | Verified by |
|---|---|---|
| Can't see host processes | PID namespace | `tests/security/escape_attempts.rs: test_pid_namespace_isolation`, `test_cannot_see_host_processes` |
| Can't create namespaces, mount, load kernel modules, touch `bpf`/`io_uring`/`userfaultfd`/`keyctl`/`perf_event_open` | seccomp-BPF, fail-closed past the last reviewed syscall | `tests/security/syscall_filter.rs` |
| Can't write outside granted paths (no `rootfs`) | Landlock. `/tmp`, `/var/tmp` and `/dev/shm` are writable by default; where mounting is possible each gets its own private tmpfs per run, so nothing written there reaches the host or another sandbox (see Known gaps for where it isn't) | `tests/security/escape_attempts.rs`, `tests/security/read_rules.rs`, `tests/security/shared_tmp_dirs.rs` |
| Can't connect to host services over Unix sockets (`docker.sock`, the systemd bus, `ssh-agent`, ...) | seccomp denies `socket(AF_UNIX, ...)` (Landlock governs creating a socket file, not connecting to one, and the filter can't read a `connect()` path). Other address families and `socketpair()` are untouched | `tests/security/syscall_filter.rs: test_filter_blocks_kernel_entry_points`, `test_denying_af_unix_sockets_does_not_break_dns_or_compilation` |
| A command can signal itself and its children normally | the command runs as PID 2 under a small init shim (PID 1), which relays signals and reaps orphans -- see "The init shim" below | `tests/security/process_management.rs: test_self_sigterm_now_works_like_anywhere_else`, `test_sandboxed_command_is_pid_2_under_the_init_shim` |
| Can't read credentials/history/`deny_read` paths by default | read-rule allowlist | `tests/security/read_rules.rs: test_credentials_unreadable_by_default` |
| Can't exceed memory/CPU/PID/wall-time limits | cgroups v2 (`memory.max`, `cpu.max`, `pids.max`) + wall-clock poll | `tests/security/resource_exhaustion.rs`, `tests/security/resource_enforcement.rs` |
| Can't reach the network outside `allow_network`'s allowlist, including via direct connection bypassing the proxy | own network namespace; the proxy is the only route out | `tests/security/network_security.rs: test_ip_bypass_blocked` |
| Can't outlive the host process | `PR_SET_PDEATHSIG` | `tests/security/process_management.rs: test_sandbox_dies_with_its_host_process` |
| Fork bombs, background processes that detach from the tracked tree | PID namespace init death takes the whole subtree down | `tests/security/resource_exhaustion.rs: test_fork_bomb_contained`, `test_subprocess_bomb_contained` |

### The init shim

The sandbox's PID namespace needs an init, and the kernel treats it
specially: a default-disposition signal sent to it by another member of the
namespace, itself included, is dropped unless it has a handler. Running the
command directly as PID 1 therefore meant `kill -KILL $$` inside the
sandbox did nothing. The command now runs as PID 2 under a small shim
(`src/platform/linux/child.rs`) that forwards signals to it and reaps
orphans, the same job `tini` does for containers.

What this does not change: `wall_time_limit`, `cpu_time_limit` and the
other limits kill from the host, in an ancestor namespace, where the
special treatment doesn't apply -- they were never affected.

One visible consequence: the shim can't die *by* a signal on behalf of the
command (the kernel would drop it), so when the command is killed by a
signal, `ExecutionResult.exit_code` is `128 + signal` and
`ExecutionResult.signal` is `None`. A kill by the host's own limits still
reports `signal`.

### ptrace is allowed, deliberately

`seccomp` does not block `ptrace`. This is a scope statement, not an
oversight: the sandbox's PID namespace holds only its own processes, so
`ptrace` lets one part of a single `run()`'s process tree fully control
another part (read/write memory, intercept syscalls) -- but both are
already the attacker's own code. It cannot reach anything outside the PID
namespace: a process inside a child PID namespace cannot see, signal, or
`ptrace` anything in an ancestor namespace, full stop, regardless of
`ptrace_scope` or capabilities. That's enforced by the namespace boundary
itself, not by seccomp.

The practical consequence: **the isolation boundary is one `run()` call, not
the individual processes inside it.** Don't use a single sandbox invocation
to run two pieces of code that need to be isolated *from each other* --
that's not what this protects. Run them in separate sandboxes.

### Known gaps

- Where AppArmor's `unprivileged_userns` profile applies (Ubuntu 23.10+,
  unprivileged and unconfined caller), nothing can be mounted, so
  `/var/tmp` and `/dev/shm` remain the host's real, shared, persistent
  paths: writable by every sandbox and the host alike. `/tmp` is covered by
  `$TMPDIR` pointing at a per-run directory there; these two have no
  equivalent. Don't rely on them being private on such a host.
- A root caller's sandbox runs as `nobody`, so a `writable`/`bind(ReadWrite)`
  source `nobody` can't write to is refused at `build()` rather than failing
  at run time. Pass `host_uid`/`host_gid` to run as the source's owner
  instead (what that user can reach on the host, the program can). The check
  reads the source's mode bits only (no ACLs).
- `allow_network`'s DNS-rebinding defense (resolve once, connect to the
  resolved address) is implemented and unit-tested, but has no real
  end-to-end adversarial test with an actual rebinding DNS server --
  deferred, see project history. The unit-level behavior is covered.
- Resource limits are per-sandbox, not system-wide: nothing stops a caller
  from running enough concurrent sandboxes to exhaust the host regardless of
  each one's individual `memory_limit`/`cpu_limit`. That's a caller-level
  capacity-planning problem, out of scope for a single sandbox's guarantees.
- `uid`/`gid` set a single identity for the whole run; nanosandbox does not
  itself enforce anything about what that uid can reach beyond the
  mechanisms above (if you set `uid(0)`, you get root's normal Linux
  permissions, mediated by everything above, same as any other uid).

## macOS

Mechanism: `sandbox-exec`/Seatbelt, a Mandatory Access Control policy
engine (TrustedBSD MAC framework) -- **not** the same class of guarantee as
Linux's namespaces. A namespace makes a resource not exist from the
sandboxed process's point of view; Seatbelt lets the resource exist and
checks each operation against a policy. The practical difference: a missed
rule, an unreviewed new syscall/API, or a bug in a specific kernel check
path can leak through Seatbelt in a way a namespace boundary structurally
can't. See [platform-macos.md](platform-macos.md)'s own comparison table.

| Claim | Mechanism | Verified by |
|---|---|---|
| Can't read credentials/`deny_read`/hidden-home paths | SBPL `file-read-data` denial | `tests/security/sbpl_rules.rs`, `tests/security/read_rules.rs` |
| Can't write outside granted paths | SBPL `file-write*` denial, default-deny | `tests/security/sbpl_rules.rs: test_read_only_filesystem` |
| Can't reach the network outside `allow_network` | SBPL denies all network except the loopback proxy port | `tests/security/sbpl_rules.rs: test_no_network_blocks_connections` |
| Eventually killed for exceeding memory | polled `proc_pid_rusage` over the run's process tree, checked every 2-10ms | `tests/security/resource_enforcement.rs: test_macos_memory_limit_enforced` |
| Outlives neither the run's timeout nor the host process | watchdog process holding a pipe the host's death closes | `tests/security/process_management.rs`, `docs/platform-macos.md` Process Lifetime |

**Not provided, structurally (not a todo -- XNU has no namespace or cgroup
equivalent):**

- No PID isolation: a sandboxed process can see and enumerate other
  processes on the system (not signal or ptrace them without its own
  permissions allowing it -- SBPL still denies `process-fork`/mach lookups
  it doesn't grant -- but it can *see* them, unlike Linux).
- No hard memory/CPU/process-count limit. `max_pids` is refused by `build()`
  (`SandboxError::Unsupported`) rather than silently accepted and ignored,
  but memory enforcement is a poll loop with a window (a short
  burst can exceed the limit before the next check catches it), and CPU
  time is `RLIMIT_CPU` per-process only -- nothing sums CPU across a
  process tree the way Linux's cgroup accounting does.
- `private_tmp` on macOS is a private directory with size checked every
  250ms and the run killed if over, not a real tmpfs with `ENOSPC` on
  write -- a short burst can exceed the configured size before the next
  check.

**Standing caveat:** `sandbox-exec`'s general/custom-profile use has been
marked deprecated by Apple since macOS 10.15, for third-party use outside
Apple's own App Sandbox entitlement system. It has not been removed as of
this writing, and major projects (Chromium) still build on the same
underlying Seatbelt mechanism (via the lower-level API, not the CLI --
nanosandbox currently spawns `/usr/bin/sandbox-exec` as a subprocess, see
`src/platform/macos/mod.rs`). There is no Apple-blessed general-purpose
replacement for this specific use case today; Endpoint Security Framework
requires an Apple-gated entitlement and a much heavier system-extension
architecture, and App Sandbox's entitlement model doesn't fit "sandbox an
arbitrary target binary" at all. This is accepted technical debt, not an
oversight -- see project history for the fuller reasoning.

## Windows

Mechanism: Job Objects (`max_pids`, `memory_limit`, `cpu_limit`) and
Restricted Tokens. **No filesystem or network isolation at all.**
`read_only`/`writable`/`deny_read`/`hide_home`/`allow_network`/`no_network`
are all refused by `build()` on Windows (`SandboxError::Unsupported`) rather
than silently ignored -- see [platform-windows.md](platform-windows.md).

What this means in practice: on Windows, nanosandbox is a resource-limit
and process-lifecycle tool, not a security sandbox. A process you run
through it on Windows can read and write anything the calling user's
account can, and reach the network freely. Do not run untrusted code
through nanosandbox on Windows and expect filesystem or network
containment -- there isn't any.

## What nanosandbox does not protect against, on any platform

- **A kernel vulnerability in the isolation mechanism itself.** Namespace,
  cgroup, seccomp, and Seatbelt escape CVEs have all happened historically,
  on real, maintained kernels. nanosandbox's guarantees are only as strong
  as the host kernel's own implementation of them.
- **A misconfigured sandbox.** `writable("/")`, `allow_network(&["*"])`-style
  overly broad grants, or disabling `seccomp` for a program that doesn't
  need it, are caller decisions this document doesn't cover.
- **Side channels.** Timing, cache, or other side-channel attacks against
  co-located processes are out of scope; nanosandbox provides no isolation
  against them on any platform (it doesn't pin CPUs, flush caches, or
  anything of that kind).
- **Supply-chain compromise of the code being run.** If the untrusted
  program itself is given credentials or capabilities through legitimate
  configuration (a `writable` mount containing secrets, `allow_network` to
  an API that returns more than intended), that data reaching the program
  is the configuration working as designed, not a sandbox failure.

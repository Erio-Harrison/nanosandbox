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

### What is in the box, and what isn't

Three layers, kept apart on purpose:

1. **The boundary (this library).** What a command's processes may read and
   write (paths), reach (network destinations), consume (resources) and how
   long they live; and the fact of a refusal reported back to the caller
   (`network_refusals`, `denied_paths`). Every claim here has a row in the
   tables below and a test; nothing else is claimed.
2. **Defaults (the presets).** Opinions about what an agent's or a judge's
   machine looks like: which directories count as toolchains, which files as
   credentials, how much `/tmp`. They live in `Sandbox::agent_executor` and
   its siblings, can be overridden, and never add a guarantee of their own.
3. **Not this library's.** What the host does with the command's output
   afterwards (running git, make or an editor over a workspace the command
   wrote to); deciding whether to grant a path the command was refused, and
   remembering that decision; copying, versioning or merging workspaces. A
   product built on nanosandbox does these with the two things the boundary
   gives it: `read_only` to pin what must not change, and `denied_paths` to
   learn what a failing command wanted.

Rules that keep it so: a builder method is added for a mechanism, never for an
opinion; a review finding is placed in a layer before it is acted on, and a
finding in the third layer is answered by this document, not by code.

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
| With a `rootfs`, a symlink left in it can't make the next run's setup create or mount anything on the host | mount targets are resolved inside the rootfs (`openat2` with `RESOLVE_IN_ROOT`), mounted through the resolved descriptor | `src/platform/linux/mount.rs` unit test `test_open_in_root_contains_symlinks` |
| Can't read, write, remove or rename another run's private temp directory (where it's a directory, not a tmpfs) | every run's directory is in one container that each run's rules deny, with only the run's own directory allowed back | `tests/security/private_tmp.rs: test_a_run_cannot_reach_another_runs_private_tmp` |
| Can't redirect a writable directory by swapping it, or a directory above it, for a symlink | the rules are attached to a descriptor opened and checked in the host before each run, against where the path led at build; a path that leads elsewhere refuses the run. Where mounting is possible the directory is a mount point and can't be moved at all | `tests/security/workspace_swap.rs` |
| Can't connect to host services over Unix sockets (`docker.sock`, the systemd bus, `ssh-agent`, ...), or to a hypervisor host over vsock | seccomp denies `socket(AF_UNIX, ...)` (Landlock governs creating a socket file, not connecting to one, and the filter can't read a `connect()` path) and `socket(AF_VSOCK, ...)`, which the network namespace doesn't cover. Other address families and `socketpair()` are untouched | `tests/security/syscall_filter.rs: test_filter_blocks_kernel_entry_points`, `test_denying_af_unix_sockets_does_not_break_dns_or_compilation` |
| A command can signal itself and its children normally | the command runs as PID 2 under a small init shim (PID 1), which relays signals and reaps orphans -- see "The init shim" below | `tests/security/process_management.rs: test_self_sigterm_now_works_like_anywhere_else`, `test_sandboxed_command_is_pid_2_under_the_init_shim` |
| Can't read credentials/history/`deny_read` paths by default, including one inside a writable directory, renamed or not | read-rule allowlist; inside a writable area, a read-only mount over the path and its parents pinned (refused where mounting isn't possible) | `tests/security/read_rules.rs: test_credentials_unreadable_by_default`, `test_deny_read_inside_a_writable_dir` |
| Can't read or write a denied file through a hard link made on the host beforehand | at `build()` the denied files with more than one name are looked for under the sandbox's directories and home, and the other names denied; a link that isn't found refuses the build | `tests/security/read_rules.rs: test_a_hard_link_to_a_denied_file_is_denied_or_refused` |
| A path granted back inside a hidden home (a toolchain directory) doesn't bring the credentials inside it | the Landlock grant is split around the denied paths inside it | `tests/security/read_rules.rs: test_a_denied_path_inside_a_granted_one_stays_denied` |
| Can't read or write the caller's terminal, or inject input into it (`TIOCSTI`) | the command runs in a new session (`setsid`), so it has no controlling terminal | `tests/security/process_management.rs: test_command_runs_in_its_own_session` |
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
signal it exits with `128 + signal` and sends the signal's number to the host
over a pipe. `ExecutionResult.exit_code` and `ExecutionResult.signal` then
read the same as on macOS, and a program that merely exits with 143 isn't
mistaken for one killed by `SIGTERM`.

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

- **What the host does with the workspace afterwards is outside the sandbox.**
  The workspace is the command's output. Anything the host runs against it
  that takes instructions from files in it executes what the command wrote:
  git (hooks, `core.hooksPath`, `core.fsmonitor`, `commondir`, the `.git`
  file's `gitdir:`, submodule links in the index), `make`, `npm install`
  scripts, `cargo` (`build.rs`, `.cargo/config.toml`), `direnv`, `pre-commit`,
  an editor's task files. The sandbox confines the command's processes; path
  rules for one tool's configuration can't cover the class, and aren't
  attempted (an earlier `.git/hooks`/`.git/config` protection was removed for
  that reason: it protected one tool against some of its entry points and
  implied more than it gave). Integrators who need a file kept can name it
  `read_only` inside the writable workspace
  (`tests/security/read_only_inside_writable.rs` does this for `.git/hooks`).
  The structural answer is a workspace the host never runs tools in: the
  command works on a copy, and what comes back is reviewed before it's used.
  That is a workspace-management concern (LayerFS and similar tools do it),
  outside this library: nanosandbox takes a directory and confines what runs
  in it, whoever made the directory.
- The hard-link search at `build()` skips home's bulk (`Library`, `.cache`,
  `node_modules`, `target`, `.git`...) and the rest of the file system; a link
  there isn't found, and the build is refused rather than the link read.
- Without a mount (so: no `rootfs`, or under the AppArmor restriction), a
  command can change the metadata -- mode, owner, timestamps, xattrs -- of
  files outside its writable areas that its uid owns or may change. Landlock
  has no right for these and seccomp can't see the path, so only a read-only
  mount (which needs mounting) stops them; `chmod -R`, say, could widen the
  caller's own files. The contents still can't be written. macOS denies these
  by default (its writes are default-deny). Inside a writable area the same
  holds for the directories above a `read_only` or denied path: a `chmod 000`
  on one of them keeps the host out of the protected file until it changes
  the mode back (the file itself is intact); macOS pins their mode, owner,
  flags and ACL along with their name.
- Without a mount, the host's `/dev` is the sandbox's: a command can see and,
  for device nodes its uid may write, write to them, including another of the
  caller's own terminals (`/dev/pts/N`). It cannot inject input into them
  (`TIOCSTI` needs a controlling terminal, which the new session drops). A
  private `/dev` with its own `devpts` needs mounting; macOS's profile scopes
  device access instead.
- `/proc/self/cgroup` shows the host's cgroup path (e.g. the systemd slice
  and scope names). This is an information leak, not access: it reveals
  naming, not contents. A cgroup namespace would hide it, but it didn't
  rebase reliably under the systemd-delegated cgroup setup concurrent runs
  use, so it isn't applied.
- Where a fresh procfs can't be mounted (under the AppArmor restriction
  below, or in a container that masks parts of its own `/proc`), the
  command sees the host's `/proc`: other processes and, for the same user,
  their `/proc/<pid>/environ`. The run still goes ahead, and
  `ExecutionResult::proc_isolated` is `false`, so a caller that needs the
  isolation can refuse the result.
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
| Can't read credentials/`deny_read`/hidden-home paths, including one inside a writable root after renaming it or a directory above it | SBPL `file-read-data` denial; `file-write-unlink` denied on such a path and its parents up to the root | `tests/security/sbpl_rules.rs`, `tests/security/read_rules.rs` |
| Can't read or write a denied file through a hard link made on the host beforehand | as on Linux: found at `build()` and denied by name (`file-read-data` and `file-write*`), or the build refused | `tests/security/read_rules.rs: test_a_hard_link_to_a_denied_file_is_denied_or_refused` |
| A path granted back inside a hidden home (a toolchain directory) doesn't bring the credentials inside it | a `file-read-data` deny for each denied path inside a grant, after the grant | `tests/security/read_rules.rs: test_a_denied_path_inside_a_granted_one_stays_denied` |
| Can't read or write the caller's terminal, or inject input into it (`TIOCSTI`) | the command runs in a new session (`setsid`), so it has no controlling terminal | `tests/security/process_management.rs: test_command_runs_in_its_own_session` |
| Can't write outside granted paths, except the temp directories | SBPL `file-write*` denial, default-deny. `/tmp`, `/private/tmp`, `/private/var/tmp` and the user's own `/private/var/folders/.../T` are writable by default and are the host's own, shared with every sandbox and the host: what a program writes there by name stays, and `private_tmp`'s limit doesn't apply to it. The user's cache directory (`.../C`) and daemon state (`.../0`) next to it are not writable. `private_tmp` gives each run its own directory through `$TMPDIR` (not a mount, so it can't hide `/tmp`). `shared_tmp(false)` makes the shared ones read-only, at the cost of some programs (see [platform-macos.md](platform-macos.md#shared_tmpfalse)) | `tests/security/sbpl_rules.rs: test_read_only_filesystem`, `src/platform/macos/profile.rs: test_shared_tmp_false_leaves_only_the_private_directory_writable` |
| Can't read, write, remove or rename another run's private temp directory (where it's a directory, not a tmpfs) | every run's directory is in one container that each run's rules deny, with only the run's own directory allowed back | `tests/security/private_tmp.rs: test_a_run_cannot_reach_another_runs_private_tmp` |
| Processes of a run that left its process group are still found and killed, at the end of the run and, if the host died, by the next run's sweep; no command can strip any run's marker files to hide them | each run's processes are told apart by a marker file pair under `$TMPDIR/nanosandbox-markers/`, which every run's profile denies writing (and denies renaming anything above it); the sweep of a dead run's pair kills what it still marks before removing it | `src/platform/macos/run_marker.rs` tests, `tests/security/process_management.rs: test_a_command_cannot_touch_any_runs_markers`, `crates/nanosandbox-mcp/tests/stdio.rs: a_dead_servers_escaped_process_is_killed_by_the_next_servers_sweep` |
| A run that forks faster than it can be killed (a fork bomb) doesn't outlive its end | every process carrying the run's marker is stopped first, repeatedly until no new one appears, then killed; what survives the 250 ms budget is logged and the marker kept for the next sweep to finish | `tests/security/process_management.rs: test_a_fork_bomb_is_killed_to_the_last_process` |
| Can't redirect a writable directory by swapping it, or a directory above it, for a symlink | the profile is made from where each path led at build, a run is refused if that changed, and a writable directory and every directory above it can't be removed or renamed (`file-write-unlink` denied) | `tests/security/workspace_swap.rs` |
| Can't reach the network outside `allow_network` | SBPL denies all network except the loopback proxy port | `tests/security/sbpl_rules.rs: test_no_network_blocks_connections` |
| Can't make the system fetch a URL for it outside the allowlist | the proxied profile leaves out `trustd` and `ocspd`, which fetch a certificate's OCSP and issuer URLs for whoever asks them to evaluate it, unless `allow_trustd()` | `src/platform/macos/profile.rs: test_proxied_profile_drops_trust_services_unless_allowed` |
| Eventually killed for exceeding memory | polled `proc_pid_rusage` over the run's process tree, checked every 2-10ms | `tests/security/resource_enforcement.rs: test_macos_memory_limit_enforced` |
| Outlives neither the run's timeout nor the host process | watchdog process holding a pipe the host's death closes | `tests/security/process_management.rs`, `docs/platform-macos.md` Process Lifetime |

**Not provided, structurally (not a todo -- XNU has no namespace or cgroup
equivalent):**

- No PID isolation: a sandboxed process can see and enumerate other
  processes on the system (not signal or ptrace them without its own
  permissions allowing it -- SBPL still denies `process-fork`/mach lookups
  it doesn't grant -- but it can *see* them, unlike Linux).
- No private `/tmp`: there are no mount namespaces to give each run its own, so a program
  that writes to `/tmp` (or `/var/folders/.../T`) by name reaches the host's, with no
  size limit and nothing cleaned up afterwards, unless
  `shared_tmp(false)` takes them away. Linux, where mounting
  is possible, gives `/tmp`, `/var/tmp` and `/dev/shm` a private tmpfs per run.
- No hard memory/CPU/process-count limit. `max_pids` is refused by `build()`
  (`SandboxError::Unsupported`) rather than silently accepted and ignored,
  but memory enforcement is a poll loop with a window (a short
  burst can exceed the limit before the next check catches it), and CPU
  time is `RLIMIT_CPU` per-process only -- nothing sums CPU across a
  process tree the way Linux's cgroup accounting does. A fork bomb runs
  until the user's own process limit, the run's wall-time limit or the
  memory limit ends the run; it is then killed to the last process
  (stop-then-kill, see [platform-macos.md](platform-macos.md#process-cleanup)),
  but until then it competes with the user's other programs for process slots.
- `private_tmp` on macOS is a private directory with size checked every
  250ms (100ms once past 60% of the limit) and the run killed if over, not
  a real tmpfs with `ENOSPC` on write -- a short burst can exceed the
  configured size before the next check.

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

Mechanism: a Job Object per run (`memory_limit`, `max_pids`,
`cpu_time_limit`). **No filesystem or network isolation at all.**
`read_only`/`writable`/`deny_read`/`hide_home`/`allow_network`/`no_network`
are all refused by `build()` on Windows (`SandboxError::Unsupported`) rather
than silently ignored -- see [platform-windows.md](platform-windows.md).

What this means in practice: on Windows, nanosandbox is a resource-limit
and process-lifecycle tool, not a security sandbox. A process you run
through it on Windows can read and write anything the calling user's
account can, and reach the network freely. Do not run untrusted code
through nanosandbox on Windows and expect filesystem or network
containment -- there isn't any.

## The audit trail

`SandboxBuilder::audit` hands a sink an event before each run and one after.
The start is recorded first, and a run whose start can't be recorded doesn't
happen, so a command is never executed unrecorded; one that began and never
ended is the trace of a host that died mid-run. With `nanosandbox-mcp
--audit-dir` the events go to files, one per server run, each line chained to
the one before by SHA-256. That makes the record *tamper-evident against the
commands it records*: it must be somewhere they can't write, and the server
refuses a place they could, and denies them reading it.

It is not tamper-proof against whoever runs the server, or has the files.
They can cut lines off the end of a session, remove a whole session, or start
a new chain, and a cut-short session just reads as one that was never sealed;
for more than that, keep a session's last hash elsewhere. It records what ran
and under which policy, not what the command did inside the files it was
allowed to write. Secret-looking arguments are redacted by pattern, so a
secret in an unusual form can get through.

Old sessions are removed: by default on starting a server, past 30 days or
1 GB, and on request by `--audit-cleanup`. Neither touches a running session,
and `--audit-cleanup` leaves one that fails to verify.

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

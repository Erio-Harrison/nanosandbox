# Linux Platform Implementation

## Technology Stack

Linux uses three kernel subsystems combined to implement sandboxing:

```
┌─────────────────────────────────────────┐
│              LinuxExecutor               │
├─────────────────────────────────────────┤
│  ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │Namespace│ │ Cgroups │ │ Seccomp │   │
│  │Isolation│ │ Limits  │ │ Filter  │   │
│  └─────────┘ └─────────┘ └─────────┘   │
├─────────────────────────────────────────┤
│            Linux Kernel 5.13+           │
└─────────────────────────────────────────┘
```

## Why Three Subsystems?

| Subsystem | Function | History |
|-----------|----------|---------|
| **Namespaces** | Process isolation | Introduced 2002, gradually improved |
| **Cgroups** | Resource limits | Introduced 2008, v2 in 2016 |
| **Seccomp** | Syscall filtering | Introduced 2005, BPF in 2012 |

These three subsystems were **developed independently**, each with its own API, so they must be implemented separately.

## 1. Namespaces (Process Isolation)

### Types

| Namespace | Isolated Resource | Clone Flag |
|-----------|-------------------|------------|
| User | UID/GID mapping | `CLONE_NEWUSER` |
| PID | Process IDs | `CLONE_NEWPID` |
| Mount | Filesystem mounts | `CLONE_NEWNS` |
| Network | Network stack (`no_network()`, `allow_network()`; not `host_network()`) | `CLONE_NEWNET` |
| UTS | Hostname | `CLONE_NEWUTS` |
| IPC | Inter-process communication | `CLONE_NEWIPC` |

### Implementation

```rust
// Use clone() to create a process with new namespaces
let clone_flags = CloneFlags::CLONE_NEWUSER
    | CloneFlags::CLONE_NEWPID
    | CloneFlags::CLONE_NEWNS
    | CloneFlags::CLONE_NEWUTS
    | CloneFlags::CLONE_NEWIPC
    | CloneFlags::CLONE_NEWNET;

let child_pid = clone(
    Box::new(child_fn),
    &mut stack,
    clone_flags,
    Some(Signal::SIGCHLD as i32),
)?;
```

### User Namespace (Most Important)

User namespace allows non-root users to create sandboxes:

```rust
pub struct UserNamespace {
    inner_uid: u32,  // UID inside sandbox
    inner_gid: u32,  // GID inside sandbox
}

impl UserNamespace {
    pub fn write_mappings(&self, child_pid: i32) -> Result<()> {
        let outer_uid = unsafe { libc::getuid() };
        let outer_gid = unsafe { libc::getgid() };

        // Disable setgroups (security requirement)
        fs::write(format!("/proc/{}/setgroups", child_pid), "deny")?;

        // UID mapping: sandbox 0 -> host current user
        fs::write(
            format!("/proc/{}/uid_map", child_pid),
            format!("{} {} 1", self.inner_uid, outer_uid)
        )?;

        // GID mapping
        fs::write(
            format!("/proc/{}/gid_map", child_pid),
            format!("{} {} 1", self.inner_gid, outer_gid)
        )?;

        Ok(())
    }
}
```

### Mount Namespace (Filesystem Isolation)

Every sandbox gets its own mount namespace. In the child, after `clone()`:

1. Mark every mount private, so nothing propagates back to the host.
2. With a `rootfs`, bind it onto itself.
3. Take a detached copy (`open_tree`) of every path to bind, before anything
   can cover it.
4. Mount the tmpfs ones: `private_tmp` at `/tmp`, and any `tmpfs()`.
5. Put each bind in place (`move_mount`). With a rootfs, every
   `read_only`/`writable`/`bind` path is created under it and bound there.
   Without one, a path at its own place is already there, and Landlock
   (below) decides whether it's writable, with no mount at all. Only these
   are bound: a `bind()` to another path, a path inside a tmpfs (created in
   it first, since the tmpfs starts empty), and a `read_only` path inside a
   writable area, where Landlock can't take writing away again.
   `build()` refuses a bind target that doesn't exist outside a tmpfs, and a
   `working_dir` inside a tmpfs that nothing is bound to.
6. Mount a fresh `/proc`, so the sandbox only sees its own PID namespace.
   With a rootfs this happens before the pivot: the kernel only allows a new
   proc mount while a fully visible one is still in the namespace.
7. With a rootfs: `chdir` into it, `pivot_root(".", ".")`, and detach the old
   root. No `put_old` directory is involved, so sandboxes can share a rootfs.

Read-only binds are remounted with `MS_RDONLY`; the kernel ignores that flag
when a bind mount is first created.

All of this runs between `clone()` and `exec()`, using paths prepared
beforehand and raw syscalls only: `clone()` copies the whole multi-threaded
parent, and allocating in the child can deadlock on a lock another thread
held at that moment.

### Landlock (Writes Without a Rootfs)

Without a `rootfs` the sandbox sees the host's file system, as the calling
user, and used to be able to write anything that user can: `~/.bashrc`,
`~/.ssh`, the code next to it. Landlock now limits writes to:

- `writable` paths, the private temp directory and `tmpfs()` mounts,
- `/tmp`, `/var/tmp` and `/dev/shm`, which programs expect to write to,
- existing files under `/dev` (`/dev/null`, a terminal), without creating
  or removing anything there.

Writing covers opening for writing, creating, removing, renaming and
(Landlock ABI 3, Linux 6.2) truncating.

Reading file contents is allowed everywhere except credentials in the home
directory (`~/.ssh`, cloud and registry credentials, histories; see
`deny_read` in [API.md](API.md)), `deny_read` paths, and with `hide_home`
the whole home directory. Landlock only allows, so "everything but these"
is spelled out: every sibling along the way from `/` down to each denied
path gets a rule, computed afresh for each run. Rules cover whole subtrees,
so listing directories stays allowed everywhere (`ls ~` works, and shows
`.ssh`), or listing `/` would have to go too.

Landlock is unprivileged: no mounts and no capabilities, so this works
under the AppArmor restriction below too. `writable(path)` opens up a host
directory with only a Landlock rule, and `read_only(path)` outside the
writable areas needs nothing at all. Like seccomp, the rules are prepared in the
parent and applied in the child just before `exec`.

`build()` refuses a sandbox without a rootfs on a kernel without Landlock
(Linux 5.13+, with `landlock` in `/sys/kernel/security/lsm`). With a rootfs
the sandbox only sees that directory, which is the caller's to write to.

### Network Namespace

`no_network()` gives the sandbox an empty network namespace. `allow_network()`
gives it one too, with the domain-whitelisting proxy as its only way out:

1. Before `exec`, the child brings up loopback in its namespace, listens on
   `127.0.0.1:<proxy port>` there, and sends that listener to the parent over
   a socketpair made before `clone()` (`SCM_RIGHTS`). The parent can't do
   this itself: entering the child's namespace takes `CAP_SYS_ADMIN` in the
   parent's own user namespace.
2. The parent's proxy accepts on that listener for the length of the run,
   and opens the outbound connections from the host's network. Closing the
   listener when the run ends lets the namespace go away.

`HTTP_PROXY`/`HTTPS_PROXY` point at `127.0.0.1:<proxy port>`, so this is
transparent to programs that use them. A program that doesn't gets nowhere:
there are no other interfaces and no DNS, and connections fail immediately
rather than timing out. Without this, the whitelist only held for programs
that chose to honor the proxy variables.

## 2. Cgroups v2 (Resource Limits)

### Controllers

| Controller | Resource | Config File |
|------------|----------|-------------|
| memory | Memory usage | `memory.max`, `memory.high` |
| cpu | CPU time | `cpu.max` |
| pids | Process count | `pids.max` |

### Implementation

```rust
pub struct CgroupManager {
    path: PathBuf,  // /sys/fs/cgroup/nanobox/<sandbox_id>
}

impl CgroupManager {
    pub fn create(sandbox_id: &str) -> Result<Self> {
        let path = Path::new("/sys/fs/cgroup/nanobox").join(sandbox_id);
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub fn set_memory_limit(&self, bytes: u64) -> Result<()> {
        fs::write(self.path.join("memory.max"), bytes.to_string())?;
        // Soft limit (triggers memory reclaim)
        fs::write(self.path.join("memory.high"), ((bytes as f64) * 0.9) as u64)?;
        Ok(())
    }

    pub fn set_cpu_limit(&self, cpus: f64) -> Result<()> {
        // cpu.max format: "quota period"
        let period = 100000u64;
        let quota = (cpus * period as f64) as u64;
        fs::write(self.path.join("cpu.max"), format!("{} {}", quota, period))?;
        Ok(())
    }

    pub fn set_pids_limit(&self, max: u32) -> Result<()> {
        fs::write(self.path.join("pids.max"), max.to_string())?;
        Ok(())
    }

    pub fn add_process(&self, pid: u32) -> Result<()> {
        fs::write(self.path.join("cgroup.procs"), pid.to_string())?;
        Ok(())
    }

    pub fn get_memory_stats(&self) -> Result<MemoryStats> {
        let peak = fs::read_to_string(self.path.join("memory.peak"))?
            .trim().parse()?;
        Ok(MemoryStats { peak })
    }
}
```

## 3. Seccomp-BPF (Syscall Filtering)

Namespaces and cgroups decide what a sandbox sees and how much it can use.
They don't reduce the kernel code it can reach, and that is where local
privilege escalations live. A nested user namespace is the usual way in: it
grants `CAP_SYS_ADMIN` over netfilter, mounts and more, inside it.

So every sandbox gets one fixed filter, installed last before `exec`:

| Blocked | Result |
|---------|--------|
| `clone`/`unshare` with any `CLONE_NEW*` flag, `setns` | `EPERM` |
| `mount`, `umount2`, `pivot_root`, the new mount API (`open_tree`, `fsopen`, ...) | `EPERM` |
| `bpf`, `perf_event_open`, `userfaultfd`, `io_uring_*` | `EPERM` |
| `keyctl`, `add_key`, `request_key` | `EPERM` |
| `init_module`, `finit_module`, `delete_module`, `kexec_load`, `kexec_file_load` | `EPERM` |
| `clone3` (its flags are behind a pointer the filter can't read) | `ENOSYS`, libc falls back to `clone` |
| Any syscall numbered above the last one reviewed (`mseal`, 6.10) | `ENOSYS` |
| A syscall from another ABI (32-bit, x32) | process killed |

Everything else is allowed, including `ptrace`: the sandbox's PID namespace
only holds its own processes, so debuggers keep working. Threads, fork/exec,
pipes, python multiprocessing, gcc and git were checked to work under it.

The `ENOSYS` rule means a syscall added to a later kernel is refused until
someone reviews it, instead of slipping past a list that predates it.
Programs already handle `ENOSYS` from new syscalls, since older kernels
return it too. Reviewing one means raising `LAST_KNOWN_SYSCALL` in
`src/platform/linux/seccomp.rs`, and adding it to `DENIED` if it belongs
there.

The filter is compiled in the parent; the child only calls `prctl(PR_SET_NO_NEW_PRIVS)`
and `seccomp(SECCOMP_SET_MODE_FILTER)`. If that fails, the program doesn't run.
x86_64 and aarch64 only: elsewhere `build()` refuses `seccomp(true)`.

`seccomp(false)` turns it off, for a program that needs one of these calls,
such as Chrome with its own sandbox enabled (or run that with `--no-sandbox`).

## Complete Execution Flow

```
Parent Process                    Child Process
      │                                 │
      │  clone(CLONE_NEW*)              │
      ├────────────────────────────────►│
      │                                 │
      │  write uid_map/gid_map          │
      ├────────────────────────────────►│
      │                                 │
      │  create cgroup + add PID        │
      ├────────────────────────────────►│
      │                                 │
      │  signal: ready                  │
      ├────────────────────────────────►│
      │                                 │ setup namespaces
      │                                 │ - sethostname()
      │                                 │ - pivot_root()
      │                                 │ - mount /proc
      │                                 │
      │                                 │ apply seccomp
      │                                 │
      │                                 │ execvp(cmd)
      │                                 │
      │  waitpid + read output          │
      │◄────────────────────────────────┤
      │                                 │
      │  cleanup cgroup                 │
      │                                 │
```

## System Requirements

### Kernel Configuration

Linux 5.13 or newer with Landlock enabled, unless every sandbox has a
`rootfs`:

```bash
# Should include "landlock"
cat /sys/kernel/security/lsm
```

```bash
# Check user namespace
cat /proc/sys/kernel/unprivileged_userns_clone
# Should output 1

# Enable (if disabled)
sudo sysctl kernel.unprivileged_userns_clone=1
```

### Cgroups v2

```bash
# Check if using cgroups v2
mount | grep cgroup2
# or
ls /sys/fs/cgroup/cgroup.controllers
```

### AppArmor on Ubuntu 23.10+

Ubuntu's AppArmor confines a freshly-created unprivileged user namespace to its
`unprivileged_userns` profile (security hardening against user-namespace-based
privilege escalation). That profile denies `CAP_SYS_ADMIN`-requiring calls
even though the kernel's own capability model would allow them for the
namespace's creator. Confirmed via `dmesg | grep apparmor` and reproduced with
a minimal `clone(CLONE_NEWUSER | CLONE_NEWUTS)` program outside of
nanosandbox entirely. It even denies reading `/` itself.

nanosandbox detects this case: the sysctl is 1, and the process is neither
root nor running under its own AppArmor profile. For such a caller:

- `build()` refuses what needs an actual mount, with an error that says why:
  `rootfs`, `tmpfs`, `bind` to another path, and `read_only` inside a
  writable area (such as a directory under `/tmp`). `read_only` and
  `writable` elsewhere are only Landlock rules, so they work.
- `private_tmp` is a private directory per run instead of a tmpfs, with
  `TMPDIR` pointing to it, as on macOS (see
  [platform-macos.md](platform-macos.md#tmpfs)). Programs that write to
  `/tmp` by name get the host's `/tmp`.
- `build()` refuses `allow_network(...)` too: loopback can't be brought up in
  the sandbox's network namespace (`CAP_NET_ADMIN` is denied), and falling
  back to the host network would let programs skip the proxy.
  `no_network()` still works.
- The sandbox gets no private `/proc` and no `hostname`. Both are skipped
  quietly, with one `tracing` warning per process, instead of writing to the
  program's stderr on every run.
- cgroup resource limits are unaffected: the parent sets those up from
  outside the user namespace.

Any of these lifts it:

```bash
# Confirm this is what's happening
sudo dmesg | grep -i "unprivileged_userns"

# Lift it until the next reboot (or persist it in /etc/sysctl.d/)
sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0
```

or run as root, or give the executable that embeds nanosandbox its own
AppArmor profile that allows `userns`.

Tests that need mounts skip themselves when this restriction applies (see
`tests/common/mod.rs`).

## References

- [Linux Namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [Cgroups v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [Seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html)
- [bubblewrap](https://github.com/containers/bubblewrap) - Excellent reference implementation

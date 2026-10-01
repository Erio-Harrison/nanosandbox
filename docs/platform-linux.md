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
│            Linux Kernel 5.10+           │
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
| Network | Network stack | `CLONE_NEWNET` |
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
2. With a `rootfs`: bind it onto itself, then for each `mount()`/`tmpfs()`
   create the target under it and mount there.
   Without one: mount straight over the host's own path. The host never sees
   these, but the target must already exist, since the sandbox can't create
   directories in places like `/`. `build()` refuses a missing target, and a
   mount target or `working_dir` that a `tmpfs()` would hide.
3. Mount a fresh `/proc`, so the sandbox only sees its own PID namespace.
   With a rootfs this happens before the pivot: the kernel only allows a new
   proc mount while a fully visible one is still in the namespace.
4. With a rootfs: `chdir` into it, `pivot_root(".", ".")`, and detach the old
   root. No `put_old` directory is involved, so sandboxes can share a rootfs.

`Permission::ReadOnly` binds are remounted with `MS_RDONLY`; the kernel
ignores that flag when a bind mount is first created. A read-write mount of a
path onto itself without a rootfs changes nothing and is skipped.

All of this runs between `clone()` and `exec()`, using paths prepared
beforehand and raw syscalls only: `clone()` copies the whole multi-threaded
parent, and allocating in the child can deadlock on a lock another thread
held at that moment.

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

### Security Levels

| Level | Description |
|-------|-------------|
| Disabled | No filtering (not recommended) |
| Strict | Only allow basic syscalls |
| Standard | Allow common safe syscalls |
| Permissive | Allow most syscalls, block dangerous ones |
| Custom | User-defined whitelist |

### Implementation

```rust
pub struct SeccompFilter;

impl SeccompFilter {
    pub fn apply(profile: &SeccompProfile) -> Result<()> {
        // Set PR_SET_NO_NEW_PRIVS (prevent privilege escalation)
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

        match profile {
            SeccompProfile::Disabled => Ok(()),
            SeccompProfile::Strict => Self::apply_strict(),
            SeccompProfile::Standard => Self::apply_standard(),
            SeccompProfile::Permissive => Self::apply_permissive(),
            SeccompProfile::Custom(syscalls) => Self::apply_custom(syscalls),
        }
    }
}

// Blocked dangerous syscalls
const BLOCKED_SYSCALLS: &[&str] = &[
    "ptrace",           // Debug other processes
    "process_vm_readv", // Read other process memory
    "kexec_load",       // Load new kernel
    "init_module",      // Load kernel modules
    "mount",            // Mount filesystems
    "pivot_root",       // Change root directory
    "setns",            // Enter other namespaces
    "unshare",          // Create new namespaces
];
```

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

- `build()` refuses `rootfs(...)`, `mount(...)` and `tmpfs(...)`, with an
  error that says why.
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

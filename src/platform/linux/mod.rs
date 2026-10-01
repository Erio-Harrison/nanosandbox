//! Linux platform implementation
//!
//! Uses Linux kernel primitives for sandboxing:
//!
//! - **Namespaces**: PID, mount, network, user, UTS, IPC isolation
//! - **Cgroups v2**: Resource limits (memory, CPU, PIDs)
//! - **Seccomp-BPF**: Syscall filtering
//! - **HTTP Proxy**: Domain whitelisting for proxied network mode

use crate::builder::{Mount, NetworkMode, Permission, SandboxConfig, SeccompProfile};
use crate::error::{Result, SandboxError};
use crate::network::ProxiedNetwork;
use crate::platform::{rlimit_cpu_secs, PlatformExecutor};
use crate::result::ExecutionResult;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{IntoRawFd, RawFd};
use std::time::{Duration, Instant};

mod cgroup;
mod namespace;
mod seccomp;

pub use cgroup::CgroupManager;
pub use namespace::UserNamespace;
pub use seccomp::SeccompFilter;

/// RawFd version of close
fn close_raw(fd: RawFd) -> nix::Result<()> {
    let ret = unsafe { libc::close(fd) };
    nix::errno::Errno::result(ret).map(|_| ())
}

/// RawFd version of write
fn write_raw(fd: RawFd, data: &[u8]) -> nix::Result<usize> {
    let ret = unsafe { libc::write(fd, data.as_ptr() as _, data.len()) };
    nix::errno::Errno::result(ret).map(|r| r as usize)
}

/// RawFd version of read
fn read_raw(fd: RawFd, buf: &mut [u8]) -> nix::Result<usize> {
    let ret = unsafe { libc::read(fd, buf.as_mut_ptr() as _, buf.len()) };
    nix::errno::Errno::result(ret).map(|r| r as usize)
}

/// Resolves `cmd` to the path execve should run, searching `path_value`
/// (":"-separated) the way execvp searches $PATH -- done ahead of clone()
/// against our own desired PATH value, since the child execs with an
/// explicit envp instead of consulting (or mutating) the process's real
/// environment. A `cmd` containing '/' is used as-is (resolved against the
/// child's cwd at exec time, matching execvp); nothing found in path_value
/// falls back to `cmd_cstr` unresolved, so exec fails the same way execvp's
/// own not-found case would.
fn resolve_in_path(cmd: &str, cmd_cstr: &CString, path_value: &str) -> CString {
    if cmd.contains('/') {
        return cmd_cstr.clone();
    }
    for dir in path_value.split(':').filter(|d| !d.is_empty()) {
        let candidate = std::path::Path::new(dir).join(cmd);
        let Ok(candidate_c) = CString::new(candidate.as_os_str().as_bytes()) else {
            continue;
        };
        if unsafe { libc::access(candidate_c.as_ptr(), libc::X_OK) } == 0 {
            return candidate_c;
        }
    }
    cmd_cstr.clone()
}

/// Check if Linux sandboxing is supported
pub fn is_supported() -> bool {
    // Check for user namespace support
    check_user_namespace_support() && check_cgroup_v2_support()
}

fn check_user_namespace_support() -> bool {
    // Check if unprivileged user namespaces are enabled
    std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .map(|s| s.trim() == "1")
        .unwrap_or(true) // If file doesn't exist, assume enabled (newer kernels)
}

fn check_cgroup_v2_support() -> bool {
    // Check if cgroup v2 is mounted
    std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

/// Linux sandbox executor
pub struct LinuxExecutor {
    _private: (),
}

impl LinuxExecutor {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for LinuxExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformExecutor for LinuxExecutor {
    fn execute(
        &self,
        config: &SandboxConfig,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        proxy: Option<&ProxiedNetwork>,
    ) -> Result<ExecutionResult> {
        use nix::sched::{clone, CloneFlags};
        use nix::sys::signal::Signal;
        use nix::unistd::pipe;

        const STACK_SIZE: usize = 1024 * 1024;

        let start = Instant::now();

        // Create pipes for stdout, stderr, and synchronization
        let (r, w) = pipe()
            .map_err(|e| SandboxError::Internal(format!("create pipe for child stdout: {e}")))?;
        let stdout_read: RawFd = r.into_raw_fd();
        let stdout_write: RawFd = w.into_raw_fd();

        let (r, w) = pipe()
            .map_err(|e| SandboxError::Internal(format!("create pipe for child stderr: {e}")))?;
        let stderr_read: RawFd = r.into_raw_fd();
        let stderr_write: RawFd = w.into_raw_fd();

        let (r, w) = pipe().map_err(|e| {
            SandboxError::Internal(format!("create pipe for parent-child sync: {e}"))
        })?;
        let ready_read: RawFd = r.into_raw_fd();
        let ready_write: RawFd = w.into_raw_fd();

        let (stdin_read, stdin_write) = if stdin.is_some() {
            let (r, w) = pipe()
                .map_err(|e| SandboxError::Internal(format!("create pipe for child stdin: {e}")))?;
            (Some(r.into_raw_fd()), Some(w.into_raw_fd()))
        } else {
            (None, None)
        };

        // Build clone flags
        let mut clone_flags = CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWIPC;

        if matches!(config.network_mode, NetworkMode::None) {
            clone_flags |= CloneFlags::CLONE_NEWNET;
        }

        // Create and configure the cgroup leaf *before* clone(), so a failure
        // here (rootless with no delegated subtree, a missing controller...)
        // never leaves a half-started child stuck on the ready pipe. Adding
        // the process to it is the only step that needs child_pid, so it's
        // the only cgroup step that still happens after clone() below.
        let cgroup_controllers = needed_cgroup_controllers(config);
        let cgroup = if !cgroup_controllers.is_empty() {
            let leaf_id = cgroup::next_leaf_id();
            let cg = CgroupManager::create(&leaf_id, &cgroup_controllers)?;
            if let Some(memory) = config.memory_limit {
                cg.set_memory_limit(memory)?;
            }
            if let Some(cpu) = config.cpu_limit {
                cg.set_cpu_limit(cpu)?;
            }
            if let Some(pids) = config.max_pids {
                cg.set_pids_limit(pids)?;
            }
            Some(cg)
        } else {
            None
        };

        // Prepare command arguments
        let cmd_cstr = CString::new(cmd)?;
        let args_cstr: Vec<CString> = std::iter::once(cmd_cstr.clone())
            .chain(args.iter().map(|s| CString::new(*s).unwrap()))
            .collect();

        // Allocate stack for child
        let mut stack = vec![0u8; STACK_SIZE];

        let seccomp_profile = config.seccomp_profile.clone();
        let mut env = config.env.clone();

        // Add proxy environment variables if using proxied network
        if let Some(proxy) = proxy {
            for (key, value) in proxy.env_vars() {
                env.insert(key, value);
            }
        }
        if !env.contains_key("PATH") {
            env.insert(
                "PATH".to_string(),
                "/usr/local/bin:/usr/bin:/bin".to_string(),
            );
        }

        // Built here, before clone(), and just used as-is in the child --
        // not with std::env::set_var/remove_var there. clone() copies this
        // whole (multi-threaded) process's memory, but only the calling
        // thread continues in the child; if another thread here happened to
        // be inside std::env's internal lock at that exact instant, the
        // child inherits it frozen "locked", and its own env mutation later
        // waits forever on a thread that doesn't exist in this process.
        // Confirmed for real under enough concurrent sandbox creation: the
        // child hangs there, or execs with a stale/corrupted environment.
        let envp_cstr: Vec<CString> = env
            .iter()
            .filter_map(|(k, v)| CString::new(format!("{k}={v}")).ok())
            .collect();
        let exec_path = resolve_in_path(
            cmd,
            &cmd_cstr,
            env.get("PATH").map(String::as_str).unwrap_or(""),
        );

        // execve's own nix wrapper builds a NUL-terminated pointer array
        // from these each time it's called -- an allocation that, unlike
        // the ones above, sits on the ordinary success path too, not just
        // an error branch. Building it here instead, once, means the
        // child's own execve call is just two pointer derefs and a raw
        // syscall, no allocation at all. args_cstr/envp_cstr are moved into
        // the closure alongside these so the strings they point into stay
        // alive for the call.
        let mut args_ptrs: Vec<*const libc::c_char> =
            args_cstr.iter().map(|c| c.as_ptr()).collect();
        args_ptrs.push(std::ptr::null());
        let mut envp_ptrs: Vec<*const libc::c_char> =
            envp_cstr.iter().map(|c| c.as_ptr()).collect();
        envp_ptrs.push(std::ptr::null());

        // A pre-built CString, used with raw stat()/chdir() in the child
        // instead of Path::exists()/std::env::set_current_dir() -- both
        // allocate internally (building their own CString from the path),
        // and any allocation in the child risks the same frozen-malloc-lock
        // hang as the std::env case above (see the comment on envp_cstr):
        // clone() is a raw syscall here, not libc's fork(), so it doesn't
        // get glibc's pthread_atfork() malloc-lock protection either.
        // Confirmed for real via gdb: a child stuck in malloc, called from
        // eprintln!, itself called from this closure after clone().
        let working_dir_cstr = CString::new(config.working_dir.as_os_str().as_bytes()).ok();
        let hostname = config.hostname.clone();
        let mount_plan = match &config.rootfs {
            Some(rootfs) => Some(MountPlan::new(
                rootfs,
                &config.mounts,
                &config.tmpfs_mounts,
            )?),
            None => None,
        };

        // Applied with raw setrlimit() in the child; built here for the same
        // no-allocation-after-clone() reason as everything above. These used
        // to be silently ignored on Linux -- confirmed for real: `ulimit -n`
        // reported 1024 under max_open_files(20), and cpu_time_limit (the
        // code_judge preset's main limit) wasn't applied at all.
        let mut rlimits = Vec::new();
        if let Some(n) = config.max_open_files {
            rlimits.push((
                libc::RLIMIT_NOFILE,
                u64::from(n),
                &b"Failed to apply max_open_files\n"[..],
            ));
        }
        if let Some(size) = config.max_file_size {
            rlimits.push((
                libc::RLIMIT_FSIZE,
                size,
                &b"Failed to apply max_file_size\n"[..],
            ));
        }
        if let Some(cpu) = config.cpu_time_limit {
            rlimits.push((
                libc::RLIMIT_CPU,
                rlimit_cpu_secs(cpu),
                &b"Failed to apply cpu_time_limit\n"[..],
            ));
        }

        // Create user namespace config
        let user_ns = UserNamespace::new(config.uid, config.gid);

        // Child process entry point
        let child_fn: Box<dyn FnMut() -> isize> = Box::new(move || {
            // Keeps these alive in the child for as long as args_ptrs/
            // envp_ptrs (which point into their buffers) are in use below --
            // an explicit move rather than relying on them happening to
            // outlive clone() by virtue of where they're declared above.
            let _args_cstr = &args_cstr;
            let _envp_cstr = &envp_cstr;

            // Create a new process group with this process as leader
            // This allows us to kill all children with killpg
            unsafe {
                libc::setpgid(0, 0);
            }

            // clone() gave us a copy of both pipe ends. Close our own copy
            // of the write end *before* reading: otherwise, if the parent
            // (the intended writer) dies before signaling us, the pipe
            // never reaches EOF — our own inherited copy keeps it "open" —
            // and the read below blocks forever instead of returning.
            // Confirmed for real: a parent killed between clone() and its
            // own write+close left the child permanently stuck here, never
            // reaching exec, reparented to init once the parent was gone.
            let _ = close_raw(ready_write);

            // Wait for parent to setup UID/GID mappings and place us in our
            // cgroup. 0 bytes read means EOF — the parent died before
            // signaling — nothing valid to continue with either way.
            let mut buf = [0u8; 1];
            match read_raw(ready_read, &mut buf) {
                Ok(1) => {}
                _ => return 1,
            }
            let _ = close_raw(ready_read);

            // Setup stdin
            if let Some(stdin_fd) = stdin_read {
                unsafe {
                    libc::dup2(stdin_fd, libc::STDIN_FILENO);
                }
                let _ = close_raw(stdin_fd);
            }
            // clone() inherited our copy of the write end too (pipe() isn't
            // O_CLOEXEC); left open, it survives execvp and keeps the pipe's
            // write side alive under the exec'd program, so it never sees
            // EOF on stdin. Close it — we (the child) never write to it.
            if let Some(fd) = stdin_write {
                let _ = close_raw(fd);
            }

            // Redirect stdout/stderr
            unsafe {
                libc::dup2(stdout_write, libc::STDOUT_FILENO);
                libc::dup2(stderr_write, libc::STDERR_FILENO);
            }
            let _ = close_raw(stdout_write);
            let _ = close_raw(stderr_write);
            let _ = close_raw(stdout_read);
            let _ = close_raw(stderr_read);

            // Setup hostname (UTS namespace). Error messages below are
            // fixed strings via raw write(), not eprintln!/format! -- see
            // the comment on working_dir_cstr above for why.
            // Raw libc call, not nix's wrapper: sethostname() takes a
            // buffer and length, not a NUL-terminated string, so this
            // doesn't need a CString and doesn't allocate either way, but
            // calling it directly removes any doubt.
            if nix::unistd::sethostname(&hostname).is_err() {
                let _ = write_raw(2, b"Failed to set hostname\n");
            }

            // Setup mount namespace if needed
            if let Some(plan) = &mount_plan {
                if let Err(step) = plan.apply() {
                    let _ = write_raw(2, b"Mount setup failed: ");
                    let _ = write_raw(2, step.as_bytes());
                    let _ = write_raw(2, b"\n");
                    return 1;
                }
            }

            // Environment is passed explicitly to execve below, not set via
            // std::env here -- see the comment where envp_cstr is built.

            // Change working directory, via raw stat()/chdir() rather than
            // Path::exists()/std::env::set_current_dir() -- see working_dir_cstr.
            if let Some(dir) = &working_dir_cstr {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::stat(dir.as_ptr(), &mut st) } == 0 {
                    unsafe {
                        libc::chdir(dir.as_ptr());
                    }
                }
            }

            for (resource, value, failure) in &rlimits {
                let limit = libc::rlimit {
                    rlim_cur: *value as libc::rlim_t,
                    rlim_max: *value as libc::rlim_t,
                };
                if unsafe { libc::setrlimit(*resource, &limit) } != 0 {
                    let _ = write_raw(2, failure);
                    return 1;
                }
            }

            // Apply seccomp filter
            if !matches!(seccomp_profile, SeccompProfile::Disabled)
                && SeccompFilter::apply(&seccomp_profile).is_err()
            {
                let _ = write_raw(2, b"Seccomp setup failed\n");
            }

            // Execute. Raw libc call with the pointer arrays built ahead of
            // clone() above, not nix's execve() wrapper -- see args_ptrs.
            unsafe {
                libc::execve(exec_path.as_ptr(), args_ptrs.as_ptr(), envp_ptrs.as_ptr());
            }
            let _ = write_raw(2, b"execve failed\n");
            127
        });

        // Clone child
        let child_pid = unsafe {
            clone(
                child_fn,
                &mut stack,
                clone_flags,
                Some(Signal::SIGCHLD as i32),
            )
        }
        .map_err(|e| SandboxError::Internal(format!("clone sandboxed process: {e}")))?;

        // Parent process

        // Everything here runs before the child is ever signaled to
        // continue past its ready-pipe wait (below) — it's stuck there
        // regardless of what we do, so any failure in this block must
        // kill and reap it before returning, not just propagate the error
        // and leave it parked forever. Folded into one closure so every
        // early return here goes through that same cleanup, rather than
        // needing it repeated (and, before, missed) at each fallible step.
        let setup: Result<()> = (|| {
            close_raw(ready_read).map_err(|e| {
                SandboxError::Internal(format!("close sync pipe read end in parent: {e}"))
            })?;
            close_raw(stdout_write).map_err(|e| {
                SandboxError::Internal(format!("close stdout pipe write end in parent: {e}"))
            })?;
            close_raw(stderr_write).map_err(|e| {
                SandboxError::Internal(format!("close stderr pipe write end in parent: {e}"))
            })?;
            if let Some(fd) = stdin_read {
                close_raw(fd).map_err(|e| {
                    SandboxError::Internal(format!("close stdin pipe read end in parent: {e}"))
                })?;
            }
            user_ns.write_mappings(child_pid.as_raw())?;
            if let Some(ref cg) = cgroup {
                cg.add_process(child_pid.as_raw() as u32)?;
            }
            Ok(())
        })();
        if let Err(e) = setup {
            let _ = nix::sys::signal::kill(child_pid, Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(child_pid, None);
            return Err(e);
        }

        // Signal child to continue.
        write_raw(ready_write, &[0u8])
            .map_err(|e| SandboxError::Internal(format!("signal child to continue: {e}")))?;
        close_raw(ready_write).map_err(|e| {
            SandboxError::Internal(format!("close sync pipe write end after signaling: {e}"))
        })?;

        // Stdin is written inside wait_with_timeout's own loop, interleaved
        // with draining stdout/stderr — not sequentially before it. A
        // program that echoes input to output as it goes (e.g. `cat`) can
        // block once >64KB of it is buffered and unread, which stops it
        // reading more stdin in turn; writing all of stdin here first,
        // before anything reads stdout/stderr at all, deadlocks against
        // that (confirmed for real with a 200KB input).
        let stdin_pipe = match (stdin, stdin_write) {
            (Some(data), Some(fd)) => Some((fd, data)),
            _ => None,
        };

        // Wait for child with timeout
        let timeout = config.wall_time_limit.unwrap_or(Duration::from_secs(3600));
        let (stdout, stderr, exit_code, killed_by_timeout, signal) =
            wait_with_timeout(child_pid, stdout_read, stderr_read, stdin_pipe, timeout)?;

        // Collect resource stats BEFORE cgroup cleanup
        let (peak_memory, cpu_time, killed_by_oom) = if let Some(ref cg) = cgroup {
            let peak = cg.get_memory_stats().ok().map(|s| s.peak);
            let cpu = cg
                .get_cpu_stats()
                .ok()
                .map(|s| Duration::from_micros(s.total_usec));
            let oom = cg.was_oom_killed();
            (peak, cpu, oom)
        } else {
            (None, None, false)
        };

        // Cgroup will be cleaned up when dropped

        Ok(ExecutionResult {
            stdout,
            stderr,
            exit_code,
            duration: start.elapsed(),
            killed_by_timeout,
            killed_by_oom,
            signal,
            peak_memory,
            cpu_time,
        })
    }

    fn check_support(&self, config: &SandboxConfig) -> Result<()> {
        if !check_user_namespace_support() {
            return Err(SandboxError::UserNamespaceDisabled);
        }
        if !check_cgroup_v2_support() {
            return Err(SandboxError::CgroupV2Unavailable);
        }
        let needed = needed_cgroup_controllers(config);
        if !needed.is_empty() {
            CgroupManager::ensure_support(&needed)?;
        }
        Ok(())
    }
}

/// Which cgroup v2 controllers this config's limits actually need.
fn needed_cgroup_controllers(config: &SandboxConfig) -> Vec<&'static str> {
    let mut needed = Vec::new();
    if config.memory_limit.is_some() {
        needed.push("memory");
    }
    if config.cpu_limit.is_some() {
        needed.push("cpu");
    }
    if config.max_pids.is_some() {
        needed.push("pids");
    }
    needed
}

/// One mount-namespace setup step, with every path and option string
/// already built -- see `MountPlan`.
enum MountStep {
    /// `mkdir`, EEXIST ignored. Issued per path component, in order with the
    /// mounts, so a target nested inside an earlier mount is created inside
    /// that mount, same as `create_dir_all` right before each mount was.
    Mkdir(CString),
    /// `readonly` holds the source's locked flags (nosuid/nodev/noexec) to
    /// repeat on the read-only remount: in a user namespace, a remount that
    /// drops a locked flag fails with EPERM.
    Bind {
        source: CString,
        target: CString,
        readonly: Option<libc::c_ulong>,
    },
    Tmpfs {
        target: CString,
        options: CString,
    },
}

/// Everything the child needs to set up its mount namespace, built before
/// clone() so the child only issues raw syscalls -- the same
/// no-allocation-after-clone() rule as envp_cstr/working_dir_cstr.
struct MountPlan {
    rootfs: CString,
    steps: Vec<MountStep>,
}

impl MountPlan {
    fn new(
        rootfs: &std::path::Path,
        mounts: &[Mount],
        tmpfs_mounts: &[(std::path::PathBuf, u64)],
    ) -> Result<Self> {
        let mut steps = Vec::new();
        for m in mounts {
            let target = Self::push_mkdirs(&mut steps, rootfs, &m.target)?;
            let source = path_cstring(&m.source)?;
            let readonly = (m.permission == Permission::ReadOnly).then(|| locked_flags(&source));
            steps.push(MountStep::Bind {
                source,
                target,
                readonly,
            });
        }
        for (path, size) in tmpfs_mounts {
            let target = Self::push_mkdirs(&mut steps, rootfs, path)?;
            let options = CString::new(format!("size={size}")).expect("no NUL in a number");
            steps.push(MountStep::Tmpfs { target, options });
        }
        Ok(Self {
            rootfs: path_cstring(rootfs)?,
            steps,
        })
    }

    /// Queues a mkdir for each component of `target` under `rootfs`, returning
    /// the full target path.
    fn push_mkdirs(
        steps: &mut Vec<MountStep>,
        rootfs: &std::path::Path,
        target: &std::path::Path,
    ) -> Result<CString> {
        let mut path = rootfs.to_path_buf();
        for component in target.strip_prefix("/").unwrap_or(target).components() {
            path.push(component);
            steps.push(MountStep::Mkdir(path_cstring(&path)?));
        }
        path_cstring(&path)
    }

    /// Runs in the child between clone() and exec(): raw syscalls only.
    /// The error names the step that failed, as a static string.
    fn apply(&self) -> std::result::Result<(), &'static str> {
        let null = std::ptr::null();
        unsafe {
            if libc::mount(
                null,
                c"/".as_ptr(),
                null,
                libc::MS_REC | libc::MS_PRIVATE,
                null as _,
            ) != 0
            {
                return Err("mark all mounts as private");
            }
            let rootfs = self.rootfs.as_ptr();
            if libc::mount(
                rootfs,
                rootfs,
                null,
                libc::MS_BIND | libc::MS_REC,
                null as _,
            ) != 0
            {
                return Err("bind mount rootfs");
            }
            for step in &self.steps {
                match step {
                    MountStep::Mkdir(path) => {
                        if libc::mkdir(path.as_ptr(), 0o755) != 0
                            && *libc::__errno_location() != libc::EEXIST
                        {
                            return Err("create mount target");
                        }
                    }
                    MountStep::Bind {
                        source,
                        target,
                        readonly,
                    } => {
                        if libc::mount(
                            source.as_ptr(),
                            target.as_ptr(),
                            null,
                            libc::MS_BIND,
                            null as _,
                        ) != 0
                        {
                            return Err("bind mount");
                        }
                        // MS_RDONLY is ignored when a bind mount is created;
                        // it only takes effect on a remount. Confirmed for
                        // real: a ReadOnly mount without this was writable,
                        // and the write landed on the host directory.
                        if let Some(locked) = readonly {
                            let flags = libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | locked;
                            if libc::mount(null, target.as_ptr(), null, flags, null as _) != 0 {
                                return Err("remount bind mount read-only");
                            }
                        }
                    }
                    MountStep::Tmpfs { target, options } => {
                        let tmpfs = c"tmpfs".as_ptr();
                        if libc::mount(tmpfs, target.as_ptr(), tmpfs, 0, options.as_ptr() as _) != 0
                        {
                            return Err("mount tmpfs");
                        }
                    }
                }
            }
            // pivot_root(".", ".") then detaching "." stacks the old root on
            // the new one and drops it, with no put_old directory. Every
            // sandbox used to share one `<rootfs>/old_root`, so concurrent
            // runs on the same rootfs raced creating, pivoting into, and
            // removing it -- confirmed for real as "Mount setup failed" under
            // 20 concurrent runs. Same approach as runc.
            if libc::chdir(rootfs) != 0 {
                return Err("chdir into rootfs");
            }
            if libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) != 0 {
                return Err("pivot_root");
            }
            if libc::umount2(c".".as_ptr(), libc::MNT_DETACH) != 0 {
                return Err("detach old root");
            }
            if libc::chdir(c"/".as_ptr()) != 0 {
                return Err("chdir to new root");
            }
        }
        Ok(())
    }
}

fn path_cstring(path: &std::path::Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| SandboxError::Config(format!("path contains a NUL byte: {}", path.display())))
}

/// nosuid/nodev/noexec currently set on the mount holding `path`.
fn locked_flags(path: &CString) -> libc::c_ulong {
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 {
        return 0;
    }
    let mut flags = 0;
    for (st_flag, ms_flag) in [
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
    ] {
        if st.f_flag & st_flag != 0 {
            flags |= ms_flag;
        }
    }
    flags
}

fn wait_with_timeout(
    pid: nix::unistd::Pid,
    stdout_fd: RawFd,
    stderr_fd: RawFd,
    mut stdin: Option<(RawFd, &[u8])>,
    timeout: Duration,
) -> Result<(String, String, i32, bool, Option<i32>)> {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

    let start = Instant::now();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut killed_by_timeout = false;

    // Set non-blocking
    unsafe {
        let flags = libc::fcntl(stdout_fd, libc::F_GETFL);
        libc::fcntl(stdout_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        let flags = libc::fcntl(stderr_fd, libc::F_GETFL);
        libc::fcntl(stderr_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    if let Some((fd, _)) = stdin {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    loop {
        // Write more stdin, non-blocking, interleaved with draining
        // stdout/stderr below — not all upfront. A program that echoes
        // input to output as it goes (e.g. `cat`) can block on writing its
        // own output once enough of it is buffered and unread, which stops
        // it reading more stdin in turn; writing stdin to completion
        // before anything reads stdout/stderr deadlocks against exactly
        // that, confirmed for real with input over the output pipe's size.
        if let Some((fd, data)) = &mut stdin {
            if !data.is_empty() {
                match write_raw(*fd, data) {
                    Ok(n) if n > 0 => *data = &data[n..],
                    Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EINTR) => {}
                    // Either wrote 0 (shouldn't happen for non-empty data)
                    // or the reader's gone (e.g. EPIPE) — nothing more to
                    // usefully write either way.
                    _ => *data = &[],
                }
            }
            if data.is_empty() {
                let _ = close_raw(*fd);
                stdin = None;
            }
        }

        // Read available output
        let mut buf = [0u8; 4096];
        if let Ok(n) = read_raw(stdout_fd, &mut buf) {
            if n > 0 {
                stdout.extend_from_slice(&buf[..n]);
            }
        }
        if let Ok(n) = read_raw(stderr_fd, &mut buf) {
            if n > 0 {
                stderr.extend_from_slice(&buf[..n]);
            }
        }

        match waitpid(pid, Some(WaitPidFlag::WNOHANG))
            .map_err(|e| SandboxError::Internal(format!("waitpid for child {pid}: {e}")))?
        {
            WaitStatus::Exited(_, code) => {
                if let Some((fd, _)) = stdin.take() {
                    let _ = close_raw(fd);
                }
                drain_fd(stdout_fd, &mut stdout);
                drain_fd(stderr_fd, &mut stderr);
                close_raw(stdout_fd).ok();
                close_raw(stderr_fd).ok();
                return Ok((
                    String::from_utf8_lossy(&stdout).to_string(),
                    String::from_utf8_lossy(&stderr).to_string(),
                    code,
                    killed_by_timeout,
                    None,
                ));
            }
            WaitStatus::Signaled(_, sig, _) => {
                if let Some((fd, _)) = stdin.take() {
                    let _ = close_raw(fd);
                }
                drain_fd(stdout_fd, &mut stdout);
                drain_fd(stderr_fd, &mut stderr);
                close_raw(stdout_fd).ok();
                close_raw(stderr_fd).ok();
                return Ok((
                    String::from_utf8_lossy(&stdout).to_string(),
                    String::from_utf8_lossy(&stderr).to_string(),
                    128 + sig as i32,
                    killed_by_timeout,
                    Some(sig as i32),
                ));
            }
            WaitStatus::StillAlive => {
                if start.elapsed() > timeout && !killed_by_timeout {
                    // Kill the entire process group (negative PID)
                    // The child runs in a PID namespace where it's PID 1,
                    // but from our namespace we see the real PID.
                    // Use SIGKILL on the process - the PID namespace
                    // will ensure all children are killed when init (pid 1) dies.
                    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);

                    // Also try to kill the process group just in case
                    unsafe {
                        libc::kill(-(pid.as_raw()), libc::SIGKILL);
                    }

                    killed_by_timeout = true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn drain_fd(fd: RawFd, buf: &mut Vec<u8>) {
    let mut tmp = [0u8; 4096];
    loop {
        match read_raw(fd, &mut tmp) {
            Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            _ => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_executor_creation() {
        let executor = LinuxExecutor::new();
        let _ = executor;
    }
}

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
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
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

        // Proxied gets its own network namespace too, with the proxy as its
        // only way out (see `ProxyLink`). Without one, the domain whitelist
        // only held for programs that chose to honor HTTP_PROXY -- confirmed
        // for real: `curl --noproxy '*'` reached 1.1.1.1, example.org and
        // github.com straight past it.
        if !matches!(config.network_mode, NetworkMode::Host) {
            clone_flags |= CloneFlags::CLONE_NEWNET;
        }
        let mut proxy_link = match (&config.network_mode, proxy) {
            (NetworkMode::Proxied { .. }, Some(proxy)) => Some(ProxyLink::new(proxy.port())?),
            _ => None,
        };

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
        // Where AppArmor denies mounting and sethostname in the sandbox's
        // user namespace, skip both instead of having every run log their
        // failure to the program's stderr. check_mounts already refused any
        // mounts the caller asked for here at build() time.
        let userns_restricted = userns_restricted_by_apparmor();
        if userns_restricted {
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                tracing::warn!(
                    "AppArmor's unprivileged_userns profile applies here, so sandboxes get no \
                     private /proc or hostname (see docs/platform-linux.md)"
                )
            });
        }
        let mount_plan = if userns_restricted {
            None
        } else {
            Some(MountPlan::new(
                config.rootfs.as_deref(),
                &config.mounts,
                &config.tmpfs_mounts,
            )?)
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

        let proxy_link_child = proxy_link.as_ref().map(ProxyLink::child_side);

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
            // the comment on working_dir_cstr above for why. nix's
            // sethostname passes the &str's bytes and length straight to
            // libc (no CString), so it doesn't allocate.
            if !userns_restricted && nix::unistd::sethostname(&hostname).is_err() {
                let _ = write_raw(2, b"Failed to set hostname\n");
            }

            // Mount namespace: caller's rootfs/mounts/tmpfs, then a private
            // /proc, then pivot into the rootfs if any. A failure in what the
            // caller asked for fails the run; /proc alone is best effort.
            if let Some(plan) = &mount_plan {
                let fatal = |step: &str| {
                    let _ = write_raw(2, b"Mount setup failed: ");
                    let _ = write_raw(2, step.as_bytes());
                    let _ = write_raw(2, b"\n");
                    1
                };
                match plan.apply() {
                    Err(step) if plan.requested() => return fatal(step),
                    Err(_) => {
                        let _ = write_raw(2, b"Failed to mount /proc\n");
                    }
                    Ok(()) => {
                        if !plan.mount_proc() {
                            let _ = write_raw(2, b"Failed to mount /proc\n");
                        }
                        if let Err(step) = plan.enter_rootfs() {
                            return fatal(step);
                        }
                    }
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

            // Before the rlimits: a small max_open_files could stop these
            // sockets from opening.
            if let Some(link) = proxy_link_child {
                if let Err(step) = link.bind_and_send() {
                    let _ = write_raw(2, b"Network setup failed: ");
                    let _ = write_raw(2, step.as_bytes());
                    let _ = write_raw(2, b"\n");
                    return 1;
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

        if let Some(link) = &mut proxy_link {
            link.close_child_end();
        }

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

        // Serve the proxy on the listener the child just bound inside its
        // network namespace, for exactly as long as this run lasts: kept
        // open, it would also keep that namespace alive. No listener means
        // the child failed its network setup, and already said why on its
        // stderr before exiting, which the wait below collects.
        let proxy_attachment = match (&proxy_link, proxy) {
            (Some(link), Some(proxy)) => match link.receive().map(|l| proxy.attach(l)) {
                Some(Err(e)) => {
                    let _ = nix::sys::signal::kill(child_pid, Signal::SIGKILL);
                    let _ = nix::sys::wait::waitpid(child_pid, None);
                    return Err(SandboxError::Internal(format!(
                        "serve the proxy inside the sandbox: {e}"
                    )));
                }
                attached => attached.transpose().ok().flatten(),
            },
            _ => None,
        };

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
        let (stdout, stderr, exit_code, killed_by_timeout, signal, rusage) =
            wait_with_timeout(child_pid, stdout_read, stderr_read, stdin_pipe, timeout)?;
        drop(proxy_attachment);

        // Without a cgroup, these used to be None. wait4's rusage is the
        // fallback: its CPU time sums the child and the descendants it waited
        // for, and its maxrss is the largest single one of them (not a total).
        // The cgroup's numbers, which cover the whole tree, win when there.
        let tv = |t: libc::timeval| {
            Duration::from_secs(t.tv_sec as u64) + Duration::from_micros(t.tv_usec as u64)
        };
        let rusage_cpu = tv(rusage.ru_utime) + tv(rusage.ru_stime);
        let rusage_peak = rusage.ru_maxrss as u64 * 1024; // Linux reports KiB

        // Collect resource stats BEFORE cgroup cleanup
        let (peak_memory, cpu_time, killed_by_oom) = if let Some(ref cg) = cgroup {
            let peak = cg.get_memory_stats().ok().map(|s| s.peak);
            let cpu = cg
                .get_cpu_stats()
                .ok()
                .map(|s| Duration::from_micros(s.total_usec));
            let oom = cg.was_oom_killed();
            (peak.or(Some(rusage_peak)), cpu.or(Some(rusage_cpu)), oom)
        } else {
            (Some(rusage_peak), Some(rusage_cpu), false)
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
        check_mounts(config)?;
        check_network(config)?;
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
///
/// With a rootfs, targets are created under it and the child pivots into it.
/// Without one, mounts go straight over the host's own paths, inside the
/// child's private mount namespace, so the host never sees them. Such a
/// target must already exist (an unprivileged child can't create one in a
/// host directory like `/`), which `check_mounts` enforces at build() time.
/// Without a rootfs these used to be silently ignored.
struct MountPlan {
    rootfs: Option<CString>,
    steps: Vec<MountStep>,
    /// Where a fresh procfs goes, so `/proc` shows the sandbox's own pid
    /// namespace instead of every host process. Confirmed for real:
    /// `ps aux` listed host processes before.
    proc_target: CString,
}

impl MountPlan {
    fn new(
        rootfs: Option<&std::path::Path>,
        mounts: &[Mount],
        tmpfs_mounts: &[(std::path::PathBuf, u64)],
    ) -> Result<Self> {
        let mut steps = Vec::new();
        for m in mounts.iter().filter(|m| !Self::is_noop(rootfs, m)) {
            let target = Self::target(&mut steps, rootfs, &m.target)?;
            let source = path_cstring(&m.source)?;
            let readonly = (m.permission == Permission::ReadOnly).then(|| locked_flags(&source));
            steps.push(MountStep::Bind {
                source,
                target,
                readonly,
            });
        }
        for (path, size) in tmpfs_mounts {
            let target = Self::target(&mut steps, rootfs, path)?;
            let options = CString::new(format!("size={size}")).expect("no NUL in a number");
            steps.push(MountStep::Tmpfs { target, options });
        }
        let proc_target = match rootfs {
            Some(rootfs) => path_cstring(&rootfs.join("proc"))?,
            None => c"/proc".to_owned(),
        };
        Ok(Self {
            rootfs: rootfs.map(path_cstring).transpose()?,
            steps,
            proc_target,
        })
    }

    /// Without a rootfs, a read-write mount of a path onto itself changes
    /// nothing, so it isn't worth a mount (or an AppArmor refusal).
    fn is_noop(rootfs: Option<&std::path::Path>, m: &Mount) -> bool {
        rootfs.is_none()
            && m.permission == Permission::ReadWrite
            && std::fs::canonicalize(&m.source).ok() == std::fs::canonicalize(&m.target).ok()
    }

    /// The full path to mount at. Under a rootfs, also queues a mkdir for
    /// each component of it; without one it must already exist.
    fn target(
        steps: &mut Vec<MountStep>,
        rootfs: Option<&std::path::Path>,
        target: &std::path::Path,
    ) -> Result<CString> {
        let Some(rootfs) = rootfs else {
            return path_cstring(target);
        };
        let mut path = rootfs.to_path_buf();
        for component in target.strip_prefix("/").unwrap_or(target).components() {
            path.push(component);
            steps.push(MountStep::Mkdir(path_cstring(&path)?));
        }
        path_cstring(&path)
    }

    /// Whether the caller asked for anything here (a rootfs, a mount, a
    /// tmpfs), as opposed to just the `/proc` this plan always adds.
    fn requested(&self) -> bool {
        self.rootfs.is_some() || !self.steps.is_empty()
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
            if let Some(rootfs) = &self.rootfs {
                let rootfs = rootfs.as_ptr();
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
        }
        Ok(())
    }

    /// Mounts the fresh procfs. Best effort: a failure here is logged by the
    /// child but doesn't stop the run. Must happen before `enter_rootfs`: the
    /// kernel only allows a new proc mount while a fully visible one is still
    /// in the mount namespace, and pivoting drops the host's.
    fn mount_proc(&self) -> bool {
        let target = self.proc_target.as_ptr();
        unsafe {
            if libc::mkdir(target, 0o555) != 0 && *libc::__errno_location() != libc::EEXIST {
                return false;
            }
            let proc = c"proc".as_ptr();
            let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
            libc::mount(proc, target, proc, flags, std::ptr::null()) == 0
        }
    }

    /// Pivots into the rootfs, if there is one.
    fn enter_rootfs(&self) -> std::result::Result<(), &'static str> {
        let Some(rootfs) = &self.rootfs else {
            return Ok(());
        };
        let rootfs = rootfs.as_ptr();
        unsafe {
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

/// Ubuntu 23.10+: a fresh user namespace created by an unprivileged,
/// unconfined process lands in AppArmor's `unprivileged_userns` profile,
/// which denies mounting, sethostname, and bringing up a network namespace's
/// loopback (CAP_NET_ADMIN) inside it, even though the kernel's own
/// capability model allows all three there. Confirmed for real via dmesg
/// (`apparmor="DENIED" ... profile="unprivileged_userns"`, for both
/// `operation="mount"` and `capname="net_admin"`).
/// Root isn't affected, and neither is an executable with its own AppArmor
/// profile that allows `userns`.
fn userns_restricted_by_apparmor() -> bool {
    if unsafe { libc::geteuid() } == 0 {
        return false;
    }
    let restricted =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .is_ok_and(|v| v.trim() == "1");
    restricted
        && std::fs::read_to_string("/proc/self/attr/apparmor/current")
            .or_else(|_| std::fs::read_to_string("/proc/self/attr/current"))
            .map_or(true, |label| label.trim() == "unconfined")
}

/// Refuses, at build() time, mount setups that can only fail or silently do
/// something other than asked once the sandbox runs.
fn check_network(config: &SandboxConfig) -> Result<()> {
    if matches!(config.network_mode, NetworkMode::Proxied { .. }) && userns_restricted_by_apparmor()
    {
        // Falling back to the host network would make the whitelist
        // advisory again: any program ignoring HTTP_PROXY gets straight out.
        return Err(SandboxError::Config(
            "allow_network needs to bring up loopback in the sandbox's own network namespace, \
             which AppArmor denies here (kernel.apparmor_restrict_unprivileged_userns=1 for an \
             unprivileged, unconfined process). Run as root, set that sysctl to 0, or give \
             this executable an AppArmor profile that allows userns"
                .into(),
        ));
    }
    Ok(())
}

fn check_mounts(config: &SandboxConfig) -> Result<()> {
    let plan = MountPlan::new(
        config.rootfs.as_deref(),
        &config.mounts,
        &config.tmpfs_mounts,
    )?;
    if plan.requested() && userns_restricted_by_apparmor() {
        return Err(SandboxError::Config(
            "rootfs/mount/tmpfs need to mount inside the sandbox's user namespace, which \
             AppArmor denies here (kernel.apparmor_restrict_unprivileged_userns=1 for an \
             unprivileged, unconfined process). Run as root, set that sysctl to 0, or give \
             this executable an AppArmor profile that allows userns"
                .into(),
        ));
    }
    let binds = config
        .mounts
        .iter()
        .filter(|m| !MountPlan::is_noop(config.rootfs.as_deref(), m));
    if config.rootfs.is_none() {
        for target in binds
            .clone()
            .map(|m| &m.target)
            .chain(config.tmpfs_mounts.iter().map(|(p, _)| p))
        {
            if !target.exists() {
                return Err(SandboxError::Config(format!(
                    "mount target {} does not exist; without a rootfs, mounts go over the \
                     host's own paths, so the target must already exist",
                    target.display()
                )));
            }
        }
    }
    // A tmpfs mounts after the binds, and starts empty: anything under it
    // would be hidden.
    for (tmpfs, _) in &config.tmpfs_mounts {
        let hidden = |path: &std::path::Path| path != tmpfs && path.starts_with(tmpfs);
        if let Some(m) = binds.clone().find(|m| hidden(&m.target)) {
            return Err(SandboxError::Config(format!(
                "mount target {} is inside tmpfs {}, which would hide it",
                m.target.display(),
                tmpfs.display()
            )));
        }
        if hidden(&config.working_dir) {
            return Err(SandboxError::Config(format!(
                "working_dir {} is inside tmpfs {}, which would hide it",
                config.working_dir.display(),
                tmpfs.display()
            )));
        }
    }
    Ok(())
}

/// Gets the proxy into a Proxied sandbox's own network namespace, where
/// nothing else is reachable. The child binds the listener in there -- the
/// parent can't enter that namespace without CAP_SYS_ADMIN in its own --
/// and hands it back over a socketpair made before clone(). The parent's
/// proxy then accepts on it, while connecting out from its own network.
struct ProxyLink {
    port: u16,
    parent: OwnedFd,
    child: Option<OwnedFd>,
}

/// The child's half of a `ProxyLink`, copied into the clone() closure.
#[derive(Clone, Copy)]
struct ProxyLinkChild {
    port: u16,
    fd: RawFd,
}

/// Fits one cmsghdr carrying a single fd (CMSG_SPACE(sizeof(int)) is 24 on
/// 64-bit Linux), aligned like one. A stack buffer, so building or reading
/// it never allocates.
#[repr(C, align(8))]
struct FdControl([u8; 32]);

impl ProxyLink {
    fn new(port: u16) -> Result<Self> {
        let mut fds = [0; 2];
        let flags = libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC;
        if unsafe { libc::socketpair(libc::AF_UNIX, flags, 0, fds.as_mut_ptr()) } != 0 {
            return Err(SandboxError::Internal(format!(
                "create proxy socketpair: {}",
                std::io::Error::last_os_error()
            )));
        }
        let [parent, child] = fds.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
        Ok(Self {
            port,
            parent,
            child: Some(child),
        })
    }

    fn child_side(&self) -> ProxyLinkChild {
        ProxyLinkChild {
            port: self.port,
            fd: self
                .child
                .as_ref()
                .expect("taken only after clone")
                .as_raw_fd(),
        }
    }

    /// Parent, right after clone(): drop our copy of the child's end, so
    /// `receive` sees EOF if the child exits or execs without sending.
    fn close_child_end(&mut self) {
        self.child = None;
    }

    /// The child's listener, or None if it never sent one -- it failed, and
    /// its stderr says why.
    fn receive(&self) -> Option<std::net::TcpListener> {
        let mut byte = 0u8;
        let mut iov = libc::iovec {
            iov_base: &mut byte as *mut u8 as *mut libc::c_void,
            iov_len: 1,
        };
        let mut control = FdControl([0; 32]);
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control.0.len() as _;
        loop {
            let n =
                unsafe { libc::recvmsg(self.parent.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
            if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if n <= 0 {
                return None;
            }
            break;
        }
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null()
                || (*cmsg).cmsg_level != libc::SOL_SOCKET
                || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            {
                return None;
            }
            let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const libc::c_int);
            Some(std::net::TcpListener::from_raw_fd(fd))
        }
    }
}

impl ProxyLinkChild {
    /// Runs in the child between clone() and exec(): raw syscalls only.
    /// The error names the step that failed, as a static string.
    fn bind_and_send(self) -> std::result::Result<(), &'static str> {
        unsafe {
            // A new network namespace's loopback starts down.
            let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
            if s < 0 {
                return Err("open a socket to configure loopback");
            }
            let mut ifr: libc::ifreq = std::mem::zeroed();
            ifr.ifr_name[0] = b'l' as libc::c_char;
            ifr.ifr_name[1] = b'o' as libc::c_char;
            let up = libc::ioctl(s, libc::SIOCGIFFLAGS as _, &mut ifr) == 0 && {
                ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
                libc::ioctl(s, libc::SIOCSIFFLAGS as _, &ifr) == 0
            };
            libc::close(s);
            if !up {
                return Err("bring up loopback");
            }

            let listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            if listener < 0 {
                return Err("open the proxy listener");
            }
            let addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: self.port.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
                },
                sin_zero: [0; 8],
            };
            let addr_len = std::mem::size_of_val(&addr) as libc::socklen_t;
            if libc::bind(
                listener,
                &addr as *const _ as *const libc::sockaddr,
                addr_len,
            ) != 0
                || libc::listen(listener, 128) != 0
            {
                libc::close(listener);
                return Err("listen for the proxy");
            }

            let mut byte = 0u8;
            let mut iov = libc::iovec {
                iov_base: &mut byte as *mut u8 as *mut libc::c_void,
                iov_len: 1,
            };
            let mut control = FdControl([0; 32]);
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut libc::c_int, listener);
            let sent = libc::sendmsg(self.fd, &msg, 0);
            libc::close(listener);
            if sent != 1 {
                return Err("hand the proxy listener to the parent");
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
) -> Result<(String, String, i32, bool, Option<i32>, libc::rusage)> {
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

        // wait4, not waitpid: its rusage is where cpu_time/peak_memory come
        // from when there's no cgroup to read them from.
        let mut status: libc::c_int = 0;
        let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::wait4(pid.as_raw(), &mut status, libc::WNOHANG, &mut rusage) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SandboxError::Internal(format!(
                "wait4 for child {pid}: {err}"
            )));
        }
        let exited = ret == pid.as_raw() && libc::WIFEXITED(status);
        let signaled = ret == pid.as_raw() && libc::WIFSIGNALED(status);
        if exited || signaled {
            if let Some((fd, _)) = stdin.take() {
                let _ = close_raw(fd);
            }
            drain_fd(stdout_fd, &mut stdout);
            drain_fd(stderr_fd, &mut stderr);
            close_raw(stdout_fd).ok();
            close_raw(stderr_fd).ok();
            let (code, signal) = if exited {
                (libc::WEXITSTATUS(status), None)
            } else {
                let sig = libc::WTERMSIG(status);
                (128 + sig, Some(sig))
            };
            return Ok((
                String::from_utf8_lossy(&stdout).to_string(),
                String::from_utf8_lossy(&stderr).to_string(),
                code,
                killed_by_timeout,
                signal,
                rusage,
            ));
        }
        if ret == 0 && start.elapsed() > timeout && !killed_by_timeout {
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

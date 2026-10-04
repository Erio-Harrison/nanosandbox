//! Linux platform implementation
//!
//! Uses Linux kernel primitives for sandboxing:
//!
//! - **Namespaces**: PID, mount, network, user, UTS, IPC isolation
//! - **Cgroups v2**: Resource limits (memory, CPU, PIDs)
//! - **Seccomp-BPF**: Syscall filtering
//! - **Landlock**: Writes only where allowed, without a rootfs
//! - **HTTP Proxy**: Domain whitelisting for proxied network mode

use crate::builder::{NetworkMode, SandboxConfig};
use crate::error::{Result, SandboxError};
use crate::network::{ProxiedNetwork, SANDBOX_PROXY_PORT};
use crate::platform::private_tmp::PrivateTmp;
use crate::platform::{rlimit_cpu_secs, PlatformExecutor};
use crate::result::ExecutionResult;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::time::{Duration, Instant};

mod cgroup;
mod landlock;
mod mount;
mod namespace;
mod proxy_link;
mod seccomp;
mod wait;

pub use cgroup::CgroupManager;
use mount::{check_mounts, needed_cgroup_controllers, MountPlan};
pub use namespace::UserNamespace;
use proxy_link::{check_network, ProxyLink};
use seccomp::SyscallFilter;
use wait::{wait_with_timeout, Waited};

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

/// The paths to try executing `cmd` at, in order, the way execvp searches
/// $PATH: `cmd` itself if it contains '/', else each directory of
/// `path_value` (":"-separated) joined with it. The child tries them after
/// entering its rootfs, so the search happens in what the program will see.
/// It used to happen here, in the host's file system: with a rootfs, `ls`
/// resolved to the host's /usr/bin/ls, which an Alpine rootfs doesn't have.
fn exec_candidates(cmd: &str, path_value: &str) -> Result<Vec<CString>> {
    if cmd.contains('/') {
        return Ok(vec![CString::new(cmd)?]);
    }
    path_value
        .split(':')
        .filter(|d| !d.is_empty())
        .map(|dir| {
            Ok(CString::new(
                Path::new(dir).join(cmd).as_os_str().as_bytes(),
            )?)
        })
        .collect()
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
        use nix::fcntl::OFlag;
        use nix::sched::{clone, CloneFlags};
        use nix::sys::signal::Signal;
        use nix::unistd::pipe2;

        // Close-on-exec, so no sandboxed program inherits them. Without it,
        // a run on another thread that clone()s while these are open hands
        // them to its own program: it could read this run's stdin, write
        // into its output, and hold its stdin open so it never sees EOF.
        // dup2() onto 0/1/2 in our own child clears the flag on those.
        let pipe = || pipe2(OFlag::O_CLOEXEC);

        const STACK_SIZE: usize = 1024 * 1024;

        let start = Instant::now();

        // Pipes for stdout, stderr, stdin and the ready signal. Owned, so
        // that any early return closes them; they used to be raw fds that
        // every error path leaked. The child gets plain copies of the fd
        // numbers (below): it has its own fd table, and closes its own.
        let pipe = |what: &str| {
            pipe().map_err(|e| SandboxError::Internal(format!("create pipe for child {what}: {e}")))
        };
        let (stdout_read_fd, stdout_write_fd) = pipe("stdout")?;
        let (stderr_read_fd, stderr_write_fd) = pipe("stderr")?;
        let (ready_read_fd, ready_write_fd) = pipe("sync")?;
        let (stdin_read_fd, stdin_write_fd) = match stdin {
            Some(_) => {
                let (r, w) = pipe("stdin")?;
                (Some(r), Some(w))
            }
            None => (None, None),
        };
        let stdout_read = stdout_read_fd.as_raw_fd();
        let stdout_write = stdout_write_fd.as_raw_fd();
        let stderr_read = stderr_read_fd.as_raw_fd();
        let stderr_write = stderr_write_fd.as_raw_fd();
        let ready_read = ready_read_fd.as_raw_fd();
        let ready_write = ready_write_fd.as_raw_fd();
        let stdin_read = stdin_read_fd.as_ref().map(AsRawFd::as_raw_fd);
        let stdin_write = stdin_write_fd.as_ref().map(AsRawFd::as_raw_fd);

        // As root, the sandbox runs as nobody (see namespace::runs_as_root),
        // and a pipe belongs to whoever made it, mode 0600: so it couldn't
        // reopen its own stdout through /dev/stdout. Give them to nobody.
        if namespace::runs_as_root() {
            for fd in [Some(stdout_write), Some(stderr_write), stdin_read]
                .into_iter()
                .flatten()
            {
                unsafe {
                    libc::fchown(fd, namespace::NOBODY, namespace::NOBODY);
                }
            }
        }

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
            (NetworkMode::Proxied { .. }, Some(_)) => Some(ProxyLink::new(SANDBOX_PROXY_PORT)?),
            _ => None,
        };

        // Create and configure the cgroup leaf *before* clone(), so a failure
        // here (rootless with no delegated subtree, a missing controller...)
        // never leaves a half-started child stuck on the ready pipe. Adding
        // the process to it is the only step that needs child_pid, so it's
        // the only cgroup step that still happens after clone() below.
        let cgroup_controllers = needed_cgroup_controllers(config);
        // cpu_time_limit alone doesn't need a controller enabled: cpu.stat's
        // usage_usec, read below, is populated regardless (confirmed for
        // real against a cgroup with none enabled) -- it just needs the
        // cgroup to exist.
        let cgroup = if !cgroup_controllers.is_empty() || config.cpu_time_limit.is_some() {
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

        // Prepare command arguments. A NUL byte in one is an error: it used
        // to panic here.
        let cmd_cstr = CString::new(cmd)?;
        let args_cstr: Vec<CString> = std::iter::once(Ok(cmd_cstr.clone()))
            .chain(args.iter().map(|s| CString::new(*s)))
            .collect::<std::result::Result<_, _>>()?;

        // Allocate stack for child
        let mut stack = vec![0u8; STACK_SIZE];

        // clear_env(false): start from this process's environment. It used
        // to be ignored here, always starting empty.
        let mut env: HashMap<String, String> = if config.clear_env {
            HashMap::new()
        } else {
            std::env::vars().collect()
        };
        env.extend(config.env.clone());

        // private_tmp is a tmpfs at /tmp (see MountPlan), or where AppArmor
        // denies mounting, a directory for this run, removed when this
        // returns (see platform/private_tmp.rs). TMPDIR points to it either
        // way.
        let userns_restricted = userns_restricted_by_apparmor();
        let mut private_tmp = config
            .private_tmp
            .filter(|_| userns_restricted)
            .map(PrivateTmp::create)
            .transpose()
            .map_err(|e| SandboxError::Internal(format!("create private /tmp: {e}")))?;
        if config.private_tmp.is_some() {
            let dir = private_tmp
                .as_ref()
                .map_or(Path::new("/tmp"), PrivateTmp::path);
            env.entry("TMPDIR".to_string())
                .or_insert_with(|| dir.to_string_lossy().into_owned());
        }

        // Add proxy environment variables if using proxied network
        if proxy_link.is_some() {
            env.extend(ProxiedNetwork::env_vars(SANDBOX_PROXY_PORT));
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
        // A NUL byte in a variable is an error too; it used to be dropped.
        let envp_cstr: Vec<CString> = env
            .iter()
            .map(|(k, v)| CString::new(format!("{k}={v}")))
            .collect::<std::result::Result<_, _>>()?;
        let exec_paths = exec_candidates(cmd, env.get("PATH").map(String::as_str).unwrap_or(""))?;

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
        let working_dir_cstr = CString::new(config.working_dir.as_os_str().as_bytes())?;
        let hostname = config.hostname.clone();
        // Where AppArmor denies mounting and sethostname in the sandbox's
        // user namespace, skip both instead of having every run log their
        // failure to the program's stderr. check_mounts already refused any
        // mounts the caller asked for here at build() time.
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
            Some(MountPlan::new(config, false)?)
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
        // As root, the ids the child switches to before exec (mapped to
        // nobody), having dropped root's groups. See namespace::runs_as_root.
        let become_nobody = namespace::runs_as_root().then(|| user_ns.ids());

        let proxy_link_child = proxy_link.as_ref().map(ProxyLink::child_side);

        // Without a rootfs: writes only to ReadWrite mounts, tmpfs and the
        // temp directories. check_support refused a kernel without Landlock.
        let write_rules =
            landlock::WriteRules::new(config, private_tmp.as_ref().map(PrivateTmp::path))?;

        // check_support refused seccomp(true) where there's no filter.
        let syscall_filter = if config.seccomp {
            SyscallFilter::new()
        } else {
            None
        };

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

            // Die with the thread that made us. Without it, the sandbox kept
            // running after the host process died, with nothing left to
            // enforce its time limit. As init of its PID namespace, it takes
            // the rest of the sandbox with it. If the parent is already gone,
            // the ready pipe below reads EOF.
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
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

            // Now that gid_map is written, which setgroups needs.
            // Raw syscalls, not libc's setgroups/setresuid/setresgid: in a
            // multi-threaded process glibc has every thread switch ids
            // together, and waits for threads that clone() didn't copy.
            // Confirmed for real: run as root, children hung in a futex.
            if become_nobody.is_some()
                && unsafe { libc::syscall(libc::SYS_setgroups, 0, std::ptr::null::<libc::gid_t>()) }
                    != 0
            {
                let _ = write_raw(2, b"Failed to drop supplementary groups\n");
                return 1;
            }

            // Setup stdin
            if let Some(stdin_fd) = stdin_read {
                unsafe {
                    libc::dup2(stdin_fd, libc::STDIN_FILENO);
                }
                let _ = close_raw(stdin_fd);
            }
            // clone() inherited our copy of the write end too. It's
            // close-on-exec, but close it now anyway: we never write to it.
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

            // Change working directory, via raw chdir() rather than
            // std::env::set_current_dir() -- see working_dir_cstr. A failure
            // fails the run: it used to be ignored, leaving the program in
            // whatever directory this process happened to be in.
            if unsafe { libc::chdir(working_dir_cstr.as_ptr()) } != 0 {
                let _ = write_raw(2, b"Failed to enter working_dir\n");
                return 1;
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

            // Before the rlimits too: it opens a file descriptor per path.
            if let Some(rules) = &write_rules {
                if let Err(step) = rules.apply() {
                    let _ = write_raw(2, b"File system rules failed: ");
                    let _ = write_raw(2, step.as_bytes());
                    let _ = write_raw(2, b"\n");
                    return 1;
                }
            }

            // After everything that needs root (mounts, the Landlock rules'
            // paths), before anything of the program's. NO_NEW_PRIVS first:
            // root is mapped in this namespace (see write_mappings), and a
            // setuid-root program mustn't make the program root again.
            if let Some((uid, gid)) = become_nobody {
                // Raw syscalls: see setgroups above.
                let switched = unsafe {
                    libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                        && libc::syscall(libc::SYS_setresgid, gid, gid, gid) == 0
                        && libc::syscall(libc::SYS_setresuid, uid, uid, uid) == 0
                };
                if !switched {
                    let _ = write_raw(2, b"Failed to switch to the sandbox's ids\n");
                    return 1;
                }
                // Changing ids clears the parent-death signal: set it again.
                unsafe {
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
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

            // Last, so nothing above is filtered. A sandbox that asked for the
            // filter doesn't run without it.
            if let Some(filter) = &syscall_filter {
                if !filter.install() {
                    let _ = write_raw(2, b"Failed to install the syscall filter\n");
                    return 1;
                }
            }

            // Ignored signals stay ignored across exec, and the signal mask
            // carries over too. This process ignores SIGPIPE (Rust's runtime
            // does), so programs did too: `yes | head -1` had `yes` fail with
            // "Broken pipe" instead of just ending. Give them the defaults.
            unsafe {
                libc::signal(libc::SIGPIPE, libc::SIG_DFL);
                let mut none: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut none);
                libc::sigprocmask(libc::SIG_SETMASK, &none, std::ptr::null_mut());
            }

            // Execute, trying each $PATH candidate in turn as execvp does:
            // on to the next if this one isn't there or isn't executable.
            // Raw libc calls with everything built ahead of clone() above,
            // not nix's execve() wrapper -- see args_ptrs.
            let mut denied = false;
            for path in &exec_paths {
                unsafe {
                    libc::execve(path.as_ptr(), args_ptrs.as_ptr(), envp_ptrs.as_ptr());
                }
                match unsafe { *libc::__errno_location() } {
                    libc::ENOENT | libc::ENOTDIR => {}
                    libc::EACCES => denied = true,
                    _ => {
                        let _ = write_raw(2, b"execve failed\n");
                        return 126;
                    }
                }
            }
            let _ = write_raw(2, b"nanosandbox: ");
            let _ = write_raw(2, cmd_cstr.as_bytes());
            if denied {
                let _ = write_raw(2, b": permission denied\n");
                126
            } else {
                let _ = write_raw(2, b": command not found\n");
                127
            }
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
        // The child's ends are the child's now.
        drop(ready_read_fd);
        drop(stdout_write_fd);
        drop(stderr_write_fd);
        drop(stdin_read_fd);

        let setup: Result<()> = (|| {
            user_ns.write_mappings(child_pid.as_raw())?;
            if let Some(ref cg) = cgroup {
                cg.add_process(child_pid.as_raw() as u32)?;
            }
            // Signal child to continue.
            write_raw(ready_write, &[0u8])
                .map_err(|e| SandboxError::Internal(format!("signal child to continue: {e}")))?;
            Ok(())
        })();
        if let Err(e) = setup {
            let _ = nix::sys::signal::kill(child_pid, Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(child_pid, None);
            return Err(e);
        }
        drop(ready_write_fd);

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
        let stdin_pipe = match (stdin, stdin_write_fd) {
            (Some(data), Some(fd)) => Some((fd, data)),
            _ => None,
        };

        // Wait for child with timeout
        let timeout = config.wall_time_limit.unwrap_or(Duration::from_secs(3600));
        let Waited {
            stdout,
            stderr,
            exit_code,
            killed_by_timeout,
            killed_by_tmp_limit,
            killed_by_cpu_limit,
            signal,
            rusage,
            output_truncated,
        } = wait_with_timeout(
            child_pid,
            [stdout_read_fd, stderr_read_fd],
            stdin_pipe,
            timeout,
            private_tmp.as_mut(),
            config.max_output,
            cgroup
                .as_ref()
                .zip(config.cpu_time_limit)
                .map(|(cg, d)| (cg, d.as_micros() as u64)),
        )?;
        let blocked_hosts = proxy_attachment.map(|a| a.finish()).unwrap_or_default();
        drop(private_tmp);

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

        // The child writes this exact line, and only from this exact exit
        // code, right before giving up on every $PATH candidate -- so it's
        // safe to turn back into an error here, matching Windows (which
        // can tell "not found" from "ran and failed" synchronously, since
        // it execs the command directly instead of through a child that
        // searches $PATH itself). This used to stay an `Ok` with exit 127
        // on every Unix platform, so a caller matching on
        // `SandboxError::CommandNotFound` never saw it there.
        if exit_code == 127
            && signal.is_none()
            && !killed_by_timeout
            && !killed_by_tmp_limit
            && stderr.starts_with("nanosandbox: ")
            && stderr.ends_with(": command not found\n")
        {
            return Err(SandboxError::CommandNotFound(cmd.to_string()));
        }

        Ok(ExecutionResult {
            stdout,
            stderr,
            exit_code,
            duration: start.elapsed(),
            killed_by_timeout,
            killed_by_oom,
            killed_by_tmp_limit,
            killed_by_cpu_limit,
            signal,
            peak_memory,
            cpu_time,
            blocked_hosts,
            output_truncated,
        })
    }

    fn check_support(&self, config: &SandboxConfig) -> Result<()> {
        if !check_user_namespace_support() {
            return Err(SandboxError::UserNamespaceDisabled);
        }
        if !check_cgroup_v2_support() {
            return Err(SandboxError::CgroupV2Unavailable);
        }
        if namespace::runs_as_root() && (config.uid == Some(0) || config.gid == Some(0)) {
            return Err(SandboxError::Unsupported {
                setting: "uid(0)/gid(0) when running as root".into(),
                reason: "a root caller's sandbox runs as nobody, under its uid/gid; 0 is \
                         reserved for setting it up"
                    .into(),
            });
        }
        // Without a rootfs, working_dir is a host path: check it now rather
        // than fail every run. (With one, it's a path in the rootfs.)
        if config.rootfs.is_none() && !config.working_dir.is_dir() {
            return Err(SandboxError::PathNotFound(config.working_dir.clone()));
        }
        check_mounts(config)?;
        landlock::check(config)?;
        check_network(config)?;
        if config.seccomp && !SyscallFilter::supported() {
            return Err(SandboxError::Unsupported {
                setting: "seccomp(true)".into(),
                reason: "the syscall filter is for x86_64 and aarch64 only; use seccomp(false) \
                         to run without it"
                    .into(),
            });
        }
        let needed = needed_cgroup_controllers(config);
        if !needed.is_empty() {
            CgroupManager::ensure_support(&needed)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_executor_creation() {
        let executor = LinuxExecutor::new();
        let _ = executor;
    }
}

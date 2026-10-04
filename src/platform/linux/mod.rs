//! Linux platform implementation
//!
//! Uses Linux kernel primitives for sandboxing:
//!
//! - **Namespaces**: PID, mount, network, user, UTS, IPC isolation
//! - **Cgroups v2**: Resource limits (memory, CPU, PIDs)
//! - **Seccomp-BPF**: Syscall filtering
//! - **Landlock**: Writes only where allowed, without a rootfs
//! - **HTTP Proxy**: Domain whitelisting for proxied network mode

use crate::builder::{Mount, NetworkMode, Permission, SandboxConfig};
use crate::error::{Result, SandboxError};
use crate::network::{ProxiedNetwork, SANDBOX_PROXY_PORT};
use crate::platform::output::Captured;
use crate::platform::private_tmp::PrivateTmp;
use crate::platform::{rlimit_cpu_secs, PlatformExecutor};
use crate::result::ExecutionResult;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

mod cgroup;
mod landlock;
mod namespace;
mod seccomp;

pub use cgroup::CgroupManager;
pub use namespace::UserNamespace;
use seccomp::SyscallFilter;

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
    /// Create an empty file to bind a file onto, if there's nothing there.
    Touch(CString),
    /// `readonly` holds the source's locked flags (nosuid/nodev/noexec) to
    /// repeat on the read-only remount: in a user namespace, a remount that
    /// drops a locked flag fails with EPERM.
    /// `tree` is the detached copy of `source` that `apply` takes before
    /// mounting anything, so a source inside a path a tmpfs then covers
    /// (anything under /tmp, with private_tmp) is still there to bind.
    Bind {
        source: CString,
        target: CString,
        readonly: Option<libc::c_ulong>,
        tree: std::cell::Cell<RawFd>,
    },
    Tmpfs {
        target: CString,
        options: CString,
    },
}

/// open_tree(2): a detached copy of the mount at a path (non-recursive, like
/// MS_BIND without MS_REC).
const OPEN_TREE_CLONE: libc::c_uint = 1;
/// move_mount(2): the source is the fd itself.
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;

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
    /// `restricted`: AppArmor denies mounting (see
    /// `userns_restricted_by_apparmor`), so private_tmp isn't a tmpfs.
    fn new(config: &SandboxConfig, restricted: bool) -> Result<Self> {
        let rootfs = config.rootfs.as_deref();
        let tmpfs = Self::tmpfs_mounts(config, restricted);
        let binds: Vec<&Mount> = config
            .mounts
            .iter()
            .filter(|m| Self::needs_bind(config, &tmpfs, m))
            .collect();

        // One combined order, shallowest target first: a mount has to be in
        // place before anything mounts under it, whichever kind either one
        // is. Grouping "all tmpfs, then all binds" instead used to shadow a
        // tmpfs nested inside a bind's target, while fixing the opposite,
        // bind-inside-a-tmpfs case -- confirmed for real.
        enum Item<'a> {
            Tmpfs(&'a Path, u64),
            Bind(&'a Mount),
        }
        let mut items: Vec<Item> = tmpfs
            .iter()
            .map(|(p, s)| Item::Tmpfs(p, *s))
            .chain(binds.iter().map(|&m| Item::Bind(m)))
            .collect();
        items.sort_by_key(|item| {
            match item {
                Item::Tmpfs(p, _) => *p,
                Item::Bind(m) => m.target.as_path(),
            }
            .components()
            .count()
        });

        let mut steps = Vec::new();
        for item in items {
            match item {
                Item::Tmpfs(path, size) => {
                    let target = Self::target(&mut steps, rootfs, path, &tmpfs, true)?;
                    let options = CString::new(format!("size={size}")).expect("no NUL in a number");
                    steps.push(MountStep::Tmpfs { target, options });
                }
                Item::Bind(m) => {
                    let is_dir = m.source.is_dir();
                    let target = Self::target(&mut steps, rootfs, &m.target, &tmpfs, is_dir)?;
                    let source = path_cstring(&m.source)?;
                    let readonly =
                        (m.permission == Permission::ReadOnly).then(|| locked_flags(&source));
                    steps.push(MountStep::Bind {
                        source,
                        target,
                        readonly,
                        tree: std::cell::Cell::new(-1),
                    });
                }
            }
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

    /// The caller's tmpfs mounts, plus private_tmp's at /tmp where it can be
    /// mounted.
    fn tmpfs_mounts(config: &SandboxConfig, restricted: bool) -> Vec<(PathBuf, u64)> {
        let mut tmpfs = config.tmpfs_mounts.clone();
        if let Some(size) = config.private_tmp.filter(|_| !restricted) {
            tmpfs.insert(0, (PathBuf::from("/tmp"), size));
        }
        tmpfs
    }

    /// Whether a read_only/writable/bind path needs an actual bind mount.
    /// Without a rootfs, a host path at its own path is already there, and
    /// Landlock decides whether it's writable (see landlock.rs), with no
    /// mount at all. It still needs one if it's elsewhere (bind()), under a
    /// tmpfs that would hide it, or read-only inside a writable area, where
    /// Landlock can't take writing away again.
    fn needs_bind(config: &SandboxConfig, tmpfs: &[(PathBuf, u64)], m: &Mount) -> bool {
        if config.rootfs.is_some() {
            return true;
        }
        let canonical = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        if canonical(&m.source) != canonical(&m.target) {
            return true;
        }
        if tmpfs.iter().any(|(t, _)| m.target.starts_with(t)) {
            return true;
        }
        m.permission == Permission::ReadOnly
            && landlock::writable_areas(config)
                .any(|area| area != m.target.as_path() && m.target.starts_with(area))
    }

    /// The full path to mount at. Under a rootfs, also queues a mkdir for
    /// each component of it. Without one, the target must already exist,
    /// unless it's inside one of `tmpfs`: those start empty, so the part
    /// below the tmpfs is created in it. `is_dir`: whether the last
    /// component is a directory, or a file to bind a file onto.
    fn target(
        steps: &mut Vec<MountStep>,
        rootfs: Option<&Path>,
        target: &Path,
        tmpfs: &[(PathBuf, u64)],
        is_dir: bool,
    ) -> Result<CString> {
        let (mut path, below) = match rootfs {
            Some(rootfs) => (
                rootfs.to_path_buf(),
                target.strip_prefix("/").unwrap_or(target),
            ),
            None => match tmpfs
                .iter()
                .filter(|(t, _)| t != target && target.starts_with(t))
                .max_by_key(|(t, _)| t.components().count())
            {
                Some((t, _)) => (t.clone(), target.strip_prefix(t).expect("checked above")),
                None => return path_cstring(target),
            },
        };
        let components: Vec<_> = below.components().collect();
        for (i, component) in components.iter().enumerate() {
            path.push(component);
            let last = i + 1 == components.len();
            steps.push(if last && !is_dir {
                MountStep::Touch(path_cstring(&path)?)
            } else {
                MountStep::Mkdir(path_cstring(&path)?)
            });
        }
        path_cstring(&path)
    }

    /// Whether there's anything to mount here (a rootfs, a bind, a tmpfs),
    /// as opposed to just the `/proc` this plan always adds.
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
            // Take every bind's source now, before any tmpfs can cover it.
            for step in &self.steps {
                if let MountStep::Bind { source, tree, .. } = step {
                    let fd = libc::syscall(
                        libc::SYS_open_tree,
                        libc::AT_FDCWD,
                        source.as_ptr(),
                        OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint,
                    );
                    if fd < 0 {
                        return Err("open bind source");
                    }
                    tree.set(fd as RawFd);
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
                    MountStep::Touch(path) => {
                        let fd = libc::open(
                            path.as_ptr(),
                            libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC,
                            0o644,
                        );
                        if fd < 0 {
                            return Err("create mount target");
                        }
                        libc::close(fd);
                    }
                    MountStep::Bind {
                        target,
                        readonly,
                        tree,
                        ..
                    } => {
                        let moved = libc::syscall(
                            libc::SYS_move_mount,
                            tree.get(),
                            c"".as_ptr(),
                            libc::AT_FDCWD,
                            target.as_ptr(),
                            MOVE_MOUNT_F_EMPTY_PATH,
                        );
                        libc::close(tree.get());
                        if moved != 0 {
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
        return Err(SandboxError::Unsupported {
            setting: "allow_network()".into(),
            reason: "it needs to bring up loopback in the sandbox's own network namespace, \
                     which AppArmor denies here (kernel.apparmor_restrict_unprivileged_userns=1 \
                     for an unprivileged, unconfined process). Run as root, set that sysctl to \
                     0, or give this executable an AppArmor profile that allows userns"
                .into(),
        });
    }
    Ok(())
}

fn check_mounts(config: &SandboxConfig) -> Result<()> {
    let restricted = userns_restricted_by_apparmor();
    let plan = MountPlan::new(config, restricted)?;
    if plan.requested() && restricted {
        return Err(SandboxError::Unsupported {
            setting: "rootfs, tmpfs, bind, or read_only inside a writable directory".into(),
            reason: "these need to mount inside the sandbox's user namespace, which AppArmor \
                     denies here (kernel.apparmor_restrict_unprivileged_userns=1 for an \
                     unprivileged, unconfined process). Run as root, set that sysctl to 0, or \
                     give this executable an AppArmor profile that allows userns"
                .into(),
        });
    }
    if config.rootfs.is_some() {
        return Ok(());
    }
    let tmpfs = MountPlan::tmpfs_mounts(config, restricted);
    let in_tmpfs = |path: &Path| tmpfs.iter().any(|(t, _)| t != path && path.starts_with(t));
    for (path, _) in &config.tmpfs_mounts {
        if !path.exists() {
            return Err(SandboxError::Config(format!(
                "tmpfs path {} does not exist; without a rootfs, it's mounted over the \
                 host's own path, which must already exist",
                path.display()
            )));
        }
    }
    for m in &config.mounts {
        if !in_tmpfs(&m.target) && !m.target.exists() {
            return Err(SandboxError::Config(format!(
                "bind target {} does not exist; without a rootfs, binds go over the host's \
                 own paths, so it must already exist",
                m.target.display()
            )));
        }
    }
    // A tmpfs starts empty: only what's bound into it is there.
    let wd = &config.working_dir;
    if in_tmpfs(wd) && !config.mounts.iter().any(|m| wd.starts_with(&m.target)) {
        return Err(SandboxError::Config(format!(
            "working_dir {} is inside a tmpfs, which starts empty; make it readable or \
             writable to have it there",
            wd.display()
        )));
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

/// How the sandboxed process ended, from `wait_with_timeout`.
struct Waited {
    stdout: String,
    stderr: String,
    exit_code: i32,
    killed_by_timeout: bool,
    killed_by_tmp_limit: bool,
    killed_by_cpu_limit: bool,
    signal: Option<i32>,
    rusage: libc::rusage,
    output_truncated: bool,
}

/// Reads what's available on `fd` into `out`, until it would block. False
/// once the writers are all gone (EOF) or it fails.
fn drain(fd: RawFd, out: &mut Captured) -> bool {
    let mut buf = [0u8; 64 * 1024];
    loop {
        match read_raw(fd, &mut buf) {
            Ok(0) => return false,
            Ok(n) => out.push(&buf[..n]),
            Err(nix::errno::Errno::EAGAIN) => return true,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => return false,
        }
    }
}

/// Feeds stdin, collects stdout/stderr and waits for the process, killing
/// it on `timeout`, when `private_tmp` goes over its size, or (`cpu_limit`)
/// when the whole cgroup goes over `cpu_time_limit` in total CPU time --
/// `RLIMIT_CPU` alone only catches one process over it, not the group.
///
/// Waits in poll() on the pipes, and reads each one until it's empty when
/// it has data. It used to read 4 KB per stream every 10 ms, about 400 KB/s:
/// a program printing 10 MB took 25 s, and ran out a 10 s time limit.
fn wait_with_timeout(
    pid: nix::unistd::Pid,
    outputs: [OwnedFd; 2],
    mut stdin: Option<(OwnedFd, &[u8])>,
    timeout: Duration,
    mut private_tmp: Option<&mut PrivateTmp>,
    max_output: u64,
    cpu_limit: Option<(&CgroupManager, u64)>,
) -> Result<Waited> {
    let start = Instant::now();
    let mut captured = [Captured::new(max_output), Captured::new(max_output)];
    let mut open = [true, true];
    let mut killed_by_timeout = false;
    let mut killed_by_tmp_limit = false;
    // Total across the whole cgroup, not just `pid` itself: RLIMIT_CPU
    // (set in the child) is per process, so a program that forks could use
    // close to N times cpu_time_limit before any one of them individually
    // hit it. cpu.stat's usage_usec works without the "cpu" controller
    // enabled (confirmed for real), so this needs only a cgroup to exist.
    let mut killed_by_cpu_limit = false;
    let kill = || {
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
        unsafe {
            libc::kill(-(pid.as_raw()), libc::SIGKILL);
        }
    };

    let set_nonblocking = |fd: RawFd| unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    };
    let fds = [outputs[0].as_raw_fd(), outputs[1].as_raw_fd()];
    fds.iter().for_each(|&fd| set_nonblocking(fd));
    if let Some((fd, _)) = &stdin {
        set_nonblocking(fd.as_raw_fd());
    }

    loop {
        // Wait up to 10 ms for output, or for room to write stdin; the
        // wait4/timeout checks below run at least that often.
        let mut polled: Vec<libc::pollfd> = fds
            .iter()
            .zip(open)
            .filter(|(_, open)| *open)
            .map(|(&fd, _)| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        if let Some((fd, _)) = &stdin {
            polled.push(libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            });
        }
        unsafe {
            libc::poll(polled.as_mut_ptr(), polled.len() as libc::nfds_t, 10);
        }

        // Write more stdin, non-blocking, interleaved with draining
        // stdout/stderr below — not all upfront. A program that echoes
        // input to output as it goes (e.g. `cat`) can block on writing its
        // own output once enough of it is buffered and unread, which stops
        // it reading more stdin in turn; writing stdin to completion
        // before anything reads stdout/stderr deadlocks against exactly
        // that, confirmed for real with input over the output pipe's size.
        if let Some((fd, data)) = &mut stdin {
            if !data.is_empty() {
                match write_raw(fd.as_raw_fd(), data) {
                    Ok(n) if n > 0 => *data = &data[n..],
                    Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EINTR) => {}
                    // Either wrote 0 (shouldn't happen for non-empty data)
                    // or the reader's gone (e.g. EPIPE) — nothing more to
                    // usefully write either way.
                    _ => *data = &[],
                }
            }
            if data.is_empty() {
                stdin = None; // dropping it closes the pipe: EOF for the program
            }
        }

        for i in 0..2 {
            if open[i] {
                open[i] = drain(fds[i], &mut captured[i]);
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
            // What's left in the pipes. A descendant that inherited them can
            // keep them open, so not to EOF: only what's there now.
            for i in 0..2 {
                if open[i] {
                    drain(fds[i], &mut captured[i]);
                }
            }
            let (code, signal) = if exited {
                (libc::WEXITSTATUS(status), None)
            } else {
                let sig = libc::WTERMSIG(status);
                (128 + sig, Some(sig))
            };
            let output_truncated = captured.iter().any(Captured::truncated);
            let [stdout, stderr] = captured.map(Captured::into_string);
            return Ok(Waited {
                stdout,
                stderr,
                exit_code: code,
                killed_by_timeout,
                killed_by_tmp_limit,
                killed_by_cpu_limit,
                signal,
                rusage,
                output_truncated,
            });
        }
        if let Some(tmp) = private_tmp.as_deref_mut() {
            if ret == 0 && !killed_by_tmp_limit && tmp.over_limit() {
                kill();
                killed_by_tmp_limit = true;
            }
        }
        if let Some((cg, limit_usec)) = cpu_limit {
            if ret == 0 && !killed_by_cpu_limit {
                let used = cg.get_cpu_stats().map(|s| s.total_usec).unwrap_or(0);
                if used > limit_usec {
                    kill();
                    killed_by_cpu_limit = true;
                }
            }
        }
        if ret == 0 && start.elapsed() > timeout && !killed_by_timeout {
            // The child is init of its PID namespace: when it dies, the
            // kernel kills everything else in there. The process group is
            // killed too, just in case.
            kill();
            killed_by_timeout = true;
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

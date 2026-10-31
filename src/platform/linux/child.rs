//! What runs in the child between clone() and exec(): raw syscalls only, no allocation.
//! clone() is raw, not libc's fork(), so there's no pthread_atfork() malloc-lock protection:
//! an allocation here can hang on a frozen malloc lock (see `ExecBuffers` in prepare.rs).

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

use super::landlock::WriteRules;
use super::mount::MountPlan;
use super::proxy_link::ProxyLinkChild;
use super::seccomp::SyscallFilter;
use super::{close_raw, read_raw, write_raw};

/// The sandboxed command's pid for [`forward_to_child`]; atomic since the signal handler reads it.
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

/// The init shim's signal handler: relays signals to the command. `kill` is async-signal-safe.
extern "C" fn forward_to_child(sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

/// Everything the child needs, built in the parent before clone(). Run with `&self` so the
/// whole struct, including the buffers `args_ptrs`/`envp_ptrs` point into, lives for the call.
pub(super) struct ChildSetup {
    pub(super) cmd_cstr: CString,
    // Never read directly; only the pointer vectors into them are.
    #[allow(dead_code)]
    pub(super) args_cstr: Vec<CString>,
    #[allow(dead_code)]
    pub(super) envp_cstr: Vec<CString>,
    pub(super) args_ptrs: Vec<*const libc::c_char>,
    pub(super) envp_ptrs: Vec<*const libc::c_char>,
    pub(super) exec_paths: Vec<CString>,

    pub(super) ready_write: RawFd,
    pub(super) ready_read: RawFd,
    pub(super) signal_read: RawFd,
    pub(super) signal_write: RawFd,
    pub(super) become_nobody: Option<(u32, u32)>,
    pub(super) stdin_read: Option<RawFd>,
    pub(super) stdin_write: Option<RawFd>,
    pub(super) stdout_write: RawFd,
    pub(super) stderr_write: RawFd,
    pub(super) stdout_read: RawFd,
    pub(super) stderr_read: RawFd,
    pub(super) userns_restricted: bool,
    pub(super) hostname: String,
    pub(super) mount_plan: Option<MountPlan>,
    pub(super) working_dir_cstr: CString,
    pub(super) proxy_link_child: Option<ProxyLinkChild>,
    pub(super) write_rules: Option<WriteRules>,
    pub(super) rlimits: Vec<(u32, u64, &'static [u8])>,
    pub(super) syscall_filter: Option<SyscallFilter>,
    /// A pseudo-terminal's slave device, opened here (see `pty::Pty::slave_path`): the
    /// command's controlling terminal and stdio.
    pub(super) pty_slave: Option<CString>,
}

impl ChildSetup {
    /// The command will see the host's `/proc`: say so on stderr and to the host, which then
    /// reports `proc_isolated: false` (see wait::read_reports).
    fn report_no_private_proc(&self) {
        let _ = write_raw(2, b"Failed to mount /proc\n");
        let _ = write_raw(self.signal_write, &[0]);
    }

    /// Runs in the child between clone() and exec(): see the module doc.
    pub(super) fn run(&self) -> isize {
        // New session (and so process group, for killpg): no controlling terminal, so the command
        // can't open /dev/tty to read the caller's terminal or inject input with TIOCSTI.
        if unsafe { libc::setsid() } < 0 {
            let _ = write_raw(2, b"Failed to create a session\n");
            return 1;
        }

        // Die with the thread that made us, else the sandbox outlives the host with nothing
        // enforcing its time limit. As PID-ns init it takes the sandbox with it; if the parent
        // is already gone, the ready pipe reads EOF.
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        }

        // Close our copy of the write end before reading: otherwise a parent dying before
        // signaling leaves the pipe never at EOF and the read blocks forever.
        let _ = close_raw(self.ready_write);

        // Wait for the parent's UID/GID mapping and cgroup join. EOF means the parent died.
        let mut buf = [0u8; 1];
        match read_raw(self.ready_read, &mut buf) {
            Ok(1) => {}
            _ => return 1,
        }
        let _ = close_raw(self.ready_read);

        // gid_map is written now, which setgroups needs. Raw syscalls: in a multi-threaded process
        // glibc's setresuid/setresgid wait for threads clone() didn't copy (hung in a futex as root).
        if self.become_nobody.is_some()
            && unsafe { libc::syscall(libc::SYS_setgroups, 0, std::ptr::null::<libc::gid_t>()) }
                != 0
        {
            let _ = write_raw(2, b"Failed to drop supplementary groups\n");
            return 1;
        }

        // Stdin: /dev/null if none given, not our inherited stdin (e.g. an MCP client's stream),
        // whose shared file description let an O_NONBLOCK set by the command break the host's reads.
        if let Some(path) = &self.pty_slave {
            // The terminal is the session's (setsid above) and all three streams. Opened now,
            // while the host's /dev/pts is still what /dev/pts is.
            let slave = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
                )
            };
            if slave < 0
                || unsafe { libc::ioctl(slave, libc::TIOCSCTTY as _, 0) } != 0
                || unsafe { libc::dup2(slave, libc::STDIN_FILENO) } < 0
                || unsafe { libc::dup2(slave, libc::STDOUT_FILENO) } < 0
                || unsafe { libc::dup2(slave, libc::STDERR_FILENO) } < 0
            {
                let _ = write_raw(2, b"Failed to take the terminal\n");
                return 1;
            }
            let _ = close_raw(slave);
        } else if let Some(stdin_fd) = self.stdin_read {
            if unsafe { libc::dup2(stdin_fd, libc::STDIN_FILENO) } < 0 {
                let _ = write_raw(2, b"Failed to redirect stdin\n");
                return 1;
            }
            let _ = close_raw(stdin_fd);
        } else {
            let null =
                unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if null < 0 || unsafe { libc::dup2(null, libc::STDIN_FILENO) } < 0 {
                let _ = write_raw(2, b"Failed to redirect stdin\n");
                return 1;
            }
            let _ = close_raw(null);
        }
        // Inherited copy of the write end; close-on-exec, but we never write to it.
        if let Some(fd) = self.stdin_write {
            let _ = close_raw(fd);
        }

        // A failed redirect would leave output uncaptured: fail instead.
        if self.pty_slave.is_none()
            && (unsafe { libc::dup2(self.stdout_write, libc::STDOUT_FILENO) } < 0
                || unsafe { libc::dup2(self.stderr_write, libc::STDERR_FILENO) } < 0)
        {
            let _ = write_raw(2, b"Failed to redirect output\n");
            return 1;
        }
        let _ = close_raw(self.stdout_write);
        let _ = close_raw(self.stderr_write);
        let _ = close_raw(self.stdout_read);
        let _ = close_raw(self.stderr_read);
        let _ = close_raw(self.signal_read);

        // Hostname (UTS ns). Errors are fixed strings via raw write(), not eprintln!/format! (module
        // doc); nix's sethostname doesn't allocate.
        if !self.userns_restricted && nix::unistd::sethostname(&self.hostname).is_err() {
            let _ = write_raw(2, b"Failed to set hostname\n");
        }

        // Mount ns: caller's rootfs/mounts/tmpfs, then private /proc, then pivot into the rootfs.
        // Caller-requested failures fail the run; /proc is best effort.
        if let Some(plan) = &self.mount_plan {
            let fatal = |step: &str| {
                let _ = write_raw(2, b"Mount setup failed: ");
                let _ = write_raw(2, step.as_bytes());
                let _ = write_raw(2, b"\n");
                1
            };
            match plan.apply() {
                Err(step) if plan.requested() => return fatal(step),
                Err(_) => self.report_no_private_proc(),
                Ok(()) => {
                    if !plan.mount_proc() {
                        self.report_no_private_proc();
                    }
                    if let Err(step) = plan.enter_rootfs() {
                        return fatal(step);
                    }
                }
            }
        }

        // Env goes to execve explicitly, not via std::env (see ExecBuffers in prepare.rs).

        // Raw chdir() rather than std::env::set_current_dir() (see working_dir_cstr in execute()).
        // A failure fails the run.
        if unsafe { libc::chdir(self.working_dir_cstr.as_ptr()) } != 0 {
            let _ = write_raw(2, b"Failed to enter working_dir\n");
            return 1;
        }

        // Before the rlimits: a small max_open_files could stop these sockets opening.
        if let Some(link) = self.proxy_link_child
            && let Err(step) = link.bind_and_send()
        {
            let _ = write_raw(2, b"Network setup failed: ");
            let _ = write_raw(2, step.as_bytes());
            let _ = write_raw(2, b"\n");
            return 1;
        }

        // Before the rlimits too: opens an fd per path.
        if let Some(rules) = &self.write_rules
            && let Err(step) = rules.apply()
        {
            let _ = write_raw(2, b"File system rules failed: ");
            let _ = write_raw(2, step.as_bytes());
            let _ = write_raw(2, b"\n");
            return 1;
        }

        // After everything needing root, before anything of the program's. NO_NEW_PRIVS first: root
        // is mapped here (see write_mappings), and setuid-root mustn't regain it.
        if let Some((uid, gid)) = self.become_nobody {
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

        for (resource, value, failure) in &self.rlimits {
            let limit = libc::rlimit {
                rlim_cur: *value as libc::rlim_t,
                rlim_max: *value as libc::rlim_t,
            };
            if unsafe { libc::setrlimit(*resource, &limit) } != 0 {
                let _ = write_raw(2, failure);
                return 1;
            }
        }

        // Last, so nothing above is filtered.
        if let Some(filter) = &self.syscall_filter
            && !filter.install()
        {
            let _ = write_raw(2, b"Failed to install the syscall filter\n");
            return 1;
        }

        // We become init of a fresh PID ns, where pid_namespaces(7) drops default-disposition
        // signals from other members (even self-SIGKILL) unless caught. So fork: this process stays
        // init and relays signals to the command (PID 2), as `tini`/`docker run --init` do.
        for sig in (1..=31).chain(libc::SIGRTMIN()..=libc::SIGRTMAX()) {
            if sig == libc::SIGKILL || sig == libc::SIGSTOP || sig == libc::SIGCHLD {
                continue;
            }
            let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
            sa.sa_sigaction = forward_to_child as *const () as libc::sighandler_t;
            unsafe {
                libc::sigaction(sig, &sa, std::ptr::null_mut());
            }
        }

        // Raw clone(), not fork(): same no-allocation reasoning as above.
        let forked = unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD as libc::c_long, 0i64) };
        if forked < 0 {
            let _ = write_raw(2, b"Failed to fork the sandboxed command\n");
            return 1;
        }

        if forked != 0 {
            // Still PID 1: init, not the command. Needs no fds, so close everything: clone() snapshots
            // the fd table, and a stray not-yet-CLOEXEC pipe end from a concurrent run would stay open for
            // this never-exec'ing process, so readers never see EOF. Keep only the signal-report pipe.
            let keep = self.signal_write as u32;
            unsafe {
                if keep > 0 {
                    libc::syscall(libc::SYS_close_range, 0u32, keep - 1, 0i32);
                }
                libc::syscall(libc::SYS_close_range, keep + 1, u32::MAX, 0i32);
            }
            CHILD_PID.store(forked as i32, Ordering::Relaxed);
            loop {
                let mut status: libc::c_int = 0;
                let r = unsafe { libc::waitpid(-1, &mut status, 0) };
                if r < 0 {
                    if unsafe { *libc::__errno_location() } == libc::EINTR {
                        continue;
                    }
                    return 1; // ECHILD or similar: nothing left to reap
                }
                if r == forked as libc::pid_t {
                    return if libc::WIFEXITED(status) {
                        libc::WEXITSTATUS(status) as isize
                    } else if libc::WIFSIGNALED(status) {
                        // Can't die by the signal ourselves (the kernel would drop it): exit 128+signal like `tini`,
                        // and also send the signal over the pipe, since `exit(143)` looks the same.
                        let sig = libc::WTERMSIG(status);
                        let byte = sig as u8;
                        unsafe {
                            libc::write(self.signal_write, &byte as *const u8 as *const _, 1);
                        }
                        (128 + sig) as isize
                    } else {
                        1
                    };
                }
                // Orphan reparented here: reaped, keep going.
            }
        }

        // PID 2 from here: the sandboxed command.

        // Ignored signals and the mask survive exec. We ignore SIGPIPE (Rust runtime), which made
        // `yes | head -1` fail with "Broken pipe"; restore defaults.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            let mut none: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut none);
            libc::sigprocmask(libc::SIG_SETMASK, &none, std::ptr::null_mut());
        }

        // Only stdio crosses exec. A host fd without CLOEXEC (a C library's, one inherited from
        // the host's parent) would otherwise reach the command: Landlock doesn't judge open
        // descriptors, so `echo x >&3` writes wherever it points.
        unsafe {
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0i32) != 0 {
                // Pre-5.9 kernel: close one by one up to the table size.
                let max = libc::sysconf(libc::_SC_OPEN_MAX).clamp(3, 1 << 20) as libc::c_int;
                for fd in 3..max {
                    libc::close(fd);
                }
            }
        }

        // Try each $PATH candidate as execvp does, with raw libc calls on buffers built before clone().
        let mut denied = false;
        for path in &self.exec_paths {
            unsafe {
                libc::execve(
                    path.as_ptr(),
                    self.args_ptrs.as_ptr(),
                    self.envp_ptrs.as_ptr(),
                );
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
        let _ = write_raw(2, self.cmd_cstr.as_bytes());
        if denied {
            let _ = write_raw(2, b": permission denied\n");
            126
        } else {
            let _ = write_raw(2, b": command not found\n");
            127
        }
    }
}

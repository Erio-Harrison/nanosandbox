//! What runs in the child between clone() and exec(): raw syscalls only,
//! no allocation. clone() is a raw syscall here, not libc's fork(), so the
//! child doesn't get glibc's pthread_atfork() malloc-lock protection --
//! any allocation here risks the same frozen-malloc-lock hang std::env's
//! own lock would (see `ExecBuffers` in prepare.rs). Confirmed for real
//! via gdb: a child stuck in malloc, called from eprintln!, itself called
//! from this code after clone().

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

use super::landlock::WriteRules;
use super::mount::MountPlan;
use super::proxy_link::ProxyLinkChild;
use super::seccomp::SyscallFilter;
use super::{close_raw, read_raw, write_raw};

/// The sandboxed command's pid, for [`forward_to_child`] to relay into.
/// Set once, right after the fork in [`ChildSetup::run`]; read only from a
/// signal handler from then on, hence the atomic rather than a plain field.
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

/// The init shim's signal handler (see [`ChildSetup::run`]): relays
/// whatever it's given to the real command. `kill` is async-signal-safe
/// per signal-safety(7); nothing else runs here.
extern "C" fn forward_to_child(sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

/// Everything the child needs, built in the parent before clone() so the
/// child itself never has to. Moved into the clone() closure as one
/// value, then run with `&self`: a method call needing the whole struct
/// to exist for its duration, not just the fields it happens to read.
/// That's what keeps `args_cstr`/`envp_cstr` alive for as long as
/// `args_ptrs`/`envp_ptrs` (which point into their buffers) are in use
/// below -- the original flat-variable version of this closure needed an
/// explicit `let _args_cstr = &args_cstr;` pin instead, to stop Rust's
/// closure capture analysis from dropping an "unused-looking" local
/// before clone(); that failure mode doesn't exist once this is a `&self`
/// method on one struct moved in whole.
pub(super) struct ChildSetup {
    pub(super) cmd_cstr: CString,
    // Never read directly (only args_ptrs/envp_ptrs, which point into
    // these, are) -- see the struct doc for why they're still here.
    #[allow(dead_code)]
    pub(super) args_cstr: Vec<CString>,
    #[allow(dead_code)]
    pub(super) envp_cstr: Vec<CString>,
    pub(super) args_ptrs: Vec<*const libc::c_char>,
    pub(super) envp_ptrs: Vec<*const libc::c_char>,
    pub(super) exec_paths: Vec<CString>,

    pub(super) ready_write: RawFd,
    pub(super) ready_read: RawFd,
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
}

impl ChildSetup {
    /// Runs in the child between clone() and exec(): see the module doc.
    pub(super) fn run(&self) -> isize {
        // Create a new process group with this process as leader
        // This allows us to kill all children with killpg
        if unsafe { libc::setpgid(0, 0) } != 0 {
            let _ = write_raw(2, b"Failed to create process group\n");
            return 1;
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
        let _ = close_raw(self.ready_write);

        // Wait for parent to setup UID/GID mappings and place us in our
        // cgroup. 0 bytes read means EOF — the parent died before
        // signaling — nothing valid to continue with either way.
        let mut buf = [0u8; 1];
        match read_raw(self.ready_read, &mut buf) {
            Ok(1) => {}
            _ => return 1,
        }
        let _ = close_raw(self.ready_read);

        // Now that gid_map is written, which setgroups needs.
        // Raw syscalls, not libc's setgroups/setresuid/setresgid: in a
        // multi-threaded process glibc has every thread switch ids
        // together, and waits for threads that clone() didn't copy.
        // Confirmed for real: run as root, children hung in a futex.
        if self.become_nobody.is_some()
            && unsafe { libc::syscall(libc::SYS_setgroups, 0, std::ptr::null::<libc::gid_t>()) }
                != 0
        {
            let _ = write_raw(2, b"Failed to drop supplementary groups\n");
            return 1;
        }

        // Setup stdin
        if let Some(stdin_fd) = self.stdin_read {
            if unsafe { libc::dup2(stdin_fd, libc::STDIN_FILENO) } < 0 {
                let _ = write_raw(2, b"Failed to redirect stdin\n");
                return 1;
            }
            let _ = close_raw(stdin_fd);
        }
        // clone() inherited our copy of the write end too. It's
        // close-on-exec, but close it now anyway: we never write to it.
        if let Some(fd) = self.stdin_write {
            let _ = close_raw(fd);
        }

        // Redirect stdout/stderr. A failure here leaves the program's
        // output going wherever fd 1/2 pointed to before (whatever this
        // process inherited at clone()), not captured -- fail instead of
        // running with the wrong stdout/stderr.
        if unsafe { libc::dup2(self.stdout_write, libc::STDOUT_FILENO) } < 0
            || unsafe { libc::dup2(self.stderr_write, libc::STDERR_FILENO) } < 0
        {
            let _ = write_raw(2, b"Failed to redirect output\n");
            return 1;
        }
        let _ = close_raw(self.stdout_write);
        let _ = close_raw(self.stderr_write);
        let _ = close_raw(self.stdout_read);
        let _ = close_raw(self.stderr_read);

        // Setup hostname (UTS namespace). Error messages below are
        // fixed strings via raw write(), not eprintln!/format! -- see
        // the module doc for why. nix's sethostname passes the &str's
        // bytes and length straight to libc (no CString), so it doesn't
        // allocate.
        if !self.userns_restricted && nix::unistd::sethostname(&self.hostname).is_err() {
            let _ = write_raw(2, b"Failed to set hostname\n");
        }

        // Mount namespace: caller's rootfs/mounts/tmpfs, then a private
        // /proc, then pivot into the rootfs if any. A failure in what the
        // caller asked for fails the run; /proc alone is best effort.
        if let Some(plan) = &self.mount_plan {
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
        // std::env here -- see ExecBuffers in prepare.rs for why.

        // Change working directory, via raw chdir() rather than
        // std::env::set_current_dir() -- see where working_dir_cstr is
        // built in execute(), above clone(), for why. A failure fails the
        // run: it used to be ignored, leaving the program in whatever
        // directory this process happened to be in.
        if unsafe { libc::chdir(self.working_dir_cstr.as_ptr()) } != 0 {
            let _ = write_raw(2, b"Failed to enter working_dir\n");
            return 1;
        }

        // Before the rlimits: a small max_open_files could stop these
        // sockets from opening.
        if let Some(link) = self.proxy_link_child
            && let Err(step) = link.bind_and_send()
        {
            let _ = write_raw(2, b"Network setup failed: ");
            let _ = write_raw(2, step.as_bytes());
            let _ = write_raw(2, b"\n");
            return 1;
        }

        // Before the rlimits too: it opens a file descriptor per path.
        if let Some(rules) = &self.write_rules
            && let Err(step) = rules.apply()
        {
            let _ = write_raw(2, b"File system rules failed: ");
            let _ = write_raw(2, step.as_bytes());
            let _ = write_raw(2, b"\n");
            return 1;
        }

        // After everything that needs root (mounts, the Landlock rules'
        // paths), before anything of the program's. NO_NEW_PRIVS first:
        // root is mapped in this namespace (see write_mappings), and a
        // setuid-root program mustn't make the program root again.
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

        // Last, so nothing above is filtered. A sandbox that asked for the
        // filter doesn't run without it.
        if let Some(filter) = &self.syscall_filter
            && !filter.install()
        {
            let _ = write_raw(2, b"Failed to install the syscall filter\n");
            return 1;
        }

        // This process becomes init of a fresh PID namespace once cloned;
        // pid_namespaces(7) has the kernel silently drop any default-
        // disposition signal sent to init by another member of that
        // namespace -- including one it sends itself -- unless it's
        // caught. Running the command directly here would leave it unable
        // to be signaled by anything inside its own sandbox (confirmed for
        // real, down to self-SIGKILL doing nothing). Fork instead: this
        // process stays init and relays signals to the command, now PID 2,
        // the same fix `tini`/`dumb-init`/`docker run --init` use for
        // Docker containers hitting the identical problem.
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

        // A raw clone(), not libc's fork(): same no-allocation reasoning
        // as setgroups/setresuid/setresgid above, still in force here --
        // nothing since the original clone() has touched the heap.
        let forked = unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD as libc::c_long, 0i64) };
        if forked < 0 {
            let _ = write_raw(2, b"Failed to fork the sandboxed command\n");
            return 1;
        }

        if forked != 0 {
            // Still PID 1: its init from here, not the command itself.
            // Needs no fds at all -- sigaction/waitpid/kill don't take
            // any -- so close everything rather than keep whatever this
            // run's stdout/stdin/etc. pipes happened to dup2/inherit.
            // That closes a real leak: clone() snapshots this whole
            // process's fd table, so a run's child can inherit a fresh,
            // not-yet-CLOEXEC'd pipe fd another thread's concurrent run
            // was still setting up at that exact moment. Harmless before
            // this shim existed -- the one process in the child always
            // exec'd, and CLOEXEC cleaned it up right then -- but this
            // process never execs, so an inherited stray write end would
            // otherwise stay open for the run's whole lifetime, and
            // whatever reads that pipe never sees EOF. Confirmed for
            // real under concurrent runs: `cat`'s stdin pipe never
            // closed, because a sibling run's leaked write end kept it
            // open from outside the sandbox's own process tree entirely.
            unsafe {
                libc::syscall(libc::SYS_close_range, 0u32, u32::MAX, 0i32);
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
                        // Can't reproduce a true signal-death on itself
                        // for the same reason this fork exists -- the
                        // kernel would just drop it again. Same fallback
                        // `tini` uses: exit with 128+signal rather than
                        // die by it, so the caller still learns which one.
                        (128 + libc::WTERMSIG(status)) as isize
                    } else {
                        1
                    };
                }
                // Someone else's orphan, reparented here: reaped, keep going.
            }
        }

        // PID 2 from here on: the actual sandboxed command.

        // Ignored signals stay ignored across exec, and the signal mask
        // carries over too. This process ignores SIGPIPE (Rust's runtime
        // does), so programs did too: `yes | head -1` had `yes` fail with
        // "Broken pipe" instead of just ending. Give them the defaults.
        // The handlers just installed above for the shim are reset to
        // their defaults by execve() itself, same as this one.
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

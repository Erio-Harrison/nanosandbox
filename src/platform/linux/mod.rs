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
use crate::platform::PlatformExecutor;
use crate::result::ExecutionResult;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::time::{Duration, Instant};

mod cgroup;
mod child;
mod landlock;
mod mount;
mod namespace;
mod prepare;
mod proxy_link;
mod seccomp;
mod wait;

pub use cgroup::CgroupManager;
use child::ChildSetup;
use mount::{check_mounts, needed_cgroup_controllers, MountPlan};
pub use namespace::UserNamespace;
use prepare::{prepare_cgroup, prepare_env, prepare_rlimits, ExecBuffers, Pipes};
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
        use nix::sched::{clone, CloneFlags};
        use nix::sys::signal::Signal;

        const STACK_SIZE: usize = 1024 * 1024;

        let start = Instant::now();

        // Pipes for stdout, stderr, stdin and the ready signal; see
        // prepare::Pipes. The child gets plain copies of the fd numbers
        // (below): it has its own fd table, and closes its own.
        let pipes = Pipes::create(stdin)?;
        let stdout_read = pipes.stdout_read_fd.as_raw_fd();
        let stdout_write = pipes.stdout_write_fd.as_raw_fd();
        let stderr_read = pipes.stderr_read_fd.as_raw_fd();
        let stderr_write = pipes.stderr_write_fd.as_raw_fd();
        let ready_read = pipes.ready_read_fd.as_raw_fd();
        let ready_write = pipes.ready_write_fd.as_raw_fd();
        let stdin_read = pipes.stdin_read_fd.as_ref().map(AsRawFd::as_raw_fd);
        let stdin_write = pipes.stdin_write_fd.as_ref().map(AsRawFd::as_raw_fd);

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

        // See prepare::prepare_cgroup: created and configured *before*
        // clone(), so a failure there never leaves a half-started child
        // stuck on the ready pipe.
        let cgroup = prepare_cgroup(config)?;

        // Prepare command arguments. A NUL byte in one is an error: it used
        // to panic here.
        let cmd_cstr = CString::new(cmd)?;
        let args_cstr: Vec<CString> = std::iter::once(Ok(cmd_cstr.clone()))
            .chain(args.iter().map(|s| CString::new(*s)))
            .collect::<std::result::Result<_, _>>()?;

        // Allocate stack for child
        let mut stack = vec![0u8; STACK_SIZE];

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

        // See prepare::prepare_env: clear_env, TMPDIR, the proxy's env vars,
        // a default PATH.
        let env = prepare_env(
            config,
            proxy_link.is_some(),
            private_tmp.as_ref().map(PrivateTmp::path),
        );

        // See prepare::ExecBuffers for why these are built here, before
        // clone(), and just used as-is in the child.
        let exec_buffers = ExecBuffers::build(cmd, cmd_cstr, args_cstr, &env)?;

        // A pre-built CString, used with raw stat()/chdir() in the child
        // instead of Path::exists()/std::env::set_current_dir() -- both
        // allocate internally (building their own CString from the path),
        // and any allocation in the child risks the same frozen-malloc-lock
        // hang as ExecBuffers's own envp_cstr (see prepare.rs): clone() is a
        // raw syscall here, not libc's fork(), so it doesn't get glibc's
        // pthread_atfork() malloc-lock protection either. Confirmed for real
        // via gdb: a child stuck in malloc, called from eprintln!, itself
        // called from child.rs after clone().
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

        // See prepare::prepare_rlimits: applied with raw setrlimit() in the
        // child, built here for the same no-allocation-after-clone() reason
        // as everything in child.rs.
        let rlimits = prepare_rlimits(config);

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

        // Everything the child needs, built above; see child.rs.
        let child_setup = ChildSetup {
            cmd_cstr: exec_buffers.cmd_cstr,
            args_cstr: exec_buffers.args_cstr,
            envp_cstr: exec_buffers.envp_cstr,
            args_ptrs: exec_buffers.args_ptrs,
            envp_ptrs: exec_buffers.envp_ptrs,
            exec_paths: exec_buffers.exec_paths,
            ready_write,
            ready_read,
            become_nobody,
            stdin_read,
            stdin_write,
            stdout_write,
            stderr_write,
            stdout_read,
            stderr_read,
            userns_restricted,
            hostname,
            mount_plan,
            working_dir_cstr,
            proxy_link_child,
            write_rules,
            rlimits,
            syscall_filter,
        };

        // Child process entry point
        let child_fn: Box<dyn FnMut() -> isize> = Box::new(move || child_setup.run());

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
        drop(pipes.ready_read_fd);
        drop(pipes.stdout_write_fd);
        drop(pipes.stderr_write_fd);
        drop(pipes.stdin_read_fd);

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
        drop(pipes.ready_write_fd);

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
        let stdin_pipe = match (stdin, pipes.stdin_write_fd) {
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
            [pipes.stdout_read_fd, pipes.stderr_read_fd],
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

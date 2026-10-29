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
use crate::platform::PlatformExecutor;
use crate::platform::private_tmp::PrivateTmp;
use crate::platform::supervise::{self, Handles, Launched, Outcome, Supervisor};
use crate::result::ExecutionResult;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

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
use mount::{MountPlan, check_mounts, needed_cgroup_controllers};
pub use namespace::UserNamespace;
use prepare::{ExecBuffers, Pipes, prepare_cgroup, prepare_env, prepare_rlimits};
use proxy_link::{ProxyLink, check_network};
use seccomp::SyscallFilter;
use wait::{CpuLimit, Ended, supervise as supervise_run};

/// CPUs a run can use at once: the host's, capped by `cpu_limit`.
fn parallelism(config: &SandboxConfig) -> u32 {
    let host = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
    match config.cpu_limit {
        Some(cpus) if cpus >= 1.0 => host.min(cpus.ceil() as u32),
        Some(_) => 1,
        None => host,
    }
}

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

/// Paths to try for `cmd` in order, as execvp searches $PATH: `cmd` if it contains '/', else
/// each `path_value` directory joined with it. Tried by the child inside its rootfs, not on the host.
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

/// Whether the default config can run here: user namespaces, Landlock (no rootfs), and a
/// syscall filter for this arch. Cgroup v2 isn't checked (see `needs_cgroup`). A host that says
/// no can still run some configs; `build()` decides per config.
pub fn is_supported() -> bool {
    check_user_namespace_support() && landlock::abi() >= 1 && SyscallFilter::supported()
}

fn check_user_namespace_support() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .map(|s| s.trim() == "1")
        .unwrap_or(true) // If file doesn't exist, assume enabled (newer kernels)
}

fn check_cgroup_v2_support() -> bool {
    std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

/// Whether this config needs cgroups; hosts without cgroup v2 (e.g. hybrid v1/v2) should still
/// run sandboxes that ask for none.
fn needs_cgroup(config: &SandboxConfig) -> bool {
    config.memory_limit.is_some()
        || config.cpu_limit.is_some()
        || config.cpu_time_limit.is_some()
        || config.max_pids.is_some()
}

#[cfg(test)]
mod needs_cgroup_tests {
    use super::needs_cgroup;
    use crate::Sandbox;

    #[test]
    fn only_when_a_cgroup_backed_limit_is_set() {
        assert!(!needs_cgroup(&Sandbox::builder().into_config()));
        assert!(needs_cgroup(
            &Sandbox::builder().memory_limit(1).into_config()
        ));
        assert!(needs_cgroup(
            &Sandbox::builder().cpu_limit(0.5).into_config()
        ));
        assert!(needs_cgroup(
            &Sandbox::builder()
                .cpu_time_limit(std::time::Duration::from_secs(1))
                .into_config()
        ));
        assert!(needs_cgroup(&Sandbox::builder().max_pids(1).into_config()));
    }
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

/// Starts the command (on the supervisor thread) and returns its I/O ends with the closure that
/// supervises it there to the end.
fn launch_in_thread(
    config: &Arc<SandboxConfig>,
    cmd: &str,
    args: &[String],
    stdin: bool,
    proxy: Option<Arc<ProxiedNetwork>>,
) -> Result<(Handles, impl FnOnce() -> Result<Outcome> + use<>)> {
    use nix::sched::{CloneFlags, clone};
    use nix::sys::signal::Signal;

    const STACK_SIZE: usize = 1024 * 1024;

    // Pipes (see prepare::Pipes). The child gets plain fd numbers: it has its own fd table.
    let user_ns =
        UserNamespace::new(config.uid, config.gid).with_host_ids(config.host_uid, config.host_gid);
    let pipes = Pipes::create(stdin, user_ns.host_ids())?;
    let stdout_read = pipes.stdout_read_fd.as_raw_fd();
    let stdout_write = pipes.stdout_write_fd.as_raw_fd();
    let stderr_read = pipes.stderr_read_fd.as_raw_fd();
    let stderr_write = pipes.stderr_write_fd.as_raw_fd();
    let ready_read = pipes.ready_read_fd.as_raw_fd();
    let ready_write = pipes.ready_write_fd.as_raw_fd();
    let signal_read = pipes.signal_read_fd.as_raw_fd();
    let signal_write = pipes.signal_write_fd.as_raw_fd();
    let stdin_read = pipes.stdin_read_fd.as_ref().map(AsRawFd::as_raw_fd);
    let stdin_write = pipes.stdin_write_fd.as_ref().map(AsRawFd::as_raw_fd);

    let mut clone_flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWIPC;

    // Proxied gets its own netns with the proxy as its only way out (see `ProxyLink`); otherwise
    // the whitelist only held for programs honoring HTTP_PROXY.
    if !matches!(config.network_mode, NetworkMode::Host) {
        clone_flags |= CloneFlags::CLONE_NEWNET;
    }
    let mut proxy_link = match (&config.network_mode, &proxy) {
        (NetworkMode::Proxied { .. }, Some(_)) => Some(ProxyLink::new(SANDBOX_PROXY_PORT)?),
        _ => None,
    };

    // See prepare::prepare_cgroup: made before clone() so a failure can't strand the child.
    let cgroup = prepare_cgroup(config)?;

    // A NUL byte is an error.
    let cmd_cstr = CString::new(cmd)?;
    let args_cstr: Vec<CString> = std::iter::once(Ok(cmd_cstr.clone()))
        .chain(args.iter().map(|s| CString::new(s.as_str())))
        .collect::<std::result::Result<_, _>>()?;

    let mut stack = vec![0u8; STACK_SIZE];

    // private_tmp: a tmpfs at /tmp (see MountPlan), or under AppArmor a per-run directory
    // (platform/private_tmp.rs). TMPDIR points to it either way.
    let userns_restricted = userns_restricted_by_apparmor();
    let mut private_tmp = config
        .private_tmp
        .filter(|_| userns_restricted)
        .map(PrivateTmp::create)
        .transpose()
        .map_err(|e| SandboxError::Internal {
            context: "create private /tmp".into(),
            source: Box::new(e),
        })?;

    // See prepare::prepare_env.
    let env = prepare_env(
        config,
        proxy_link.is_some(),
        private_tmp.as_ref().map(PrivateTmp::path),
    );

    // See prepare::ExecBuffers: built before clone(), used as-is in the child.
    let exec_buffers = ExecBuffers::build(cmd, cmd_cstr, args_cstr, &env)?;

    // Pre-built CString for raw stat()/chdir() in the child: Path::exists()/set_current_dir()
    // allocate, risking the frozen-malloc-lock hang (see ExecBuffers in prepare.rs).
    let working_dir_cstr = CString::new(config.working_dir.as_os_str().as_bytes())?;
    let hostname = config.hostname.clone();
    // Where AppArmor denies mounting and sethostname in the userns, skip both rather than log
    // failures per run. check_mounts already refused caller mounts at build().
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

    // See prepare::prepare_rlimits: raw setrlimit() in the child.
    let rlimits = prepare_rlimits(config);

    // As root, the ids the child switches to before exec (see namespace::runs_as_root).
    let become_nobody = namespace::runs_as_root().then(|| user_ns.ids());

    let proxy_link_child = proxy_link.as_ref().map(ProxyLink::child_side);

    // Without a rootfs: writes only to ReadWrite mounts, tmpfs and temp dirs.
    let write_rules = landlock::WriteRules::new(config, private_tmp.as_ref().map(PrivateTmp::path))?;

    // check_support refused seccomp(true) where there's no filter.
    let syscall_filter = if config.seccomp {
        SyscallFilter::new()
    } else {
        None
    };

    let child_setup = ChildSetup {
        cmd_cstr: exec_buffers.cmd_cstr,
        args_cstr: exec_buffers.args_cstr,
        envp_cstr: exec_buffers.envp_cstr,
        args_ptrs: exec_buffers.args_ptrs,
        envp_ptrs: exec_buffers.envp_ptrs,
        exec_paths: exec_buffers.exec_paths,
        ready_write,
        ready_read,
        signal_read,
        signal_write,
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

    let child_fn: Box<dyn FnMut() -> isize> = Box::new(move || child_setup.run());

    let child_pid = unsafe {
        clone(
            child_fn,
            &mut stack,
            clone_flags,
            Some(Signal::SIGCHLD as i32),
        )
    }
    .map_err(|e| SandboxError::Internal {
        context: "clone sandboxed process".into(),
        source: Box::new(e),
    })?;

    if let Some(link) = &mut proxy_link {
        link.close_child_end();
    }

    // Until the child is signaled it is parked on the ready pipe, so any failure here must kill
    // and reap it. One closure so every early return goes through that cleanup. The child's ends
    // are the child's now.
    drop(pipes.ready_read_fd);
    drop(pipes.signal_write_fd);
    drop(pipes.stdout_write_fd);
    drop(pipes.stderr_write_fd);
    drop(pipes.stdin_read_fd);

    let setup: Result<()> = (|| {
        user_ns.write_mappings(child_pid.as_raw())?;
        if let Some(ref cg) = cgroup {
            cg.add_process(child_pid.as_raw() as u32)?;
        }
        write_raw(ready_write, &[0u8]).map_err(|e| SandboxError::Internal {
            context: "signal child to continue".into(),
            source: Box::new(e),
        })?;
        Ok(())
    })();
    if let Err(e) = setup {
        let _ = nix::sys::signal::kill(child_pid, Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(child_pid, None);
        return Err(e);
    }
    drop(pipes.ready_write_fd);

    // Serve the proxy on the listener the child bound in its netns, for this run only (kept
    // open it would keep that ns alive). No listener: the child failed network setup and said why
    // on stderr.
    let proxy_attachment = match (&proxy_link, &proxy) {
        (Some(link), Some(proxy)) => match link.receive().map(|l| proxy.attach(l)) {
            Some(Err(e)) => {
                let _ = nix::sys::signal::kill(child_pid, Signal::SIGKILL);
                let _ = nix::sys::wait::waitpid(child_pid, None);
                return Err(SandboxError::Internal {
                    context: "serve the proxy inside the sandbox".into(),
                    source: Box::new(e),
                });
            }
            attached => attached.transpose().ok().flatten(),
        },
        _ => None,
    };

    let handles = Handles {
        stdin: pipes.stdin_write_fd,
        stdout: Some(pipes.stdout_read_fd),
        stderr: Some(pipes.stderr_read_fd),
        pid: child_pid.as_raw() as u32,
    };
    let signal_pipe = pipes.signal_read_fd;
    let timeout = config.wall_time_limit.unwrap_or(Duration::from_secs(3600));
    let cpu_time_limit = config.cpu_time_limit;
    let parallelism = parallelism(config);

    let supervise = move || {
        let Ended {
            exit_code,
            killed_by_timeout,
            killed_by_tmp_limit,
            killed_by_cpu_limit,
            signal,
            proc_mount_failed,
            rusage,
        } = supervise_run(
            child_pid,
            signal_pipe,
            timeout,
            private_tmp.as_mut(),
            cgroup
                .as_ref()
                .zip(cpu_time_limit)
                .map(|(cgroup, limit)| CpuLimit {
                    cgroup,
                    limit,
                    parallelism,
                }),
        )?;
        let blocked_hosts = proxy_attachment.map(|a| a.finish()).unwrap_or_default();
        drop(private_tmp);

        // Without a cgroup, wait4's rusage is the fallback: CPU time sums waited descendants, maxrss
        // is the largest single one. The cgroup's whole-tree numbers win when present.
        let tv = |t: libc::timeval| {
            Duration::from_secs(t.tv_sec as u64) + Duration::from_micros(t.tv_usec as u64)
        };
        let rusage_cpu = tv(rusage.ru_utime) + tv(rusage.ru_stime);
        let rusage_peak = rusage.ru_maxrss as u64 * 1024; // Linux reports KiB

        // Collect stats BEFORE cgroup cleanup.
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
        drop(cgroup);

        Ok(Outcome {
            exit_code,
            signal,
            killed_by_timeout,
            killed_by_oom,
            killed_by_tmp_limit,
            killed_by_cpu_limit,
            peak_memory,
            cpu_time,
            proc_isolated: !userns_restricted && !proc_mount_failed,
            blocked_hosts,
        })
    };
    Ok((handles, supervise))
}

impl PlatformExecutor for LinuxExecutor {
    fn launch(
        &self,
        config: Arc<SandboxConfig>,
        cmd: &str,
        args: &[&str],
        stdin: bool,
        proxy: Option<Arc<ProxiedNetwork>>,
    ) -> Result<Launched> {
        let cmd = cmd.to_string();
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        Supervisor::start(move || launch_in_thread(&config, &cmd, &args, stdin, proxy))
    }

    fn execute(
        &self,
        config: &Arc<SandboxConfig>,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        proxy: Option<&Arc<ProxiedNetwork>>,
    ) -> Result<ExecutionResult> {
        let launched = self.launch(Arc::clone(config), cmd, args, stdin.is_some(), proxy.cloned())?;
        let result = supervise::collect(launched, stdin, config.max_output)?;
        // The child writes this exact line only from this exit code, after giving up on every $PATH
        // candidate, so it's safe to turn into `SandboxError::CommandNotFound`, matching Windows.
        if result.exit_code == 127
            && result.signal.is_none()
            && !result.killed_by_timeout
            && !result.killed_by_tmp_limit
            && result.stderr.starts_with("nanosandbox: ")
            && result.stderr.ends_with(": command not found\n")
        {
            return Err(SandboxError::CommandNotFound(cmd.to_string()));
        }
        Ok(result)
    }

    fn check_support(&self, config: &SandboxConfig) -> Result<()> {
        if !check_user_namespace_support() {
            return Err(SandboxError::UserNamespaceDisabled);
        }
        if needs_cgroup(config) && !check_cgroup_v2_support() {
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
        if !namespace::runs_as_root() && (config.host_uid.is_some() || config.host_gid.is_some()) {
            return Err(SandboxError::Unsupported {
                setting: "host_uid/host_gid".into(),
                reason: "only a root caller can choose the host user its sandbox runs as; an \
                         unprivileged caller can only map its own ids"
                    .into(),
            });
        }
        if config.host_uid == Some(0) || config.host_gid == Some(0) {
            return Err(SandboxError::Unsupported {
                setting: "host_uid(0)/host_gid(0)".into(),
                reason: "0 is root's, which the sandbox must not run as".into(),
            });
        }
        // Without a rootfs working_dir is a host path: check it now. (With one, it's in the rootfs.)
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

/// Ubuntu 23.10+: an unprivileged, unconfined process's new userns lands in AppArmor's
/// `unprivileged_userns` profile, which denies mounting, sethostname and netns loopback
/// (CAP_NET_ADMIN) despite the kernel allowing them. Root and executables with their own
/// `userns`-allowing profile are unaffected.
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

    /// The answer matches whether the default config actually builds.
    #[test]
    fn is_supported_agrees_with_building_the_default_sandbox() {
        let builds = crate::Sandbox::builder()
            .working_dir("/tmp")
            .build()
            .is_ok();
        assert_eq!(is_supported(), builds);
    }

    #[test]
    fn test_linux_executor_creation() {
        let executor = LinuxExecutor::new();
        let _ = executor;
    }
}

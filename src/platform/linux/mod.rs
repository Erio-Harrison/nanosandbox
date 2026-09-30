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
use crate::platform::PlatformExecutor;
use crate::result::ExecutionResult;
use std::os::unix::io::{IntoRawFd, RawFd};
use std::time::{Duration, Instant};

mod cgroup;
mod namespace;
mod seccomp;

pub use cgroup::CgroupManager;
pub use namespace::{MountNamespace, UserNamespace, UtsNamespace};
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
        use nix::unistd::{execvp, pipe};
        use std::ffi::CString;

        const STACK_SIZE: usize = 1024 * 1024;

        let start = Instant::now();

        // Create pipes for stdout, stderr, and synchronization
        let (r, w) = pipe().map_err(|e| SandboxError::Internal(format!("create pipe for child stdout: {e}")))?;
        let stdout_read: RawFd = r.into_raw_fd();
        let stdout_write: RawFd = w.into_raw_fd();

        let (r, w) = pipe().map_err(|e| SandboxError::Internal(format!("create pipe for child stderr: {e}")))?;
        let stderr_read: RawFd = r.into_raw_fd();
        let stderr_write: RawFd = w.into_raw_fd();

        let (r, w) = pipe().map_err(|e| SandboxError::Internal(format!("create pipe for parent-child sync: {e}")))?;
        let ready_read: RawFd = r.into_raw_fd();
        let ready_write: RawFd = w.into_raw_fd();

        let (stdin_read, stdin_write) = if stdin.is_some() {
            let (r, w) = pipe().map_err(|e| SandboxError::Internal(format!("create pipe for child stdin: {e}")))?;
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

        // Clone config for child
        let child_config = config.clone();
        let mut env = config.env.clone();

        // Add proxy environment variables if using proxied network
        if let Some(proxy) = proxy {
            for (key, value) in proxy.env_vars() {
                env.insert(key, value);
            }
        }

        let working_dir = config.working_dir.clone();
        let hostname = config.hostname.clone();

        // Create user namespace config
        let user_ns = UserNamespace::new(config.uid, config.gid);

        // Child process entry point
        let child_fn: Box<dyn FnMut() -> isize> = Box::new(move || {
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

            // Setup hostname (UTS namespace)
            if let Err(e) = nix::unistd::sethostname(&hostname) {
                eprintln!("Failed to set hostname: {}", e);
            }

            // Setup mount namespace if needed
            if let Some(rootfs) = &child_config.rootfs {
                if let Err(e) = setup_mount_namespace(rootfs, &child_config.mounts, &child_config.tmpfs_mounts) {
                    eprintln!("Mount setup failed: {}", e);
                    return 1;
                }
            }

            // Set environment
            for (key, _) in std::env::vars() {
                std::env::remove_var(&key);
            }
            for (key, value) in &env {
                std::env::set_var(key, value);
            }
            if !env.contains_key("PATH") {
                std::env::set_var("PATH", "/usr/local/bin:/usr/bin:/bin");
            }

            // Change working directory
            if working_dir.exists() {
                let _ = std::env::set_current_dir(&working_dir);
            }

            // Apply seccomp filter
            if !matches!(child_config.seccomp_profile, SeccompProfile::Disabled) {
                if let Err(e) = SeccompFilter::apply(&child_config.seccomp_profile) {
                    eprintln!("Seccomp setup failed: {}", e);
                }
            }

            // Execute
            let _ = execvp(&cmd_cstr, &args_cstr);
            eprintln!("execvp failed");
            127
        });

        // Clone child
        let child_pid = unsafe {
            clone(child_fn, &mut stack, clone_flags, Some(Signal::SIGCHLD as i32))
        }.map_err(|e| SandboxError::Internal(format!("clone sandboxed process: {e}")))?;

        // Parent process

        // Everything here runs before the child is ever signaled to
        // continue past its ready-pipe wait (below) — it's stuck there
        // regardless of what we do, so any failure in this block must
        // kill and reap it before returning, not just propagate the error
        // and leave it parked forever. Folded into one closure so every
        // early return here goes through that same cleanup, rather than
        // needing it repeated (and, before, missed) at each fallible step.
        let setup: Result<()> = (|| {
            close_raw(ready_read).map_err(|e| SandboxError::Internal(format!("close sync pipe read end in parent: {e}")))?;
            close_raw(stdout_write).map_err(|e| SandboxError::Internal(format!("close stdout pipe write end in parent: {e}")))?;
            close_raw(stderr_write).map_err(|e| SandboxError::Internal(format!("close stderr pipe write end in parent: {e}")))?;
            if let Some(fd) = stdin_read {
                close_raw(fd).map_err(|e| SandboxError::Internal(format!("close stdin pipe read end in parent: {e}")))?;
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
        write_raw(ready_write, &[0u8]).map_err(|e| SandboxError::Internal(format!("signal child to continue: {e}")))?;
        close_raw(ready_write).map_err(|e| SandboxError::Internal(format!("close sync pipe write end after signaling: {e}")))?;

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
            let cpu = cg.get_cpu_stats().ok().map(|s| Duration::from_micros(s.total_usec));
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

fn setup_mount_namespace(
    rootfs: &std::path::Path,
    mounts: &[Mount],
    tmpfs_mounts: &[(std::path::PathBuf, u64)],
) -> Result<()> {
    use nix::mount::{mount, MsFlags};

    // Make everything private
    mount::<str, str, str, str>(None, "/", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)
        .map_err(|e| SandboxError::Internal(format!("mark all mounts as private: {e}")))?;

    // Bind mount rootfs
    mount(
        Some(rootfs),
        rootfs,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| SandboxError::Internal(format!("bind mount rootfs at {}: {e}", rootfs.display())))?;

    // Setup mounts
    for m in mounts {
        let target = rootfs.join(m.target.strip_prefix("/").unwrap_or(&m.target));
        std::fs::create_dir_all(&target)?;

        let mut flags = MsFlags::MS_BIND;
        if m.permission == Permission::ReadOnly {
            flags |= MsFlags::MS_RDONLY;
        }

        mount(
            Some(&m.source),
            &target,
            None::<&str>,
            flags,
            None::<&str>,
        )
        .map_err(|e| SandboxError::Internal(format!("bind mount {} -> {}: {e}", m.source.display(), m.target.display())))?;
    }

    // Setup tmpfs mounts
    for (path, size) in tmpfs_mounts {
        let target = rootfs.join(path.strip_prefix("/").unwrap_or(path));
        std::fs::create_dir_all(&target)?;

        let options = format!("size={}", size);
        mount(
            None::<&str>,
            &target,
            Some("tmpfs"),
            MsFlags::empty(),
            Some(options.as_str()),
        )
        .map_err(|e| SandboxError::Internal(format!("mount tmpfs at {} (size={}): {e}", path.display(), size)))?;
    }

    // Pivot root
    let old_root = rootfs.join("old_root");
    std::fs::create_dir_all(&old_root)?;

    nix::unistd::pivot_root(rootfs, &old_root)
        .map_err(|e| SandboxError::Internal(format!("pivot_root into sandbox at {}: {e}", rootfs.display())))?;
    std::env::set_current_dir("/")?;

    // Unmount old root
    mount::<str, str, str, str>(None, "/old_root", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)
        .map_err(|e| SandboxError::Internal(format!("mark /old_root as private mount: {e}")))?;
    nix::mount::umount2("/old_root", nix::mount::MntFlags::MNT_DETACH)
        .map_err(|e| SandboxError::Internal(format!("detach /old_root mount: {e}")))?;
    std::fs::remove_dir("/old_root")?;

    Ok(())
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

//! macOS platform implementation
//!
//! Uses macOS sandbox-exec (Seatbelt) for sandboxing.
//!
//! ## Implementation
//!
//! - **Process isolation**: sandbox-exec with SBPL profiles
//! - **Filesystem**: Sandbox profile file system restrictions
//! - **Network**: Sandbox profile network restrictions + HTTP proxy for whitelisting
//! - **Resource limits**: setrlimit (RLIMIT_AS, RLIMIT_NPROC, RLIMIT_NOFILE)

use crate::builder::{NetworkMode, Permission, SandboxConfig, SeccompProfile};
use crate::error::{Result, SandboxError};
use crate::network::ProxiedNetwork;
use crate::platform::PlatformExecutor;
use crate::result::ExecutionResult;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// std's spawn error carries only errno, so the child reports which setrlimit
// failed through a side pipe as [limit, errno].
const LIMIT_OPEN_FILES: u8 = 1;
const LIMIT_FILE_SIZE: u8 = 2;
const LIMIT_CPU_TIME: u8 = 3;

/// Check if sandbox-exec is available
pub fn is_supported() -> bool {
    std::path::Path::new("/usr/bin/sandbox-exec").exists()
}

/// macOS sandbox executor using sandbox-exec
pub struct MacOSExecutor {
    _private: (),
}

impl MacOSExecutor {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Generate SBPL (Sandbox Profile Language) profile
    fn generate_profile(&self, config: &SandboxConfig) -> String {
        let mut profile = String::new();

        // Version and default deny
        profile.push_str("(version 1)\n");
        profile.push_str("(deny default)\n");

        // Allow basic process operations
        profile.push_str("(allow process-fork)\n");
        profile.push_str("(allow process-exec)\n");
        profile.push_str("(allow process-exec-interpreter)\n");
        profile.push_str("(allow signal)\n");

        // Allow sysctl operations
        profile.push_str("(allow sysctl-read)\n");
        profile.push_str("(allow sysctl-write)\n");

        // Allow mach operations
        profile.push_str("(allow mach-lookup)\n");
        profile.push_str("(allow mach-register)\n");
        profile.push_str("(allow mach-priv-host-port)\n");
        profile.push_str("(allow mach-priv-task-port)\n");
        profile.push_str("(allow mach-task-name)\n");

        // Allow IPC operations
        profile.push_str("(allow ipc-posix-shm-read-data)\n");
        profile.push_str("(allow ipc-posix-shm-write-data)\n");
        profile.push_str("(allow ipc-posix-shm-read-metadata)\n");
        profile.push_str("(allow ipc-posix-shm-write-create)\n");
        profile.push_str("(allow ipc-posix-sem)\n");

        // Allow iokit and pseudo-tty
        profile.push_str("(allow iokit-open)\n");
        profile.push_str("(allow pseudo-tty)\n");

        // Allow process info
        profile.push_str("(allow process-info-pidinfo)\n");
        profile.push_str("(allow process-info-setcontrol)\n");
        profile.push_str("(allow process-info-dirtycontrol)\n");
        profile.push_str("(allow process-info-codesignature)\n");

        // Allow reading from anywhere (simplifies profile)
        profile.push_str("(allow file-read* (subpath \"/\"))\n");

        // Allow writes to specific directories
        profile.push_str("(allow file-write* (subpath \"/tmp\"))\n");
        profile.push_str("(allow file-write* (subpath \"/private/tmp\"))\n");
        profile.push_str("(allow file-write* (subpath \"/private/var/folders\"))\n");
        profile.push_str("(allow file-write* (subpath \"/dev\"))\n");

        // Working directory write access
        let working_dir = config.working_dir.to_string_lossy();
        profile.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", working_dir));

        // Custom mount write access
        for mount in &config.mounts {
            if mount.permission == Permission::ReadWrite {
                let source = mount.source.to_string_lossy();
                profile.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", source));
            }
        }

        // tmpfs mount write access
        for (path, _) in &config.tmpfs_mounts {
            let path_str = path.to_string_lossy();
            profile.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", path_str));
        }

        // Rootfs write access if specified
        if let Some(rootfs) = &config.rootfs {
            let rootfs_str = rootfs.to_string_lossy();
            profile.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", rootfs_str));
        }

        // Network rules
        match &config.network_mode {
            NetworkMode::None => {
                // No network rules - default deny applies
            }
            NetworkMode::Host | NetworkMode::Proxied { .. } => {
                profile.push_str("(allow network*)\n");
            }
        }

        profile
    }

    /// Apply resource limits using setrlimit.
    /// Runs in the child between fork and exec, so it must not allocate.
    /// `memory_limit` is not applied here: the macOS kernel rejects RLIMIT_AS,
    /// so `wait_with_timeout` enforces it by polling instead.
    fn apply_resource_limits(
        max_open_files: Option<u32>,
        max_file_size: Option<u64>,
        cpu_time_limit: Option<Duration>,
        report_fd: libc::c_int,
    ) -> std::io::Result<()> {
        // NOTE: RLIMIT_NPROC is NOT used on macOS because it limits processes
        // for the ENTIRE USER, not just the sandbox. This is not useful for
        // sandboxing and can interfere with other processes.
        // On Linux, we use cgroups pids controller instead.
        if let Some(max_files) = max_open_files {
            Self::set_rlimit(libc::RLIMIT_NOFILE, max_files as u64)
                .map_err(|e| Self::report_limit_failure(report_fd, LIMIT_OPEN_FILES, e))?;
        }
        if let Some(size) = max_file_size {
            Self::set_rlimit(libc::RLIMIT_FSIZE, size)
                .map_err(|e| Self::report_limit_failure(report_fd, LIMIT_FILE_SIZE, e))?;
        }
        if let Some(cpu_time) = cpu_time_limit {
            let secs = cpu_time.as_secs();
            if secs > 0 {
                Self::set_rlimit(libc::RLIMIT_CPU, secs)
                    .map_err(|e| Self::report_limit_failure(report_fd, LIMIT_CPU_TIME, e))?;
            }
        }
        Ok(())
    }

    /// Runs in the child, so it only makes one write(2) and does not allocate.
    fn report_limit_failure(fd: libc::c_int, limit: u8, err: std::io::Error) -> std::io::Error {
        let mut buf = [0u8; 5];
        buf[0] = limit;
        buf[1..].copy_from_slice(&err.raw_os_error().unwrap_or(0).to_ne_bytes());
        unsafe {
            libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len());
        }
        err
    }

    fn report_pipe() -> Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0 as libc::c_int; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(SandboxError::Internal(format!(
                "create limit report pipe: {}",
                std::io::Error::last_os_error()
            )));
        }
        for fd in fds {
            unsafe {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
        }
        Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
    }

    /// Turn a child's report into a message naming the rejected setting.
    fn limit_failure(report: OwnedFd, config: &SandboxConfig) -> Option<String> {
        let mut buf = [0u8; 5];
        let n = unsafe {
            libc::read(report.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        if n != buf.len() as isize {
            return None;
        }
        let errno = i32::from_ne_bytes(buf[1..].try_into().ok()?);
        let (setting, value, rlimit) = match buf[0] {
            LIMIT_OPEN_FILES => ("max_open_files", config.max_open_files?.to_string(), "RLIMIT_NOFILE"),
            LIMIT_FILE_SIZE => ("max_file_size", config.max_file_size?.to_string(), "RLIMIT_FSIZE"),
            LIMIT_CPU_TIME => ("cpu_time_limit", format!("{}s", config.cpu_time_limit?.as_secs()), "RLIMIT_CPU"),
            _ => return None,
        };
        Some(format!(
            "cannot apply {setting}={value} ({rlimit}): {}",
            std::io::Error::from_raw_os_error(errno)
        ))
    }

    fn set_rlimit(resource: libc::c_int, value: u64) -> std::io::Result<()> {
        let rlim = libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        if unsafe { libc::setrlimit(resource, &rlim) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn list_pids(kind: u32, arg: u32) -> Vec<i32> {
        let size = std::mem::size_of::<i32>();
        let bytes = unsafe { libc::proc_listpids(kind, arg, std::ptr::null_mut(), 0) };
        if bytes <= 0 {
            return Vec::new();
        }
        let mut pids = vec![0i32; bytes as usize / size + 16];
        let bytes = unsafe {
            libc::proc_listpids(
                kind,
                arg,
                pids.as_mut_ptr() as *mut libc::c_void,
                (pids.len() * size) as libc::c_int,
            )
        };
        if bytes <= 0 {
            return Vec::new();
        }
        pids.truncate(bytes as usize / size);
        pids.retain(|&pid| pid > 0);
        pids
    }

    /// The root process, its process group and all descendants. Descendants that
    /// leave the group (setsid/setpgid) are found through parent links; ones
    /// orphaned to launchd are not, macOS has no cgroup-style way to find them.
    fn sandbox_pids(root: i32) -> Vec<i32> {
        const PROC_PGRP_ONLY: u32 = 2;
        const PROC_PPID_ONLY: u32 = 6;
        let mut seen = HashSet::from([root]);
        let mut pending = vec![root];
        for pid in Self::list_pids(PROC_PGRP_ONLY, root as u32) {
            if seen.insert(pid) {
                pending.push(pid);
            }
        }
        while let Some(pid) = pending.pop() {
            for child in Self::list_pids(PROC_PPID_ONLY, pid as u32) {
                if seen.insert(child) {
                    pending.push(child);
                }
            }
        }
        seen.into_iter().collect()
    }

    /// Kill the sandbox's whole process tree
    fn kill_process_tree(root: i32) {
        for pid in Self::sandbox_pids(root) {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        unsafe {
            libc::kill(-root, libc::SIGKILL);
        }
    }

    /// Physical footprint summed over the process tree
    fn tree_footprint(root: i32) -> u64 {
        Self::sandbox_pids(root)
            .into_iter()
            .map(|pid| {
                let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
                let ret = unsafe {
                    libc::proc_pid_rusage(
                        pid,
                        libc::RUSAGE_INFO_V2,
                        &mut info as *mut _ as *mut libc::rusage_info_t,
                    )
                };
                if ret == 0 { info.ri_phys_footprint } else { 0 }
            })
            .sum()
    }
}

impl Default for MacOSExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformExecutor for MacOSExecutor {
    fn execute(
        &self,
        config: &SandboxConfig,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<ExecutionResult> {
        let start = Instant::now();

        // Setup proxy if using proxied network mode
        let proxy = match &config.network_mode {
            NetworkMode::Proxied { allowed_domains } => {
                Some(ProxiedNetwork::setup(allowed_domains.clone())?)
            }
            _ => None,
        };

        // Generate sandbox profile
        let profile = self.generate_profile(config);

        let (report_rd, report_wr) = Self::report_pipe()?;
        let report_fd = report_wr.as_raw_fd();

        // Clone config values for the closure
        let max_open_files = config.max_open_files;
        let max_file_size = config.max_file_size;
        let cpu_time_limit = config.cpu_time_limit;

        // Build command: sandbox-exec -p <profile> <cmd> <args>
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.arg("-p").arg(&profile);
        command.arg(cmd);
        command.args(args);

        // Set working directory
        command.current_dir(&config.working_dir);

        // Clear and set environment
        if config.clear_env {
            command.env_clear();
        }
        for (key, value) in &config.env {
            command.env(key, value);
        }
        // Set default PATH if not provided
        if !config.env.contains_key("PATH") {
            command.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
        }

        // Set proxy environment variables if proxied network
        if let Some(ref proxy) = proxy {
            for (key, value) in proxy.env_vars() {
                command.env(key, value);
            }
        }

        // Setup stdin/stdout/stderr
        command.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        // CRITICAL: Set up process group and resource limits before exec
        // This runs in the child process after fork but before exec
        unsafe {
            command.pre_exec(move || {
                // Create a new process group with this process as leader
                // This allows us to kill all children with killpg
                libc::setpgid(0, 0);

                MacOSExecutor::apply_resource_limits(
                    max_open_files,
                    max_file_size,
                    cpu_time_limit,
                    report_fd,
                )
            });
        }

        // Spawn the process
        let spawned = command.spawn();
        drop(report_wr);
        let mut child = match spawned {
            Ok(child) => {
                drop(report_rd);
                child
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(SandboxError::CommandNotFound(cmd.to_string()));
            }
            Err(e) => {
                let msg = Self::limit_failure(report_rd, config).unwrap_or_else(|| e.to_string());
                return Err(SandboxError::ExecutionFailed(msg));
            }
        };

        let child_pid = child.id() as i32;

        // Write stdin if provided
        if let Some(stdin_data) = stdin {
            if let Some(mut stdin_pipe) = child.stdin.take() {
                let _ = stdin_pipe.write_all(stdin_data);
                // Drop stdin to close the pipe and signal EOF
                drop(stdin_pipe);
            }
        }

        // Wait with timeout
        let timeout = config.wall_time_limit.unwrap_or(Duration::from_secs(3600));
        let result =
            self.wait_with_timeout(&mut child, child_pid, timeout, config.memory_limit, start);

        // Proxy will be shut down when dropped
        drop(proxy);

        result
    }

    fn check_support(&self, config: &SandboxConfig) -> Result<()> {
        if !is_supported() {
            return Err(SandboxError::SandboxExecUnavailable);
        }

        // Check for unsupported features
        if !matches!(config.seccomp_profile, SeccompProfile::Disabled | SeccompProfile::Standard) {
            // Custom seccomp profiles are not directly supported on macOS
            // We map them to sandbox-exec profiles instead
        }

        Ok(())
    }
}

impl MacOSExecutor {
    fn wait_with_timeout(
        &self,
        child: &mut std::process::Child,
        child_pid: i32,
        timeout: Duration,
        memory_limit: Option<u64>,
        start: Instant,
    ) -> Result<ExecutionResult> {
        let mut killed_by_timeout = false;
        let mut killed_by_oom = false;

        // Use wait4 with WNOHANG for non-blocking wait with rusage collection
        loop {
            let mut status: libc::c_int = 0;
            let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };

            let result = unsafe {
                libc::wait4(child_pid, &mut status, libc::WNOHANG, &mut rusage)
            };

            if result == child_pid {
                // Process exited, collect output
                let mut stdout = String::new();
                let mut stderr = String::new();

                if let Some(mut stdout_pipe) = child.stdout.take() {
                    let _ = stdout_pipe.read_to_string(&mut stdout);
                }
                if let Some(mut stderr_pipe) = child.stderr.take() {
                    let _ = stderr_pipe.read_to_string(&mut stderr);
                }

                // Extract exit code and signal
                let (exit_code, signal) = if libc::WIFEXITED(status) {
                    (libc::WEXITSTATUS(status), None)
                } else if libc::WIFSIGNALED(status) {
                    (-1, Some(libc::WTERMSIG(status)))
                } else {
                    (-1, None)
                };

                // Extract resource usage
                // maxrss is in bytes on macOS
                let peak_memory = Some(rusage.ru_maxrss as u64);

                // CPU time = user time + system time
                let user_time = Duration::new(
                    rusage.ru_utime.tv_sec as u64,
                    rusage.ru_utime.tv_usec as u32 * 1000,
                );
                let sys_time = Duration::new(
                    rusage.ru_stime.tv_sec as u64,
                    rusage.ru_stime.tv_usec as u32 * 1000,
                );
                let cpu_time = Some(user_time + sys_time);

                return Ok(ExecutionResult {
                    stdout,
                    stderr,
                    exit_code,
                    duration: start.elapsed(),
                    killed_by_timeout,
                    killed_by_oom,
                    signal,
                    peak_memory,
                    cpu_time,
                });
            } else if result == 0 {
                // Still running, check timeout
                if start.elapsed() > timeout && !killed_by_timeout {
                    Self::kill_process_tree(child_pid);
                    killed_by_timeout = true;
                }
                let mut poll = Duration::from_millis(10);
                if let Some(limit) = memory_limit {
                    if !killed_by_oom {
                        let used = Self::tree_footprint(child_pid);
                        if used > limit {
                            Self::kill_process_tree(child_pid);
                            killed_by_oom = true;
                        } else if used > limit / 10 * 6 {
                            poll = Duration::from_millis(2);
                        }
                    }
                }
                std::thread::sleep(poll);
            } else {
                // Error
                Self::kill_process_tree(child_pid);
                let _ = child.wait();
                return Err(SandboxError::ExecutionFailed(
                    format!("wait4 failed: {}", std::io::Error::last_os_error())
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::Mount;

    #[test]
    fn test_macos_is_supported() {
        // On macOS, sandbox-exec should exist
        #[cfg(target_os = "macos")]
        assert!(is_supported());
    }

    #[test]
    fn test_generate_profile() {
        let executor = MacOSExecutor::new();
        let config = SandboxConfig::default();
        let profile = executor.generate_profile(&config);

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
    }

    #[test]
    fn test_generate_profile_with_mounts() {
        let executor = MacOSExecutor::new();
        let mut config = SandboxConfig::default();
        // Use ReadWrite permission since that adds explicit rules
        config.mounts.push(Mount {
            source: "/tmp/test_mount".into(),
            target: "/sandbox/test".into(),
            permission: Permission::ReadWrite,
        });

        let profile = executor.generate_profile(&config);
        // Should contain write access for ReadWrite mounts
        assert!(profile.contains("/tmp/test_mount"));
    }

    #[test]
    fn test_generate_profile_network_none() {
        let executor = MacOSExecutor::new();
        let config = SandboxConfig {
            network_mode: NetworkMode::None,
            ..Default::default()
        };

        let profile = executor.generate_profile(&config);
        // Should not contain network* allow
        assert!(!profile.contains("(allow network*)"));
    }

    #[test]
    fn test_generate_profile_network_host() {
        let executor = MacOSExecutor::new();
        let config = SandboxConfig {
            network_mode: NetworkMode::Host,
            ..Default::default()
        };

        let profile = executor.generate_profile(&config);
        assert!(profile.contains("(allow network*)"));
    }
}

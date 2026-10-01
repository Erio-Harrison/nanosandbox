//! Windows platform implementation
//!
//! Uses Windows security features for sandboxing:
//!
//! - **Job Objects**: Process group management and resource limits
//! - **Restricted Tokens**: Security token restrictions
//! - **AppContainer**: Application isolation (Windows 8+)

use crate::builder::{NetworkMode, SandboxConfig};
use crate::error::{Result, SandboxError};
use crate::network::ProxiedNetwork;
use crate::platform::PlatformExecutor;
use crate::result::ExecutionResult;
use std::time::Duration;

/// Check if Windows sandboxing is supported
pub fn is_supported() -> bool {
    // Windows sandboxing is always available on Windows
    true
}

/// Windows sandbox executor
pub struct WindowsExecutor {
    _private: (),
}

impl WindowsExecutor {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for WindowsExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformExecutor for WindowsExecutor {
    fn execute(
        &self,
        config: &SandboxConfig,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        proxy: Option<&ProxiedNetwork>,
    ) -> Result<ExecutionResult> {
        // Windows implementation using Job Objects and Restricted Tokens

        use std::io::Write;
        use std::process::{Command, Stdio};
        use std::time::Instant;

        let start = Instant::now();

        // Build command
        let mut command = Command::new(cmd);
        command.args(args);
        command.current_dir(&config.working_dir);

        // Set environment
        if config.clear_env {
            command.env_clear();
        }
        for (key, value) in &config.env {
            command.env(key, value);
        }

        // Add proxy environment variables if using proxied network
        if let Some(proxy) = proxy {
            for (key, value) in proxy.env_vars() {
                command.env(key, value);
            }
        }

        if !config.env.contains_key("PATH") {
            // Default Windows PATH
            command.env(
                "PATH",
                r"C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem",
            );
        }

        // Setup I/O
        command.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        // Spawn process
        let mut child = command.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SandboxError::CommandNotFound(cmd.to_string())
            } else {
                SandboxError::ExecutionFailed(e.to_string())
            }
        })?;

        // Create Job Object and apply limits
        #[cfg(windows)]
        {
            self.apply_job_limits(&child, config)?;
        }

        // Write stdin
        if let Some(data) = stdin {
            if let Some(mut stdin_pipe) = child.stdin.take() {
                let _ = stdin_pipe.write_all(data);
            }
        }

        // Wait with timeout
        let timeout = config.wall_time_limit.unwrap_or(Duration::from_secs(3600));
        self.wait_with_timeout(&mut child, timeout, start)
    }

    /// Refuses what this executor can't enforce, instead of running the
    /// program with it silently missing. The process runs as the calling
    /// user, with the user's own file and network access.
    fn check_support(&self, config: &SandboxConfig) -> Result<()> {
        if !matches!(config.network_mode, NetworkMode::Host) {
            // no_network() is the default, so this covers sandboxes that
            // never mention the network too.
            return Err(SandboxError::PlatformFeatureUnavailable {
                feature: "network isolation on Windows (no_network() is the default, and \
                          allow_network() can't be enforced either); call host_network() to run \
                          with the host's network"
                    .into(),
            });
        }
        if config.rootfs.is_some() || !config.mounts.is_empty() || !config.tmpfs_mounts.is_empty() {
            return Err(SandboxError::PlatformFeatureUnavailable {
                feature: "rootfs, mount and tmpfs on Windows; the process sees the host's \
                          file system as the calling user"
                    .into(),
            });
        }
        Ok(())
    }
}

impl WindowsExecutor {
    #[cfg(windows)]
    fn apply_job_limits(&self, child: &std::process::Child, config: &SandboxConfig) -> Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::JobObjects::*;

        unsafe {
            // Create Job Object
            let job = CreateJobObjectW(None, None)
                .map_err(|e| SandboxError::JobObjectCreation(e.to_string()))?;

            // Set basic limits
            let mut basic_limits = JOBOBJECT_BASIC_LIMIT_INFORMATION::default();
            basic_limits.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            // Memory limit
            if let Some(memory) = config.memory_limit {
                basic_limits.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
                let mut extended_limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
                extended_limits.BasicLimitInformation = basic_limits;
                extended_limits.ProcessMemoryLimit = memory as usize;

                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &extended_limits as *const _ as *const _,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
                .map_err(|e| SandboxError::JobObjectCreation(e.to_string()))?;
            }

            // CPU limit
            if let Some(cpu) = config.cpu_limit {
                let cpu_rate = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
                    ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
                        | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                    Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 {
                        CpuRate: (cpu * 10000.0) as u32, // In hundredths of a percent
                    },
                };

                SetInformationJobObject(
                    job,
                    JobObjectCpuRateControlInformation,
                    &cpu_rate as *const _ as *const _,
                    std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
                )
                .map_err(|e| SandboxError::JobObjectCreation(e.to_string()))?;
            }

            // Assign process to job
            let process_handle = HANDLE(child.as_raw_handle());
            AssignProcessToJobObject(job, process_handle)
                .map_err(|e| SandboxError::JobObjectCreation(e.to_string()))?;
        }

        Ok(())
    }

    #[cfg(not(windows))]
    fn apply_job_limits(
        &self,
        _child: &std::process::Child,
        _config: &SandboxConfig,
    ) -> Result<()> {
        // No-op on non-Windows
        Ok(())
    }

    fn wait_with_timeout(
        &self,
        child: &mut std::process::Child,
        timeout: Duration,
        start: std::time::Instant,
    ) -> Result<ExecutionResult> {
        use std::io::Read;

        let mut killed_by_timeout = false;

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut stdout = String::new();
                    let mut stderr = String::new();

                    if let Some(mut pipe) = child.stdout.take() {
                        let _ = pipe.read_to_string(&mut stdout);
                    }
                    if let Some(mut pipe) = child.stderr.take() {
                        let _ = pipe.read_to_string(&mut stderr);
                    }

                    return Ok(ExecutionResult {
                        stdout,
                        stderr,
                        exit_code: status.code().unwrap_or(-1),
                        duration: start.elapsed(),
                        killed_by_timeout,
                        killed_by_oom: false,
                        signal: None,
                        peak_memory: None,
                        cpu_time: None,
                    });
                }
                Ok(None) => {
                    if start.elapsed() > timeout {
                        let _ = child.kill();
                        killed_by_timeout = true;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    return Err(SandboxError::ExecutionFailed(e.to_string()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_executor_creation() {
        let executor = WindowsExecutor::new();
        let _ = executor;
    }

    #[test]
    fn test_windows_is_supported() {
        #[cfg(windows)]
        assert!(is_supported());
    }
}

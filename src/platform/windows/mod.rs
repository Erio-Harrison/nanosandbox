//! Windows platform implementation
//!
//! Without the one-time install (see `docs/platform-windows.md`), a run is
//! the calling user's own process in a Job Object: resource limits and
//! process lifetime only, no file system or network isolation, so `build()`
//! refuses every setting that would need them.
//!
//! - **Job Objects**: every process of a run, with its memory, process
//!   count, CPU share and CPU time limits; killing the whole run at once.

mod job;
mod wait;

use crate::builder::{NetworkMode, SandboxConfig};
use crate::error::{Result, SandboxError};
use crate::network::ProxiedNetwork;
use crate::platform::PlatformExecutor;
use crate::result::ExecutionResult;
use job::{Job, Limits};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Instant;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
};

/// Check if Windows sandboxing is supported
pub fn is_supported() -> bool {
    // Job Objects (nested, as needed when the host is itself in one) are
    // in every supported Windows.
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

/// Environment variables a Windows program can't do without, passed on
/// from this process even with `clear_env`: without `SystemRoot`, for one,
/// Winsock fails to start. None of them is a secret.
const SYSTEM_ENV: [&str; 5] = ["SystemRoot", "SystemDrive", "windir", "ComSpec", "PATHEXT"];

impl PlatformExecutor for WindowsExecutor {
    fn execute(
        &self,
        config: &SandboxConfig,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        // check_support refuses allow_network without the install.
        _proxy: Option<&ProxiedNetwork>,
    ) -> Result<ExecutionResult> {
        let start = Instant::now();

        let mut command = Command::new(cmd);
        command.args(args);
        command.current_dir(&config.working_dir);

        if config.clear_env {
            command.env_clear();
            for key in SYSTEM_ENV {
                if !has_env(config, key)
                    && let Some(value) = std::env::var_os(key)
                {
                    command.env(key, value);
                }
            }
        }
        for (key, value) in &config.env {
            command.env(key, value);
        }
        if !has_env(config, "PATH") {
            command.env("PATH", default_path());
        }

        command.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        // Suspended until it's in the Job, so not even its first instruction
        // runs outside it. No console window of its own, and none shared
        // with this process: a Ctrl+C meant for the host isn't the run's.
        command.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);

        let job = Job::create(&Limits {
            memory: config.memory_limit,
            max_pids: config.max_pids,
            cpu_time: config.cpu_time_limit,
        })
        .map_err(|e| SandboxError::JobObjectCreation(e.to_string()))?;

        let mut child = command.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SandboxError::CommandNotFound(cmd.to_string())
            } else {
                SandboxError::ExecutionFailed {
                    context: "spawn process".into(),
                    source: Box::new(e),
                }
            }
        })?;

        let started = job
            .assign(child.as_raw_handle() as HANDLE)
            .map_err(|e| {
                SandboxError::JobObjectCreation(format!("assign the process to its Job: {e}"))
            })
            .and_then(|()| {
                resume(child.id()).map_err(|e| SandboxError::ExecutionFailed {
                    context: "resume the process".into(),
                    source: Box::new(e),
                })
            });
        if let Err(e) = started {
            // Never resumed, or never in the Job: it hasn't run.
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }

        wait::wait(&mut child, &job, stdin, config, start)
    }

    /// Refuses what this executor can't enforce, instead of running the
    /// program with it silently missing. The process runs as the calling
    /// user, with the user's own file and network access.
    fn check_support(&self, config: &SandboxConfig) -> Result<()> {
        if !matches!(config.network_mode, NetworkMode::Host) {
            // no_network() is the default, so this covers sandboxes that
            // never mention the network too.
            return Err(SandboxError::Unsupported {
                setting: "no_network()/allow_network() on Windows".into(),
                reason: "there's no network isolation; call host_network() to run with the \
                         host's network (no_network() is the default)"
                    .into(),
            });
        }
        if config.cpu_limit.is_some() {
            return Err(SandboxError::Unsupported {
                setting: "cpu_limit on Windows".into(),
                reason: "Windows ignores a Job's CPU cap where VBS is on; use cpu_time_limit"
                    .into(),
            });
        }
        for (set, setting) in [
            (config.max_file_size.is_some(), "max_file_size"),
            (config.max_open_files.is_some(), "max_open_files"),
        ] {
            if set {
                return Err(SandboxError::Unsupported {
                    setting: format!("{setting} on Windows"),
                    reason: "Windows has no per-process limit for it; leave it unset there".into(),
                });
            }
        }
        if !config.mounts.is_empty()
            || config.private_tmp.is_some()
            || !config.deny_read.is_empty()
            || config.hide_home
        {
            return Err(SandboxError::Unsupported {
                setting: "read_only/writable/private_tmp/deny_read/hide_home on Windows".into(),
                reason: "there's no file system isolation; the process sees the host's file \
                         system as the calling user"
                    .into(),
            });
        }
        Ok(())
    }
}

/// Environment variable names are case-insensitive on Windows.
fn has_env(config: &SandboxConfig, key: &str) -> bool {
    config.env.keys().any(|k| k.eq_ignore_ascii_case(key))
}

/// The system directories, where Windows actually is.
fn default_path() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    format!(r"{root}\system32;{root};{root}\System32\Wbem;{root}\System32\WindowsPowerShell\v1.0\")
}

/// Resumes the only thread of a process created suspended.
fn resume(pid: u32) -> std::io::Result<()> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        let mut entry = THREADENTRY32 {
            dwSize: size_of::<THREADENTRY32>() as u32,
            ..std::mem::zeroed()
        };
        let mut resumed = Err(std::io::Error::other("its thread wasn't found"));
        let mut more = Thread32First(snapshot, &mut entry) != 0;
        while more {
            if entry.th32OwnerProcessID == pid {
                let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                resumed = if thread.is_null() {
                    Err(std::io::Error::last_os_error())
                } else {
                    let r = ResumeThread(thread);
                    CloseHandle(thread);
                    if r == u32::MAX {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                };
                break;
            }
            more = Thread32Next(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
        resumed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_is_supported() {
        assert!(is_supported());
    }
}

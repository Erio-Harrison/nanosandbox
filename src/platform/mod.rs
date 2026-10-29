//! Platform abstraction layer: Linux (namespaces, cgroups v2, seccomp, Landlock), macOS
//! (sandbox-exec), Windows (Job Objects, resource limits only).

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(unix)]
pub(crate) mod checks;
pub(crate) mod output;
#[cfg(unix)]
pub(crate) mod private_tmp;
#[cfg(unix)]
#[cfg(unix)]
pub(crate) mod pty;
#[cfg(unix)]
pub(crate) mod read_rules;
#[cfg(unix)]
pub(crate) mod supervise;

use crate::builder::SandboxConfig;
use crate::error::Result;
use crate::network::ProxiedNetwork;
use crate::result::ExecutionResult;
use std::sync::Arc;

/// `cpu_time_limit` as RLIMIT_CPU whole seconds, rounded up and at least 1 (0 would mean no limit).
#[cfg(unix)]
pub(crate) fn rlimit_cpu_secs(limit: std::time::Duration) -> u64 {
    (limit.as_secs() + u64::from(limit.subsec_nanos() > 0)).max(1)
}

/// A pipe whose ends no concurrently started program inherits.
#[cfg(target_os = "linux")]
pub(crate) fn cloexec_pipe(
    what: &str,
) -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(|e| {
        crate::error::SandboxError::Internal {
            context: format!("create {what} pipe"),
            source: Box::new(e),
        }
    })
}

#[cfg(target_os = "macos")]
pub(crate) use macos::cloexec_pipe;

/// Platform-specific sandbox executor.
pub trait PlatformExecutor: Send + Sync {
    /// Starts a command on its own supervisor thread (see `supervise.rs`) and hands back its
    /// I/O ends. `proxy` is the sandbox's running proxy when `network_mode` is `Proxied`,
    /// shared by every run.
    #[cfg(unix)]
    fn launch(
        &self,
        config: Arc<SandboxConfig>,
        cmd: &str,
        args: &[&str],
        io: supervise::Io,
        proxy: Option<Arc<ProxiedNetwork>>,
    ) -> Result<supervise::Launched>;

    /// `run()`: the command with `stdin` fed to it and both streams collected (up to
    /// `max_output` each), waited for.
    #[cfg(unix)]
    fn execute(
        &self,
        config: &Arc<SandboxConfig>,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        proxy: Option<&Arc<ProxiedNetwork>>,
    ) -> Result<ExecutionResult> {
        let io = supervise::Io {
            stdin: stdin.is_some(),
            pty: None,
        };
        let launched = self.launch(Arc::clone(config), cmd, args, io, proxy.cloned())?;
        supervise::collect(launched, stdin, config.max_output)
    }

    #[cfg(not(unix))]
    fn execute(
        &self,
        config: &Arc<SandboxConfig>,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        proxy: Option<&Arc<ProxiedNetwork>>,
    ) -> Result<ExecutionResult>;

    /// Check that the platform supports every requested feature.
    fn check_support(&self, config: &SandboxConfig) -> Result<()>;
}

/// Get the executor for the current platform.
pub fn get_executor() -> Box<dyn PlatformExecutor> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxExecutor::new())
    }

    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOSExecutor::new())
    }

    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsExecutor::new())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        compile_error!("Unsupported platform")
    }
}

/// Whether the current platform supports sandboxing.
pub fn is_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::is_supported()
    }

    #[cfg(target_os = "macos")]
    {
        macos::is_supported()
    }

    #[cfg(target_os = "windows")]
    {
        windows::is_supported()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        false
    }
}

/// Get the current platform name
pub fn name() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "linux"
    }

    #[cfg(target_os = "macos")]
    {
        "macos"
    }

    #[cfg(target_os = "windows")]
    {
        "windows"
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_is_supported() {
        assert!(is_supported());
    }

    #[test]
    fn test_platform_name() {
        let name = name();
        assert!(!name.is_empty());
        #[cfg(target_os = "linux")]
        assert_eq!(name, "linux");
        #[cfg(target_os = "macos")]
        assert_eq!(name, "macos");
        #[cfg(target_os = "windows")]
        assert_eq!(name, "windows");
    }

    #[test]
    fn test_get_executor() {
        let executor = get_executor();
        let _ = executor;
    }

    #[test]
    #[cfg(unix)]
    fn rlimit_cpu_secs_rounds_up_and_is_never_zero() {
        use std::time::Duration;
        assert_eq!(rlimit_cpu_secs(Duration::ZERO), 1);
        assert_eq!(rlimit_cpu_secs(Duration::from_millis(500)), 1);
        assert_eq!(rlimit_cpu_secs(Duration::from_secs(2)), 2);
        assert_eq!(rlimit_cpu_secs(Duration::from_millis(2001)), 3);
    }
}

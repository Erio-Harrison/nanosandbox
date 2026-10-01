//! Platform abstraction layer
//!
//! This module provides a unified interface for sandbox implementation
//! across different operating systems.
//!
//! ## Supported Platforms
//!
//! | Platform | Technology | Status |
//! |----------|------------|--------|
//! | Linux | namespaces, cgroups v2, seccomp, Landlock | Full support |
//! | macOS | sandbox-exec, App Sandbox | Full support |
//! | Windows | Job Objects | Memory and CPU limits only |

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

use crate::builder::SandboxConfig;
use crate::error::Result;
use crate::network::ProxiedNetwork;
use crate::result::ExecutionResult;

/// `cpu_time_limit` as RLIMIT_CPU, which counts whole seconds: rounded up,
/// and never below 1. Truncating instead meant a sub-second limit became 0
/// and was skipped, i.e. no limit at all.
#[cfg(unix)]
pub(crate) fn rlimit_cpu_secs(limit: std::time::Duration) -> u64 {
    (limit.as_secs() + u64::from(limit.subsec_nanos() > 0)).max(1)
}

/// Platform-specific sandbox executor trait
///
/// This trait defines the interface that all platform implementations must provide.
/// Each platform (Linux, macOS, Windows) has its own implementation using
/// native sandboxing mechanisms.
pub trait PlatformExecutor: Send + Sync {
    /// Execute a command in the sandbox
    ///
    /// # Arguments
    /// * `config` - Sandbox configuration (limits, mounts, etc.)
    /// * `cmd` - Command to execute
    /// * `args` - Command arguments
    /// * `stdin` - Optional stdin data to pass to the process
    /// * `proxy` - The sandbox's proxy, already running, when `network_mode` is
    ///   `Proxied`. Owned by the `Sandbox` and reused across every `run()` call
    ///   instead of being started and torn down per call.
    ///
    /// # Returns
    /// * `ExecutionResult` containing stdout, stderr, exit code, and resource usage
    fn execute(
        &self,
        config: &SandboxConfig,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        proxy: Option<&ProxiedNetwork>,
    ) -> Result<ExecutionResult>;

    /// Check if this platform supports all requested features
    ///
    /// This validates that the platform can implement all features
    /// specified in the configuration before attempting execution.
    fn check_support(&self, config: &SandboxConfig) -> Result<()>;
}

/// Get the platform-specific executor
///
/// Returns a boxed executor for the current platform. The executor implements
/// sandboxing using platform-native mechanisms.
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

/// Check if the current platform supports sandboxing
///
/// Returns true if the platform has the necessary capabilities for sandboxing.
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
        // Should return true on all supported platforms
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
        // Just verify we can get an executor
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

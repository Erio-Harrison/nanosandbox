//! Sandbox implementation
//!
//! The main Sandbox struct that provides the high-level API for running
//! sandboxed processes across different platforms.

use crate::builder::{NetworkMode, SandboxBuilder, SandboxConfig};
use crate::error::Result;
use crate::network::ProxiedNetwork;
use crate::platform::{PlatformExecutor, get_executor};
use crate::result::ExecutionResult;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static SANDBOX_COUNTER: AtomicU64 = AtomicU64::new(0);

fn generate_sandbox_id() -> String {
    let count = SANDBOX_COUNTER.fetch_add(1, Ordering::SeqCst);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{}-{}", timestamp, count)
}

/// Main sandbox struct
///
/// Provides a cross-platform API for running sandboxed processes.
/// The actual sandboxing mechanism is platform-specific:
///
/// - **Linux**: namespaces, cgroups v2, seccomp
/// - **macOS**: sandbox-exec (Seatbelt)
/// - **Windows**: Job Objects, Restricted Tokens
pub struct Sandbox {
    config: SandboxConfig,
    id: String,
    executor: Box<dyn PlatformExecutor>,
    /// Started once here and reused by every `run()` call instead of being
    /// spun up and torn down per call; dropped (and shut down) with the
    /// `Sandbox` itself.
    proxy: Option<ProxiedNetwork>,
}

impl Sandbox {
    /// Create a new SandboxBuilder
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use nanosandbox::{Sandbox, MB};
    ///
    /// let sandbox = Sandbox::builder()
    ///     .memory_limit(256 * MB)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder() -> SandboxBuilder {
        SandboxBuilder::new()
    }

    /// Create a sandbox from a builder
    pub(crate) fn from_builder(builder: SandboxBuilder) -> Result<Self> {
        let config = builder.into_config();
        let executor = get_executor();

        // Validate platform support for this configuration
        executor.check_support(&config)?;

        // Start the proxy once, after platform support is confirmed, so it is
        // not spun up only to be discarded by a check_support() failure.
        let proxy = match &config.network_mode {
            NetworkMode::Proxied { allowed_domains } => Some(ProxiedNetwork::setup(
                allowed_domains.clone(),
                config.allow_private_destinations,
            )?),
            _ => None,
        };

        Ok(Self {
            config,
            id: generate_sandbox_id(),
            executor,
            proxy,
        })
    }

    /// Run a command in the sandbox
    ///
    /// # Arguments
    ///
    /// * `cmd` - The command to execute
    /// * `args` - Command arguments
    ///
    /// # Returns
    ///
    /// An `ExecutionResult` containing stdout, stderr, exit code, and resource usage.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use nanosandbox::Sandbox;
    ///
    /// let sandbox = Sandbox::builder().build().unwrap();
    /// let result = sandbox.run("echo", &["hello", "world"]).unwrap();
    /// assert_eq!(result.stdout.trim(), "hello world");
    /// ```
    pub fn run(&self, cmd: &str, args: &[&str]) -> Result<ExecutionResult> {
        self.run_with_input(cmd, args, None)
    }

    /// Run a command with optional stdin input
    ///
    /// # Arguments
    ///
    /// * `cmd` - The command to execute
    /// * `args` - Command arguments
    /// * `stdin` - Optional data to pass to stdin
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use nanosandbox::Sandbox;
    ///
    /// let sandbox = Sandbox::builder().build().unwrap();
    /// let result = sandbox.run_with_input("cat", &[], Some(b"hello")).unwrap();
    /// assert_eq!(result.stdout.trim(), "hello");
    /// ```
    pub fn run_with_input(
        &self,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<ExecutionResult> {
        self.executor
            .execute(&self.config, cmd, args, stdin, self.proxy.as_ref())
    }

    /// Get the sandbox ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the platform name
    pub fn platform(&self) -> &'static str {
        crate::platform::name()
    }

    // ========== Preset configurations ==========
    //
    // Presets only use settings every platform with file system isolation
    // has, so they build the same on Linux and macOS, except for the CPU
    // share and process count macOS can't limit (see cpu_and_pids).

    /// Data analysis preset
    ///
    /// - Read-only input directory
    /// - Read-write output directory
    /// - Appropriate memory and CPU limits
    /// - No network (default)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use nanosandbox::Sandbox;
    ///
    /// let sandbox = Sandbox::data_analysis("/data/input", "/data/output")
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn data_analysis(
        input_dir: impl Into<PathBuf>,
        output_dir: impl Into<PathBuf>,
    ) -> SandboxBuilder {
        let input_dir: PathBuf = input_dir.into();
        let output_dir: PathBuf = output_dir.into();
        cpu_and_pids(Sandbox::builder(), 2.0, 100)
            .read_only(input_dir)
            .writable(output_dir.clone())
            .working_dir(output_dir)
            .memory_limit(2 * 1024 * 1024 * 1024) // 2GB
            .wall_time_limit(Duration::from_secs(300)) // 5 minutes
            .no_network()
    }

    /// Code judge preset (for OJ systems)
    ///
    /// - Strict limits
    /// - Minimal permissions: `code_dir` read-only, nothing else of the
    ///   home directory readable
    /// - No network
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use nanosandbox::Sandbox;
    ///
    /// let sandbox = Sandbox::code_judge("/submissions/123")
    ///     .cpu_time_limit(std::time::Duration::from_secs(2))
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn code_judge(code_dir: impl Into<PathBuf>) -> SandboxBuilder {
        let code_dir: PathBuf = code_dir.into();
        cpu_and_pids(Sandbox::builder(), 1.0, 10)
            .read_only(code_dir.clone())
            .hide_home()
            .private_tmp(64 * 1024 * 1024)
            .working_dir(code_dir)
            .memory_limit(256 * 1024 * 1024) // 256MB
            .wall_time_limit(Duration::from_secs(10))
            .cpu_time_limit(Duration::from_secs(5))
            .no_network()
    }

    /// AI Agent executor preset
    ///
    /// - Read-write workspace
    /// - Moderate limits
    /// - Network controlled by caller
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use nanosandbox::Sandbox;
    ///
    /// let sandbox = Sandbox::agent_executor("/agent/workspace")
    ///     .allow_network(&["api.openai.com"])
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn agent_executor(workspace: impl Into<PathBuf>) -> SandboxBuilder {
        let workspace: PathBuf = workspace.into();
        let home = workspace.to_string_lossy().into_owned();
        cpu_and_pids(Sandbox::builder(), 4.0, 256)
            .writable(workspace.clone())
            .private_tmp(512 * 1024 * 1024)
            .working_dir(workspace)
            .memory_limit(4 * 1024 * 1024 * 1024) // 4GB
            .wall_time_limit(Duration::from_secs(600)) // 10 minutes
            .env("HOME", home)
            .env("USER", "sandbox")
    }

    /// Interactive shell preset
    ///
    /// - For debugging
    /// - Relatively permissive
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use nanosandbox::Sandbox;
    ///
    /// let sandbox = Sandbox::interactive("/home/user/project")
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn interactive(workspace: impl Into<PathBuf>) -> SandboxBuilder {
        let workspace: PathBuf = workspace.into();
        let home = workspace.to_string_lossy().into_owned();
        cpu_and_pids(Sandbox::builder(), 4.0, 512)
            .writable(workspace.clone())
            .private_tmp(1024 * 1024 * 1024)
            .working_dir(workspace)
            .memory_limit(8 * 1024 * 1024 * 1024) // 8GB
            .env("TERM", "xterm-256color")
            .env("HOME", home)
            .env("USER", "sandbox")
            .env("SHELL", "/bin/bash")
    }
}

/// The presets' CPU share and process count, where they can be enforced:
/// macOS has neither, and refuses them rather than ignore them.
fn cpu_and_pids(builder: SandboxBuilder, cpus: f64, pids: u32) -> SandboxBuilder {
    if cfg!(target_os = "macos") {
        builder
    } else {
        builder.cpu_limit(cpus).max_pids(pids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_id_generation() {
        let id1 = generate_sandbox_id();
        let id2 = generate_sandbox_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_sandbox_builder() {
        let builder = Sandbox::builder().memory_limit(512 * 1024 * 1024);

        let config = builder.into_config();
        assert_eq!(config.memory_limit, Some(512 * 1024 * 1024));
    }

    #[test]
    fn test_presets() {
        // Just verify presets compile and return builders
        let _ = Sandbox::data_analysis("/in", "/out");
        let _ = Sandbox::code_judge("/code");
        let _ = Sandbox::agent_executor("/workspace");
        let _ = Sandbox::interactive("/home");
    }
}

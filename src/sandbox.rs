//! Sandbox implementation
//!
//! The main Sandbox struct that provides the high-level API for running
//! sandboxed processes across different platforms.

use crate::builder::{NetworkMode, Permission, SandboxBuilder, SandboxConfig, SeccompProfile};
use crate::error::Result;
use crate::network::ProxiedNetwork;
use crate::platform::{get_executor, PlatformExecutor};
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
    /// use nanosandbox::{Sandbox, Permission, MB};
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
            NetworkMode::Proxied { allowed_domains } => {
                Some(ProxiedNetwork::setup(allowed_domains.clone())?)
            }
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
        // working_dir must be a path that actually exists once the sandbox
        // starts. "/input"/"/output" are just SBPL write-rule targets on
        // macOS (no filesystem remapping happens there at all) and are only
        // made real on Linux by pivot_root, which itself only runs when a
        // rootfs is also configured -- neither of which this preset does.
        // The real, caller-supplied directory is the one path guaranteed to
        // exist either way.
        let output_dir: PathBuf = output_dir.into();
        Sandbox::builder()
            .mount(input_dir, "/input", Permission::ReadOnly)
            .mount(output_dir.clone(), "/output", Permission::ReadWrite)
            .tmpfs("/tmp", 256 * 1024 * 1024) // 256MB tmp
            .working_dir(output_dir)
            .memory_limit(2 * 1024 * 1024 * 1024) // 2GB
            .cpu_limit(2.0)
            .wall_time_limit(Duration::from_secs(300)) // 5 minutes
            .max_pids(100)
            .seccomp_profile(SeccompProfile::Standard)
            .no_network()
    }

    /// Code judge preset (for OJ systems)
    ///
    /// - Strict limits
    /// - Minimal permissions
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
        // See data_analysis() above: working_dir needs a path that's real
        // without any rootfs/pivot_root, so use the caller's own directory
        // instead of the "/workspace" alias.
        let code_dir: PathBuf = code_dir.into();
        Sandbox::builder()
            .mount(code_dir.clone(), "/workspace", Permission::ReadOnly)
            .tmpfs("/tmp", 64 * 1024 * 1024) // 64MB tmp
            .working_dir(code_dir)
            .memory_limit(256 * 1024 * 1024) // 256MB
            .cpu_limit(1.0)
            .wall_time_limit(Duration::from_secs(10))
            .cpu_time_limit(Duration::from_secs(5))
            .max_pids(10)
            .seccomp_profile(SeccompProfile::Strict)
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
        // See data_analysis() above: working_dir (and HOME, since it should
        // agree with where we actually chdir'd) needs a path that's real
        // without any rootfs/pivot_root, so use the caller's own directory
        // instead of the "/workspace" alias.
        let workspace: PathBuf = workspace.into();
        let home = workspace.to_string_lossy().into_owned();
        Sandbox::builder()
            .mount(workspace.clone(), "/workspace", Permission::ReadWrite)
            .tmpfs("/tmp", 512 * 1024 * 1024)
            .working_dir(workspace)
            .memory_limit(4 * 1024 * 1024 * 1024) // 4GB
            .cpu_limit(4.0)
            .wall_time_limit(Duration::from_secs(600)) // 10 minutes
            .max_pids(256)
            .seccomp_profile(SeccompProfile::Standard)
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
        // See data_analysis() above: working_dir (and HOME) needs a path
        // that's real without any rootfs/pivot_root, so use the caller's
        // own directory instead of the "/workspace" alias.
        let workspace: PathBuf = workspace.into();
        let home = workspace.to_string_lossy().into_owned();
        Sandbox::builder()
            .mount(workspace.clone(), "/workspace", Permission::ReadWrite)
            .tmpfs("/tmp", 1024 * 1024 * 1024) // 1GB tmp
            .working_dir(workspace)
            .memory_limit(8 * 1024 * 1024 * 1024) // 8GB
            .cpu_limit(4.0)
            .max_pids(512)
            .seccomp_profile(SeccompProfile::Permissive)
            .hostname("sandbox")
            .env("TERM", "xterm-256color")
            .env("HOME", home)
            .env("USER", "sandbox")
            .env("SHELL", "/bin/bash")
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
        let builder = Sandbox::builder()
            .memory_limit(512 * 1024 * 1024)
            .hostname("test");

        let config = builder.into_config();
        assert_eq!(config.memory_limit, Some(512 * 1024 * 1024));
        assert_eq!(config.hostname, "test");
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

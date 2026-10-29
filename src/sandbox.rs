//! Sandbox: the high-level API.

use crate::builder::{NetworkMode, SandboxBuilder, SandboxConfig};
use crate::error::Result;
use crate::network::ProxiedNetwork;
use crate::platform::{PlatformExecutor, get_executor};
use crate::result::ExecutionResult;
use std::path::PathBuf;
use std::sync::Arc;
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

/// Cross-platform sandbox: Linux namespaces/cgroups/seccomp, macOS sandbox-exec, Windows
/// Job Objects.
pub struct Sandbox {
    /// Shared with each run's supervisor thread.
    config: Arc<SandboxConfig>,
    id: String,
    executor: Box<dyn PlatformExecutor>,
    /// Started once and reused by every run; shut down once the `Sandbox` and its runs are gone.
    proxy: Option<Arc<ProxiedNetwork>>,
    /// Counts runs, so an audit start and its end can be tied together.
    runs: AtomicU64,
}

impl Sandbox {
    /// Create a new [`SandboxBuilder`].
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
        #[cfg_attr(not(unix), allow(unused_mut))] // pinned on Unix only
        let mut config = builder.into_config();
        let executor = get_executor();

        executor.check_support(&config)?;

        // Where the paths it names lead, fixed now: see `SandboxConfig::pin`.
        #[cfg(unix)]
        config.pin();

        // // After the support check, so a failure doesn't spin up a proxy for nothing.
        let proxy = match &config.network_mode {
            NetworkMode::Proxied { allowed_domains } => Some(Arc::new(ProxiedNetwork::setup(
                allowed_domains.clone(),
                config.allow_private_destinations,
            )?)),
            _ => None,
        };

        Ok(Self {
            config: Arc::new(config),
            id: generate_sandbox_id(),
            executor,
            proxy,
            runs: AtomicU64::new(0),
        })
    }

    /// Run `cmd` with `args`, returning output, exit code and resource usage.
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

    /// Run a command, passing `stdin` as its input.
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
        #[cfg(unix)]
        self.config.check_pinned()?;
        let run = self.runs.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = &self.config.audit {
            crate::audit::begin(hook, &self.id, run, &self.config, cmd, args, stdin)?;
        }
        let result = self
            .executor
            .execute(&self.config, cmd, args, stdin, self.proxy.as_ref());
        if let Some(hook) = &self.config.audit {
            crate::audit::end(hook, &self.id, run, &result);
        }
        result
    }

    /// Get the sandbox ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the platform name
    pub fn platform(&self) -> &'static str {
        crate::platform::name()
    }

    // // Presets use only settings every file-system-isolating platform has; macOS can't
    // // limit CPU share or process count (see cpu_and_pids).

    /// Data analysis preset: read-only input, writable output, no network.
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

    /// Code judge preset (OJ systems): strict limits, `code_dir` read-only, no other home
    /// directory access, no network.
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

    /// AI agent preset: writable workspace, moderate limits, network set by the caller.
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

    /// Interactive shell preset for debugging; relatively permissive.
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

/// CPU share and process count for the presets, where enforceable (not macOS; no CPU share
/// on Windows).
fn cpu_and_pids(builder: SandboxBuilder, cpus: f64, pids: u32) -> SandboxBuilder {
    if cfg!(target_os = "macos") {
        builder
    } else if cfg!(windows) {
        builder.max_pids(pids)
    } else {
        builder.cpu_limit(cpus).max_pids(pids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A relative path names the directory as of build. Calls `pin`, not `build`: as root,
    /// build() refuses a writable directory `nobody` can't write.
    #[test]
    #[cfg(unix)]
    fn test_relative_paths_are_made_absolute_at_build() {
        let mut config = Sandbox::builder()
            .working_dir(".")
            .writable(".")
            .deny_read("nope")
            .into_config();
        config.pin();
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(config.working_dir, cwd);
        assert!(
            config
                .mounts
                .iter()
                .all(|m| m.source == cwd && m.target == cwd)
        );
        assert_eq!(config.deny_read, [cwd.join("nope")]);
        assert!(!config.pinned.is_empty());
        assert!(config.pinned.iter().all(|(given, _)| given.is_absolute()));
    }

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
        let _ = Sandbox::data_analysis("/in", "/out");
        let _ = Sandbox::code_judge("/code");
        let _ = Sandbox::agent_executor("/workspace");
        let _ = Sandbox::interactive("/home");
    }
}

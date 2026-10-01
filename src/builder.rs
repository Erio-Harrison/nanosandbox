//! Sandbox builder implementation
//!
//! Provides a fluent API for configuring and building sandboxes.

use crate::error::{Result, SandboxError};
use crate::sandbox::Sandbox;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// File/directory mount permission
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Permission {
    ReadOnly,
    ReadWrite,
}

/// Network access mode
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum NetworkMode {
    /// No network access (default, most secure)
    #[default]
    None,
    /// Use host network (not recommended, breaks isolation)
    Host,
    /// Network access through proxy with domain whitelist
    Proxied { allowed_domains: Vec<String> },
}

/// Mount configuration
#[derive(Clone, Debug)]
pub struct Mount {
    pub source: PathBuf,
    pub target: PathBuf,
    pub permission: Permission,
}

/// Sandbox configuration built by the builder
#[derive(Clone, Debug)]
pub struct SandboxConfig {
    // Filesystem
    pub mounts: Vec<Mount>,
    pub tmpfs_mounts: Vec<(PathBuf, u64)>,
    pub working_dir: PathBuf,
    pub rootfs: Option<PathBuf>,

    // Resource limits
    pub memory_limit: Option<u64>,
    pub cpu_limit: Option<f64>,
    pub wall_time_limit: Option<Duration>,
    pub cpu_time_limit: Option<Duration>,
    pub max_pids: Option<u32>,
    pub max_file_size: Option<u64>,
    pub max_open_files: Option<u32>,

    // Network
    pub network_mode: NetworkMode,

    // Security
    /// Linux syscall filter, see [`SandboxBuilder::seccomp`].
    pub seccomp: bool,
    pub uid: Option<u32>,
    pub gid: Option<u32>,

    // Environment
    pub env: HashMap<String, String>,
    pub clear_env: bool,
    pub hostname: String,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mounts: Vec::new(),
            tmpfs_mounts: Vec::new(),
            working_dir: PathBuf::from("/"),
            rootfs: None,

            memory_limit: None,
            cpu_limit: None,
            wall_time_limit: None,
            cpu_time_limit: None,
            max_pids: None,
            max_file_size: None,
            max_open_files: None,

            network_mode: NetworkMode::None,
            seccomp: true,
            uid: None,
            gid: None,

            env: HashMap::new(),
            clear_env: true,
            hostname: "sandbox".into(),
        }
    }
}

/// Sandbox builder with fluent API
#[derive(Clone)]
pub struct SandboxBuilder {
    config: SandboxConfig,
}

impl Default for SandboxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxBuilder {
    /// Create a new SandboxBuilder with default settings
    pub fn new() -> Self {
        Self {
            config: SandboxConfig::default(),
        }
    }

    /// Get the current configuration (for internal use)
    pub(crate) fn into_config(self) -> SandboxConfig {
        self.config
    }

    // ========== Filesystem ==========

    /// Mount a file or directory into the sandbox
    ///
    /// On Linux without a [`rootfs`](Self::rootfs), `target` is a host path
    /// that must already exist: the mount covers it inside the sandbox only.
    pub fn mount(
        mut self,
        source: impl Into<PathBuf>,
        target: impl Into<PathBuf>,
        permission: Permission,
    ) -> Self {
        self.config.mounts.push(Mount {
            source: source.into(),
            target: target.into(),
            permission,
        });
        self
    }

    /// Mount a tmpfs (memory filesystem)
    ///
    /// On Linux without a [`rootfs`](Self::rootfs), `path` must already exist
    /// on the host, as with [`mount`](Self::mount).
    pub fn tmpfs(mut self, path: impl Into<PathBuf>, size_bytes: u64) -> Self {
        self.config.tmpfs_mounts.push((path.into(), size_bytes));
        self
    }

    /// Set the working directory inside the sandbox
    pub fn working_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.working_dir = path.into();
        self
    }

    /// Use a custom rootfs
    pub fn rootfs(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.rootfs = Some(path.into());
        self
    }

    // ========== Resource Limits ==========

    /// Set memory limit in bytes
    pub fn memory_limit(mut self, bytes: u64) -> Self {
        self.config.memory_limit = Some(bytes);
        self
    }

    /// Set CPU limit (0.0 - N.0, where N is number of CPU cores)
    pub fn cpu_limit(mut self, cpus: f64) -> Self {
        self.config.cpu_limit = Some(cpus);
        self
    }

    /// Set wall clock time limit (process will be killed after this duration)
    pub fn wall_time_limit(mut self, duration: Duration) -> Self {
        self.config.wall_time_limit = Some(duration);
        self
    }

    /// Set CPU time limit
    pub fn cpu_time_limit(mut self, duration: Duration) -> Self {
        self.config.cpu_time_limit = Some(duration);
        self
    }

    /// Set maximum number of processes/threads
    pub fn max_pids(mut self, n: u32) -> Self {
        self.config.max_pids = Some(n);
        self
    }

    /// Set maximum file size
    pub fn max_file_size(mut self, bytes: u64) -> Self {
        self.config.max_file_size = Some(bytes);
        self
    }

    /// Set maximum number of open files
    pub fn max_open_files(mut self, n: u32) -> Self {
        self.config.max_open_files = Some(n);
        self
    }

    // ========== Network ==========

    /// Disable network access (default)
    pub fn no_network(mut self) -> Self {
        self.config.network_mode = NetworkMode::None;
        self
    }

    /// Use host network (not recommended)
    pub fn host_network(mut self) -> Self {
        self.config.network_mode = NetworkMode::Host;
        self
    }

    /// Allow network access only to specified domains
    pub fn allow_network(mut self, domains: &[&str]) -> Self {
        self.config.network_mode = NetworkMode::Proxied {
            allowed_domains: domains.iter().map(|s| s.to_string()).collect(),
        };
        self
    }

    // ========== Security ==========

    /// Turn the Linux syscall filter on or off. On by default.
    ///
    /// It blocks creating namespaces, mounting, bpf, perf_event_open,
    /// userfaultfd, io_uring, the keyring, kernel modules and kexec: the
    /// usual way into a kernel exploit, and nothing ordinary programs need.
    /// Blocked calls fail with `EPERM`. Turn it off for a program that needs
    /// one of them, such as Chrome with its own sandbox enabled (or run that
    /// with `--no-sandbox`).
    ///
    /// Linux only. macOS's sandbox profile and Windows don't filter syscalls.
    pub fn seccomp(mut self, enabled: bool) -> Self {
        self.config.seccomp = enabled;
        self
    }

    /// Set UID inside the sandbox
    pub fn uid(mut self, uid: u32) -> Self {
        self.config.uid = Some(uid);
        self
    }

    /// Set GID inside the sandbox
    pub fn gid(mut self, gid: u32) -> Self {
        self.config.gid = Some(gid);
        self
    }

    // ========== Environment ==========

    /// Set an environment variable
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.env.insert(key.into(), value.into());
        self
    }

    /// Set multiple environment variables
    pub fn envs(mut self, envs: impl IntoIterator<Item = (String, String)>) -> Self {
        self.config.env.extend(envs);
        self
    }

    /// Whether to clear inherited environment variables (default: true)
    pub fn clear_env(mut self, clear: bool) -> Self {
        self.config.clear_env = clear;
        self
    }

    /// Set hostname inside the sandbox
    pub fn hostname(mut self, name: impl Into<String>) -> Self {
        self.config.hostname = name.into();
        self
    }

    // ========== Build ==========

    /// Build the sandbox
    pub fn build(self) -> Result<Sandbox> {
        self.validate()?;
        Sandbox::from_builder(self)
    }

    fn validate(&self) -> Result<()> {
        // Pre-check platform capabilities
        self.pre_check_platform()?;

        // Validate mount paths exist
        for mount in &self.config.mounts {
            if !mount.source.exists() {
                return Err(SandboxError::PathNotFound(mount.source.clone()));
            }
        }

        // Validate rootfs if specified
        if let Some(rootfs) = &self.config.rootfs {
            if !rootfs.exists() || !rootfs.is_dir() {
                return Err(SandboxError::PathNotFound(rootfs.clone()));
            }
        }

        Ok(())
    }

    /// Pre-check platform capabilities before building sandbox
    fn pre_check_platform(&self) -> Result<()> {
        // Linux: no check here. `LinuxExecutor::check_support()` (called right
        // after this, from `Sandbox::from_builder()`) does the real thing —
        // including, for resource limits, actually resolving and validating
        // the cgroup v2 subtree instead of just checking a path exists.
        // Duplicating a weaker check here previously let `build()` succeed on
        // configs `check_support()` would immediately reject.

        #[cfg(target_os = "macos")]
        {
            // Check sandbox-exec availability
            if !std::path::Path::new("/usr/bin/sandbox-exec").exists() {
                return Err(SandboxError::Config(
                    "sandbox-exec not found at /usr/bin/sandbox-exec".into(),
                ));
            }

            // Unlike Linux (where working_dir can be a path that only
            // exists inside the sandbox's own mount namespace, made real by
            // its own mount setup), sandbox-exec does no remapping -- it
            // chdirs straight to this real host path. Left unchecked, a bad
            // one surfaces at run() time as a chdir failure with the same
            // ErrorKind as a missing command, and was being misreported as
            // CommandNotFound(cmd) even though cmd exists (confirmed for
            // real).
            if !self.config.working_dir.is_dir() {
                return Err(SandboxError::PathNotFound(self.config.working_dir.clone()));
            }
        }

        // Windows: Job Objects are always available, no pre-check needed

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_default() {
        let builder = SandboxBuilder::new();
        let config = builder.config;
        assert!(config.mounts.is_empty());
        assert!(config.memory_limit.is_none());
        assert_eq!(config.max_pids, None);
        assert!(matches!(config.network_mode, NetworkMode::None));
    }

    #[test]
    fn test_builder_memory_limit() {
        let builder = SandboxBuilder::new().memory_limit(512 * 1024 * 1024);
        assert_eq!(builder.config.memory_limit, Some(512 * 1024 * 1024));
    }

    #[test]
    fn test_builder_env() {
        let builder = SandboxBuilder::new().env("FOO", "bar").env("BAZ", "qux");
        assert_eq!(builder.config.env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(builder.config.env.get("BAZ"), Some(&"qux".to_string()));
    }

    #[test]
    fn test_builder_tmpfs() {
        let builder = SandboxBuilder::new().tmpfs("/tmp", 64 * 1024 * 1024);
        assert_eq!(builder.config.tmpfs_mounts.len(), 1);
        assert_eq!(builder.config.tmpfs_mounts[0].1, 64 * 1024 * 1024);
    }

    #[test]
    fn test_builder_network_modes() {
        let builder = SandboxBuilder::new().no_network();
        assert!(matches!(builder.config.network_mode, NetworkMode::None));

        let builder = SandboxBuilder::new().host_network();
        assert!(matches!(builder.config.network_mode, NetworkMode::Host));

        let builder = SandboxBuilder::new().allow_network(&["example.com"]);
        assert!(matches!(
            builder.config.network_mode,
            NetworkMode::Proxied { .. }
        ));
    }

    #[test]
    fn test_seccomp() {
        assert!(SandboxBuilder::new().config.seccomp);
        assert!(!SandboxBuilder::new().seccomp(false).config.seccomp);
    }
}

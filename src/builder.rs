//! Sandbox builder implementation
//!
//! Provides a fluent API for configuring and building sandboxes.

use crate::error::{Result, SandboxError};
use crate::sandbox::Sandbox;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Read-only or read-write, for [`SandboxBuilder::bind`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    ReadOnly,
    ReadWrite,
}

/// Network access mode
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum NetworkMode {
    /// No network access (default, most secure)
    #[default]
    None,
    /// Use host network (not recommended, breaks isolation)
    Host,
    /// Network access through proxy with domain whitelist
    Proxied { allowed_domains: Vec<String> },
}

/// A host path made visible in the sandbox. [`SandboxBuilder::read_only`]
/// and [`SandboxBuilder::writable`] use the same path for both.
#[derive(Clone, Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // target: Linux's bind()
pub(crate) struct Mount {
    pub(crate) source: PathBuf,
    pub(crate) target: PathBuf,
    pub(crate) permission: Permission,
}

/// The default [`SandboxBuilder::private_tmp`] size.
pub const DEFAULT_PRIVATE_TMP_SIZE: u64 = 256 * 1024 * 1024;

/// Sandbox configuration built by the builder
#[derive(Clone, Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // the Linux-only settings
pub(crate) struct SandboxConfig {
    // Filesystem
    pub(crate) mounts: Vec<Mount>,
    /// Linux only: [`SandboxBuilder::tmpfs`].
    pub(crate) tmpfs_mounts: Vec<(PathBuf, u64)>,
    /// [`SandboxBuilder::private_tmp`]'s size.
    pub(crate) private_tmp: Option<u64>,
    pub(crate) working_dir: PathBuf,
    pub(crate) rootfs: Option<PathBuf>,
    /// [`SandboxBuilder::deny_read`].
    pub(crate) deny_read: Vec<PathBuf>,
    /// [`SandboxBuilder::hide_home`].
    pub(crate) hide_home: bool,

    // Resource limits
    pub(crate) memory_limit: Option<u64>,
    pub(crate) cpu_limit: Option<f64>,
    pub(crate) wall_time_limit: Option<Duration>,
    pub(crate) cpu_time_limit: Option<Duration>,
    pub(crate) max_pids: Option<u32>,
    pub(crate) max_file_size: Option<u64>,
    pub(crate) max_open_files: Option<u32>,

    // Network
    pub(crate) network_mode: NetworkMode,
    /// [`SandboxBuilder::allow_private_destinations`].
    pub(crate) allow_private_destinations: bool,

    // Security
    /// Linux syscall filter, see [`SandboxBuilder::seccomp`].
    pub(crate) seccomp: bool,
    pub(crate) uid: Option<u32>,
    pub(crate) gid: Option<u32>,

    // Environment
    pub(crate) env: HashMap<String, String>,
    pub(crate) clear_env: bool,
    pub(crate) hostname: String,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mounts: Vec::new(),
            tmpfs_mounts: Vec::new(),
            // Windows has no file system isolation to make it private with.
            private_tmp: (!cfg!(windows)).then_some(DEFAULT_PRIVATE_TMP_SIZE),
            working_dir: PathBuf::from("/"),
            rootfs: None,
            deny_read: Vec::new(),
            hide_home: false,

            memory_limit: None,
            cpu_limit: None,
            wall_time_limit: None,
            cpu_time_limit: None,
            max_pids: None,
            max_file_size: None,
            max_open_files: None,

            network_mode: NetworkMode::None,
            allow_private_destinations: false,
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
    //
    // A sandbox can read the system's files, but nothing it hasn't been
    // given can be written. These are the same on every platform that
    // isolates the file system (Linux and macOS); Windows refuses them.

    /// Let the sandbox read `path`, a host file or directory, at the same
    /// path.
    pub fn read_only(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.config.mounts.push(Mount {
            source: path.clone(),
            target: path,
            permission: Permission::ReadOnly,
        });
        self
    }

    /// Let the sandbox read and write `path`, a host file or directory, at
    /// the same path. Writes land on the host.
    pub fn writable(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.config.mounts.push(Mount {
            source: path.clone(),
            target: path,
            permission: Permission::ReadWrite,
        });
        self
    }

    /// Give each run its own temp directory, empty at the start, removed
    /// afterwards, and limited to `size_bytes`. On by default, at
    /// [`DEFAULT_PRIVATE_TMP_SIZE`]; not available on Windows.
    ///
    /// Programs find it through `$TMPDIR`. On Linux it's a tmpfs mounted at
    /// `/tmp`, so programs that use `/tmp` by name get it too. Where that
    /// can't be mounted (macOS, and Linux under Ubuntu's AppArmor userns
    /// restriction) it's a private directory instead, and `/tmp` by name is
    /// the host's. Going over the size fails writes on a tmpfs, and kills
    /// the program elsewhere (see `ExecutionResult::killed_by_tmp_limit`).
    pub fn private_tmp(mut self, size_bytes: u64) -> Self {
        self.config.private_tmp = Some(size_bytes);
        self
    }

    /// No [`private_tmp`](Self::private_tmp).
    pub fn no_private_tmp(mut self) -> Self {
        self.config.private_tmp = None;
        self
    }

    /// Keep the sandbox from reading `path` (a file, or a directory and
    /// everything in it), on top of the credentials it can't read by
    /// default: SSH and GPG keys, cloud and registry credentials, tokens,
    /// shell histories and browser profiles in the home directory.
    /// [`read_only`](Self::read_only) and [`writable`](Self::writable)
    /// inside it still apply.
    ///
    /// On Linux, file names stay visible, only their contents aren't.
    pub fn deny_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.deny_read.push(path.into());
        self
    }

    /// Keep the sandbox from reading anything in the home directory, except
    /// what [`read_only`](Self::read_only), [`writable`](Self::writable) or
    /// [`working_dir`](Self::working_dir) name. For untrusted code that
    /// needs no more than the system's tools; toolchains installed in the
    /// home directory (rustup, nvm, pyenv) then need `read_only` too.
    pub fn hide_home(mut self) -> Self {
        self.config.hide_home = true;
        self
    }

    /// The directory the program starts in. It grants no access by itself:
    /// use [`read_only`](Self::read_only) or [`writable`](Self::writable)
    /// for that.
    pub fn working_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.working_dir = path.into();
        self
    }

    /// Linux only: make `source` on the host visible at `target` in the
    /// sandbox. Without a [`rootfs`](Self::rootfs), `target` is a host path
    /// that must already exist, unless it's inside a tmpfs; the bind covers
    /// it inside the sandbox only.
    #[cfg(target_os = "linux")]
    pub fn bind(
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

    /// Linux only: mount an empty tmpfs (memory filesystem) of `size_bytes`
    /// at `path`, private to each run. For `/tmp`, use
    /// [`private_tmp`](Self::private_tmp).
    ///
    /// Without a [`rootfs`](Self::rootfs), `path` must already exist on the
    /// host. Needs mounting, which Ubuntu's AppArmor userns restriction
    /// denies.
    #[cfg(target_os = "linux")]
    pub fn tmpfs(mut self, path: impl Into<PathBuf>, size_bytes: u64) -> Self {
        self.config.tmpfs_mounts.push((path.into(), size_bytes));
        self
    }

    /// Linux only: run in `path` as the root file system instead of the
    /// host's.
    #[cfg(target_os = "linux")]
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

    /// With [`allow_network`](Self::allow_network): let the allowed
    /// domains lead to loopback, private (10/8, 172.16/12, 192.168/16),
    /// link-local (including cloud metadata at 169.254.169.254) and other
    /// non-public addresses, such as an internal API.
    ///
    /// Off by default: the proxy connects from the host's network, so a
    /// name resolving there would reach the host's own services and
    /// internal network, which the sandbox otherwise can't.
    pub fn allow_private_destinations(mut self) -> Self {
        self.config.allow_private_destinations = true;
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
    /// Linux only.
    #[cfg(target_os = "linux")]
    pub fn seccomp(mut self, enabled: bool) -> Self {
        self.config.seccomp = enabled;
        self
    }

    /// Linux only: the UID the program runs as inside the sandbox.
    #[cfg(target_os = "linux")]
    pub fn uid(mut self, uid: u32) -> Self {
        self.config.uid = Some(uid);
        self
    }

    /// Linux only: the GID the program runs as inside the sandbox.
    #[cfg(target_os = "linux")]
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

    /// Whether the program starts with an empty environment (the default)
    /// or this process's own, before [`env`](Self::env) is applied.
    pub fn clear_env(mut self, clear: bool) -> Self {
        self.config.clear_env = clear;
        self
    }

    /// Linux only: the hostname inside the sandbox.
    #[cfg(target_os = "linux")]
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

        if let Some((path, _)) = self
            .config
            .tmpfs_mounts
            .iter()
            .find(|(path, _)| path == Path::new("/tmp") || path == Path::new("/private/tmp"))
        {
            return Err(SandboxError::Config(format!(
                "tmpfs({}, ...): use private_tmp(size) for /tmp",
                path.display()
            )));
        }

        let c = &self.config;
        if c.allow_private_destinations && !matches!(c.network_mode, NetworkMode::Proxied { .. }) {
            return Err(SandboxError::Config(
                "allow_private_destinations() only applies with allow_network()".into(),
            ));
        }
        if let Some(cpus) = c.cpu_limit {
            // Linux's cpu.max takes at least 1ms per 100ms period.
            if !cpus.is_finite() || cpus < 0.01 {
                return Err(SandboxError::Config(format!(
                    "cpu_limit({cpus}): must be at least 0.01 (cores)"
                )));
            }
        }
        for (value, setting) in [
            (c.memory_limit, "memory_limit"),
            (c.max_pids.map(u64::from), "max_pids"),
            (c.max_open_files.map(u64::from), "max_open_files"),
        ] {
            if value == Some(0) {
                return Err(SandboxError::Config(format!(
                    "{setting}(0): nothing could run"
                )));
            }
        }
        if c.hostname.is_empty() || c.hostname.len() > 64 {
            return Err(SandboxError::Config(format!(
                "hostname {:?}: must be 1 to 64 bytes",
                c.hostname
            )));
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
    fn test_builder_private_tmp() {
        let default = SandboxBuilder::new().config.private_tmp;
        if cfg!(windows) {
            assert_eq!(default, None);
        } else {
            assert_eq!(default, Some(DEFAULT_PRIVATE_TMP_SIZE));
        }
        let builder = SandboxBuilder::new().private_tmp(64 * 1024 * 1024);
        assert_eq!(builder.config.private_tmp, Some(64 * 1024 * 1024));
        assert_eq!(
            SandboxBuilder::new().no_private_tmp().config.private_tmp,
            None
        );
    }

    #[test]
    fn test_read_only_and_writable_are_in_place() {
        let config = SandboxBuilder::new().read_only("/a").writable("/b").config;
        assert_eq!(config.mounts[0].source, config.mounts[0].target);
        assert_eq!(config.mounts[0].permission, Permission::ReadOnly);
        assert_eq!(config.mounts[1].source, config.mounts[1].target);
        assert_eq!(config.mounts[1].permission, Permission::ReadWrite);
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
    #[cfg(target_os = "linux")]
    fn test_seccomp() {
        assert!(SandboxBuilder::new().config.seccomp);
        assert!(!SandboxBuilder::new().seccomp(false).config.seccomp);
    }
}

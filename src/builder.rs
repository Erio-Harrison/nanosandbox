//! Sandbox builder.

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

/// The default [`SandboxBuilder::max_output`]: for stdout and stderr each.
pub const DEFAULT_MAX_OUTPUT: u64 = 16 * 1024 * 1024;

/// The default [`SandboxBuilder::private_tmp`] size.
pub const DEFAULT_PRIVATE_TMP_SIZE: u64 = 256 * 1024 * 1024;

/// Sandbox configuration built by the builder
#[derive(Clone, Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // the Linux-only settings
pub(crate) struct SandboxConfig {
    pub(crate) mounts: Vec<Mount>,
    /// Linux only: [`SandboxBuilder::tmpfs`].
    pub(crate) tmpfs_mounts: Vec<(PathBuf, u64)>,
    /// [`SandboxBuilder::private_tmp`]'s size.
    pub(crate) private_tmp: Option<u64>,
    /// macOS: whether the system temp directories are writable. See
    /// [`SandboxBuilder::shared_tmp`].
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) shared_tmp: bool,
    pub(crate) working_dir: PathBuf,
    pub(crate) rootfs: Option<PathBuf>,
    /// [`SandboxBuilder::deny_read`].
    pub(crate) deny_read: Vec<PathBuf>,
    /// [`SandboxBuilder::hide_home`].
    pub(crate) hide_home: bool,
    /// [`SandboxBuilder::hide_home_except_toolchains`].
    pub(crate) expose_toolchains: bool,
    /// Other names of denied files, found at build (`read_rules::linked_secrets`).
    pub(crate) linked_secrets: Vec<PathBuf>,
    /// [`SandboxBuilder::report_denials`].
    pub(crate) report_denials: bool,
    /// macOS: the unified-log stream behind `report_denials`, started by `Sandbox::new`.
    #[cfg(target_os = "macos")]
    pub(crate) denial_log: Option<std::sync::Arc<crate::platform::macos::denials::DenialLog>>,

    pub(crate) memory_limit: Option<u64>,
    pub(crate) cpu_limit: Option<f64>,
    pub(crate) wall_time_limit: Option<Duration>,
    pub(crate) cpu_time_limit: Option<Duration>,
    pub(crate) max_pids: Option<u32>,
    pub(crate) max_file_size: Option<u64>,
    pub(crate) max_open_files: Option<u32>,
    /// [`SandboxBuilder::max_output`], per stream.
    pub(crate) max_output: u64,

    pub(crate) network_mode: NetworkMode,
    /// [`SandboxBuilder::allow_private_destinations`].
    pub(crate) allow_private_destinations: bool,
    /// [`SandboxBuilder::deny_network`] entries with their reasons.
    pub(crate) denied_destinations: Vec<(String, Option<String>)>,
    /// [`SandboxBuilder::require_host_match`].
    pub(crate) require_host_match: bool,
    /// macOS: [`SandboxBuilder::allow_trustd`].
    pub(crate) allow_trustd: bool,

    /// Linux syscall filter, see [`SandboxBuilder::seccomp`].
    pub(crate) seccomp: bool,
    pub(crate) uid: Option<u32>,
    pub(crate) host_uid: Option<u32>,
    pub(crate) host_gid: Option<u32>,
    pub(crate) gid: Option<u32>,

    pub(crate) env: HashMap<String, String>,
    pub(crate) clear_env: bool,
    pub(crate) hostname: String,

    /// [`SandboxBuilder::audit`].
    pub(crate) audit: Option<crate::audit::AuditHook>,

    /// Paths the configuration names, with where each resolved when built. See [`SandboxConfig::pin`].
    pub(crate) pinned: Vec<(PathBuf, PathBuf)>,
}

impl SandboxConfig {
    /// Resolves configured paths through symlinks once at build; runs use these, and
    /// [`check_pinned`] refuses a run if one has since moved. Otherwise a command could swap the
    /// writable directory (or a parent) for a symlink and have the next run grant its target.
    ///
    /// [`check_pinned`]: SandboxConfig::check_pinned
    #[cfg(unix)]
    pub(crate) fn pin(&mut self) {
        // // Absolute now, so a later chdir by the host can't change which directory it names.
        if let Ok(cwd) = std::env::current_dir() {
            let absolute = |p: &mut PathBuf| {
                if p.is_relative() {
                    *p = cwd.join(&*p);
                }
            };
            for m in &mut self.mounts {
                if m.source == m.target {
                    absolute(&mut m.source);
                    m.target = m.source.clone();
                }
            }
            absolute(&mut self.working_dir);
            for p in &mut self.deny_read {
                absolute(p);
            }
        }
        let named = self
            .mounts
            .iter()
            .filter(|m| m.source == m.target)
            .map(|m| m.target.clone())
            .chain(std::iter::once(self.working_dir.clone()))
            .chain(self.deny_read.iter().cloned());
        let mut pinned: Vec<(PathBuf, PathBuf)> = Vec::new();
        for path in named {
            if pinned.iter().all(|(given, _)| *given != path)
                && let Ok(real) = path.canonicalize()
            {
                pinned.push((path, real));
            }
        }
        self.pinned = pinned;
    }

    /// Where `path` led when the sandbox was built, if it was named then.
    #[cfg_attr(not(unix), allow(dead_code))] // file rules are Unix only so far
    pub(crate) fn pinned_path(&self, path: &Path) -> Option<&Path> {
        self.pinned
            .iter()
            .find(|(given, _)| given == path)
            .map(|(_, real)| real.as_path())
    }

    /// Refuses a run if a named path no longer leads where it did: it, or a
    /// directory above it, was replaced, which a command may have done.
    #[cfg(unix)]
    pub(crate) fn check_pinned(&self) -> Result<()> {
        for (given, was) in &self.pinned {
            match given.canonicalize() {
                Ok(now) if now == *was => {}
                Ok(now) => {
                    return Err(SandboxError::Config {
                        context: format!(
                            "{} led to {} when the sandbox was built and now leads to {}: it, or a \
                             directory above it, was replaced. Not running; build the sandbox (or \
                             restart the server) again to use the new one",
                            given.display(),
                            was.display(),
                            now.display()
                        ),
                        source: None,
                    });
                }
                Err(e) => {
                    return Err(SandboxError::Config {
                        context: format!(
                            "{} is no longer there ({e}); not running",
                            given.display()
                        ),
                        source: None,
                    });
                }
            }
        }
        Ok(())
    }
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mounts: Vec::new(),
            tmpfs_mounts: Vec::new(),
            // Windows has no file system isolation to make it private with.
            private_tmp: (!cfg!(windows)).then_some(DEFAULT_PRIVATE_TMP_SIZE),
            shared_tmp: true,
            working_dir: PathBuf::from("/"),
            rootfs: None,
            deny_read: Vec::new(),
            hide_home: false,
            expose_toolchains: false,
            linked_secrets: Vec::new(),
            report_denials: false,
            #[cfg(target_os = "macos")]
            denial_log: None,

            memory_limit: None,
            cpu_limit: None,
            wall_time_limit: None,
            cpu_time_limit: None,
            max_pids: None,
            max_file_size: None,
            max_open_files: None,
            max_output: DEFAULT_MAX_OUTPUT,

            network_mode: NetworkMode::None,
            allow_private_destinations: false,
            denied_destinations: Vec::new(),
            require_host_match: false,
            allow_trustd: false,
            seccomp: true,
            uid: None,
            host_uid: None,
            host_gid: None,
            gid: None,

            env: HashMap::new(),
            clear_env: true,
            hostname: "sandbox".into(),
            audit: None,
            pinned: Vec::new(),
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

    /// Let the sandbox read `path` at the same path.
    ///
    /// Inside a [`writable`](Self::writable) path it removes write access: the path and its
    /// parents up to the writable one can't be changed, replaced or moved. On Linux this is a
    /// read-only mount, so `build()` refuses it where mounting isn't possible (AppArmor
    /// `unprivileged_userns`).
    pub fn read_only(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.config.mounts.push(Mount {
            source: path.clone(),
            target: path,
            permission: Permission::ReadOnly,
        });
        self
    }

    /// Let the sandbox read and write `path` at the same path. Writes land on the host.
    pub fn writable(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.config.mounts.push(Mount {
            source: path.clone(),
            target: path,
            permission: Permission::ReadWrite,
        });
        self
    }

    /// Give each run its own empty temp directory, removed afterwards and limited to
    /// `size_bytes`. On by default at [`DEFAULT_PRIVATE_TMP_SIZE`]; not on Windows.
    ///
    /// Found via `$TMPDIR`. On Linux it's a tmpfs at `/tmp`; elsewhere (macOS, Linux under
    /// AppArmor's userns restriction) it's a private directory and `/tmp` by name is the host's.
    /// Exceeding the size fails writes on a tmpfs and kills the program elsewhere (see
    /// `ExecutionResult::killed_by_tmp_limit`).
    pub fn private_tmp(mut self, size_bytes: u64) -> Self {
        self.config.private_tmp = Some(size_bytes);
        self
    }

    /// No [`private_tmp`](Self::private_tmp).
    pub fn no_private_tmp(mut self) -> Self {
        self.config.private_tmp = None;
        self
    }

    /// macOS only: whether the system temp directories (`/tmp`, `/private/tmp`,
    /// `/private/var/tmp`, `/private/var/folders`) stay writable. On by default.
    ///
    /// With it on, a program writing `/tmp` by name writes to the host's. `shared_tmp(false)`
    /// makes them read-only, leaving [`private_tmp`](Self::private_tmp) via `$TMPDIR` (which
    /// must be on).
    ///
    /// Breaks: anything writing `/tmp` by name, `mktemp -t`, and Apple's `xcrun` shims in
    /// `/usr/bin` (`clang`, `cc`, ...), which reset `$TMPDIR`; run the real binaries under
    /// `xcode-select -p` instead.
    #[cfg(target_os = "macos")]
    pub fn shared_tmp(mut self, shared: bool) -> Self {
        self.config.shared_tmp = shared;
        self
    }

    /// Hand an [`AuditEvent`](crate::audit::AuditEvent) to `sink` after each run; it holds no
    /// data from the run. See [`audit`](crate::audit).
    pub fn audit(mut self, sink: std::sync::Arc<dyn crate::audit::AuditSink>) -> Self {
        self.config.audit = Some(crate::audit::AuditHook(sink));
        self
    }

    /// Keep the sandbox from reading `path` (a file, or a directory and its contents), on top
    /// of the credentials hidden by default (SSH/GPG keys, cloud and registry credentials, shell
    /// histories, browser profiles). [`read_only`](Self::read_only) and
    /// [`writable`](Self::writable) inside it still apply. On Linux file names stay visible,
    /// only contents don't.
    pub fn deny_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.deny_read.push(path.into());
        self
    }

    /// Keep the sandbox from reading anything in the home directory except what
    /// [`read_only`](Self::read_only), [`writable`](Self::writable) or
    /// [`working_dir`](Self::working_dir) name. Toolchains in the home directory (rustup, nvm,
    /// pyenv) then need `read_only`.
    pub fn hide_home(mut self) -> Self {
        self.config.hide_home = true;
        self
    }

    /// Report the file accesses the sandbox refuses in `ExecutionResult::denied_paths`, so a
    /// caller can tell what a failing command wanted (and, say, ask its user whether to grant
    /// it with `read_only`). Off by default: on macOS it reads the unified log, which adds
    /// the log's delay (tens of milliseconds) to each run's end, and tracks the run's process
    /// tree to attribute each denial by pid; `build()` fails if the log isn't delivering. Not
    /// reported on Linux yet.
    pub fn report_denials(mut self) -> Self {
        self.config.report_denials = true;
        self
    }

    /// What the agent presets use: [`hide_home`](Self::hide_home) with the toolchains and
    /// caches in the home directory kept readable (`read_rules::toolchain_dirs`), and the
    /// variables they're found through set (`read_rules::toolchain_env`). An opinion about
    /// what a developer's machine looks like, so not part of the builder's public surface:
    /// a caller composing its own policy names the directories with `read_only`.
    pub(crate) fn hide_home_except_toolchains(mut self) -> Self {
        self.config.hide_home = true;
        self.config.expose_toolchains = true;
        self
    }

    /// The directory the program starts in. Grants no access by itself.
    pub fn working_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.working_dir = path.into();
        self
    }

    /// Linux only: make `source` visible at `target` in the sandbox. Without a
    /// [`rootfs`](Self::rootfs), `target` must already exist on the host unless inside a tmpfs;
    /// the bind applies inside the sandbox only.
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

    /// Linux only: mount an empty per-run tmpfs of `size_bytes` at `path`. For `/tmp` use
    /// [`private_tmp`](Self::private_tmp).
    ///
    /// Without a [`rootfs`](Self::rootfs), `path` must exist on the host. Needs mounting, which
    /// AppArmor's userns restriction denies.
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

    /// Keep at most `bytes` of stdout and of stderr (default [`DEFAULT_MAX_OUTPUT`], 16 MB).
    /// Past the limit output is read but dropped and `ExecutionResult::output_truncated` is set.
    pub fn max_output(mut self, bytes: u64) -> Self {
        self.config.max_output = bytes;
        self
    }

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

    /// Allow network access only to the listed destinations, through a local proxy. An entry
    /// is a host (`example.com`), `*.example.com` (it and its subdomains), or an IP address,
    /// with an optional `:port` (`api.example.com:443`); without one any port is allowed.
    /// Replaces an earlier list.
    pub fn allow_network(mut self, domains: &[&str]) -> Self {
        self.config.network_mode = NetworkMode::Proxied {
            allowed_domains: domains.iter().map(|s| s.to_string()).collect(),
        };
        self
    }

    /// With [`allow_network`](Self::allow_network): destinations refused even if an allow
    /// entry matches them, in the same syntax (`github.com:22`). Adds to earlier entries.
    pub fn deny_network(mut self, entries: &[&str]) -> Self {
        self.config
            .denied_destinations
            .extend(entries.iter().map(|e| (e.to_string(), None)));
        self
    }

    /// [`deny_network`](Self::deny_network) for one entry, with a reason the program is told
    /// when refused (`"SSH is blocked; use an https remote"`), and that the result records.
    pub fn deny_network_with_reason(mut self, entry: &str, reason: &str) -> Self {
        self.config
            .denied_destinations
            .push((entry.to_string(), Some(reason.to_string())));
        self
    }

    /// With [`allow_network`](Self::allow_network): cut an HTTPS tunnel whose TLS handshake
    /// names a host other than the one it was opened to (domain fronting through a shared
    /// CDN). Off by default. The proxy waits up to 5 s for the handshake to start, so a
    /// tunnel to a protocol where the server speaks first is delayed by that.
    pub fn require_host_match(mut self) -> Self {
        self.config.require_host_match = true;
        self
    }

    /// macOS, with [`allow_network`](Self::allow_network): let the program use the system's
    /// certificate-verification service (`trustd`). Off by default: trustd fetches a
    /// certificate's OCSP and issuer URLs on the program's behalf, outside the allowlist, so a
    /// certificate the program evaluates can carry data to any host. Without it, Security.framework
    /// verification fails for programs that use it directly (Go, Swift); the system's curl, and
    /// clients with their own certificate store (Python, Node, Rust, Java) are unaffected.
    /// No effect on other platforms.
    pub fn allow_trustd(mut self) -> Self {
        self.config.allow_trustd = true;
        self
    }

    /// With [`allow_network`](Self::allow_network): let allowed domains resolve to loopback,
    /// private, link-local (including cloud metadata at 169.254.169.254) and other non-public
    /// addresses.
    ///
    /// Off by default: the proxy connects from the host, so such names would reach the host's
    /// own services and internal network.
    pub fn allow_private_destinations(mut self) -> Self {
        self.config.allow_private_destinations = true;
        self
    }

    /// Turn the Linux syscall filter on or off. On by default.
    ///
    /// Blocks namespaces, mounting, bpf, perf_event_open, userfaultfd, io_uring, keyring, kernel
    /// modules and kexec with `EPERM`. Turn it off for programs that need one, e.g. Chrome with
    /// its own sandbox.
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

    /// Linux only, for a root caller: the host user the sandbox runs as instead of `nobody`
    /// (65534). Host file permission checks use this id, not [`uid`](Self::uid), and everything
    /// this user can reach on the host is reachable by the program. Set it to the owner of
    /// [`writable`](Self::writable) directories `nobody` can't write. 0 is refused, as is
    /// setting it when the caller isn't root.
    #[cfg(target_os = "linux")]
    pub fn host_uid(mut self, uid: u32) -> Self {
        self.config.host_uid = Some(uid);
        self
    }

    /// Linux only, for a root caller: the host group the sandbox runs as,
    /// instead of `nogroup` (65534). See [`host_uid`](Self::host_uid).
    #[cfg(target_os = "linux")]
    pub fn host_gid(mut self, gid: u32) -> Self {
        self.config.host_gid = Some(gid);
        self
    }

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

    /// Build the sandbox
    pub fn build(#[cfg_attr(not(unix), allow(unused_mut))] mut self) -> Result<Sandbox> {
        self.validate()?;
        // Toolchains kept readable in a hidden home are found through these, since `HOME` won't
        // be the real one; a value the caller set wins.
        #[cfg(unix)]
        if self.config.expose_toolchains
            && let Some(home) = crate::platform::read_rules::home_dir()
        {
            for (var, value) in crate::platform::read_rules::toolchain_env(&home) {
                self.config.env.entry(var).or_insert(value);
            }
        }
        Sandbox::from_builder(self)
    }

    fn validate(&self) -> Result<()> {
        self.pre_check_platform()?;

        for mount in &self.config.mounts {
            if !mount.source.exists() {
                return Err(SandboxError::PathNotFound(mount.source.clone()));
            }
        }
        // A deny that names nothing protects nothing: a typo (or a literal `~`) must not build.
        for path in &self.config.deny_read {
            if std::fs::symlink_metadata(path).is_err() {
                return Err(SandboxError::PathNotFound(path.clone()));
            }
        }
        for key in self.config.env.keys() {
            if key.is_empty() || key.contains(['=', '\0']) {
                return Err(SandboxError::Config {
                    context: format!("env key {key:?}: must be non-empty, without `=` or NUL"),
                    source: None,
                });
            }
        }
        if self.config.env.values().any(|v| v.contains('\0')) {
            return Err(SandboxError::Config {
                context: "env value contains NUL".into(),
                source: None,
            });
        }

        if let Some((path, _)) = self
            .config
            .tmpfs_mounts
            .iter()
            .find(|(path, _)| path == Path::new("/tmp") || path == Path::new("/private/tmp"))
        {
            return Err(SandboxError::Config {
                context: format!(
                    "tmpfs({}, ...): use private_tmp(size) for /tmp",
                    path.display()
                ),
                source: None,
            });
        }

        let c = &self.config;
        if let NetworkMode::Proxied { allowed_domains } = &c.network_mode {
            let rules = crate::network::ProxyRules {
                allowed: allowed_domains.clone(),
                denied: c.denied_destinations.clone(),
                ..Default::default()
            };
            if let Some((list, entry, why)) = rules.invalid_entry() {
                return Err(SandboxError::Config {
                    context: format!("{list} entry {entry:?}: {why}"),
                    source: None,
                });
            }
        } else {
            let set = [
                (c.allow_private_destinations, "allow_private_destinations()"),
                (!c.denied_destinations.is_empty(), "deny_network()"),
                (c.require_host_match, "require_host_match()"),
                (c.allow_trustd, "allow_trustd()"),
            ];
            if let Some((_, name)) = set.iter().find(|(on, _)| *on) {
                return Err(SandboxError::Config {
                    context: format!("{name} only applies with allow_network()"),
                    source: None,
                });
            }
        }
        if let Some(cpus) = c.cpu_limit {
            // Linux's cpu.max takes at least 1ms per 100ms period.
            if !cpus.is_finite() || cpus < 0.01 {
                return Err(SandboxError::Config {
                    context: format!("cpu_limit({cpus}): must be at least 0.01 (cores)"),
                    source: None,
                });
            }
        }
        for (value, setting) in [
            (c.memory_limit, "memory_limit"),
            (c.max_pids.map(u64::from), "max_pids"),
            (c.max_open_files.map(u64::from), "max_open_files"),
        ] {
            if value == Some(0) {
                return Err(SandboxError::Config {
                    context: format!("{setting}(0): nothing could run"),
                    source: None,
                });
            }
        }
        if c.hostname.is_empty() || c.hostname.len() > 64 {
            return Err(SandboxError::Config {
                context: format!("hostname {:?}: must be 1 to 64 bytes", c.hostname),
                source: None,
            });
        }

        if let Some(rootfs) = &self.config.rootfs
            && (!rootfs.exists() || !rootfs.is_dir())
        {
            return Err(SandboxError::PathNotFound(rootfs.clone()));
        }

        Ok(())
    }

    /// Pre-check platform capabilities before building sandbox
    fn pre_check_platform(&self) -> Result<()> {
        // // Linux: no check here; `check_support()` does it for real (including cgroup v2
        // // resolution), and a weaker duplicate let build() pass configs it then rejected.

        #[cfg(target_os = "macos")]
        {
            if !std::path::Path::new("/usr/bin/sandbox-exec").exists() {
                return Err(SandboxError::Config {
                    context: "sandbox-exec not found at /usr/bin/sandbox-exec".into(),
                    source: None,
                });
            }

            // // sandbox-exec chdirs straight to this host path; unchecked, a bad one surfaces at
            // // run() as a chdir failure misreported as CommandNotFound.
            if !self.config.working_dir.is_dir() {
                return Err(SandboxError::PathNotFound(self.config.working_dir.clone()));
            }
        }

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

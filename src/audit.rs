//! An audit trail: one structured event per run, handed to an
//! [`AuditSink`] the caller supplies with [`SandboxBuilder::audit`].
//!
//! An event says what ran, under which policy, and how it ended. It carries
//! no data from the run itself: not stdin, not stdout or stderr (only their
//! sizes), not environment values (only the names). Command and arguments
//! are recorded as given, so they should not hold secrets.
//!
//! Where the events go, and how they're kept tamper-evident, is the sink's
//! business: `nanosandbox-mcp --audit-log` writes a hash chain.
//!
//! [`SandboxBuilder::audit`]: crate::SandboxBuilder::audit

use crate::builder::{NetworkMode, Permission, SandboxConfig};
use crate::error::SandboxError;
use crate::result::ExecutionResult;
use serde::Serialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Receives one [`AuditEvent`] after each run, on the thread that ran it.
/// Runs may overlap, so `record` can be called from several threads at once.
/// It should return quickly and not panic: a panic is caught, and the run's
/// result is still returned, but that event is lost.
pub trait AuditSink: Send + Sync {
    fn record(&self, event: &AuditEvent);
}

/// What one run did. Serializes to JSON with integer fields only, so that
/// the same event always serializes to the same text.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct AuditEvent {
    /// When the run ended, in milliseconds since the Unix epoch.
    pub ts_ms: u64,
    pub sandbox_id: String,
    pub platform: &'static str,
    pub command: String,
    pub args: Vec<String>,
    /// Length of the input given on stdin; the input itself isn't kept.
    pub stdin_bytes: u64,
    pub policy: AuditPolicy,
    pub outcome: AuditOutcome,
}

/// The sandbox's configuration, as far as it bears on what the run could do.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct AuditPolicy {
    /// `none`, `proxied` or `host`.
    pub network: &'static str,
    pub allowed_domains: Vec<String>,
    pub allow_private_destinations: bool,
    /// Paths the sandbox may read, and may write; `source:target` where a
    /// bind puts one at another path.
    pub read_only: Vec<String>,
    pub writable: Vec<String>,
    pub deny_read: Vec<String>,
    pub hide_home: bool,
    pub working_dir: String,
    pub rootfs: Option<String>,
    pub private_tmp_bytes: Option<u64>,
    pub shared_tmp: bool,
    pub seccomp: bool,
    pub memory_limit: Option<u64>,
    /// CPUs, in thousandths.
    pub cpu_limit_millis: Option<u64>,
    pub wall_time_limit_ms: Option<u64>,
    pub cpu_time_limit_ms: Option<u64>,
    pub max_pids: Option<u32>,
    pub max_file_size: Option<u64>,
    pub max_open_files: Option<u32>,
    pub max_output: u64,
    pub clear_env: bool,
    /// Names only, never values.
    pub env_names: Vec<String>,
}

/// How the run ended.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditOutcome {
    /// The command ran and finished, however it finished.
    Completed {
        exit_code: i32,
        signal: Option<i32>,
        duration_ms: u64,
        timed_out: bool,
        out_of_memory: bool,
        tmp_limit_hit: bool,
        cpu_limit_hit: bool,
        output_truncated: bool,
        stdout_bytes: u64,
        stderr_bytes: u64,
        peak_memory: Option<u64>,
        cpu_time_ms: Option<u64>,
        /// Hosts the proxy refused.
        blocked_hosts: Vec<String>,
    },
    /// The command didn't run (not found, the sandbox couldn't be set up...).
    Failed { error: String },
}

/// Shared handle to a sink, kept in the configuration.
#[derive(Clone)]
pub(crate) struct AuditHook(pub(crate) Arc<dyn AuditSink>);

impl std::fmt::Debug for AuditHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditHook")
    }
}

impl AuditPolicy {
    pub(crate) fn from_config(config: &SandboxConfig) -> Self {
        let show = |source: &std::path::Path, target: &std::path::Path| {
            if source == target {
                source.display().to_string()
            } else {
                format!("{}:{}", source.display(), target.display())
            }
        };
        let mounts = |permission: Permission| -> Vec<String> {
            config
                .mounts
                .iter()
                .filter(|m| m.permission == permission)
                .map(|m| show(&m.source, &m.target))
                .collect()
        };
        let paths = |list: &[std::path::PathBuf]| -> Vec<String> {
            list.iter().map(|p| p.display().to_string()).collect()
        };
        let (network, allowed_domains) = match &config.network_mode {
            NetworkMode::None => ("none", Vec::new()),
            NetworkMode::Host => ("host", Vec::new()),
            NetworkMode::Proxied { allowed_domains } => ("proxied", allowed_domains.clone()),
        };
        let ms = |d: std::time::Duration| d.as_millis() as u64;
        let mut env_names: Vec<String> = config.env.keys().cloned().collect();
        env_names.sort();
        Self {
            network,
            allowed_domains,
            allow_private_destinations: config.allow_private_destinations,
            read_only: mounts(Permission::ReadOnly),
            writable: mounts(Permission::ReadWrite),
            deny_read: paths(&config.deny_read),
            hide_home: config.hide_home,
            working_dir: config.working_dir.display().to_string(),
            rootfs: config.rootfs.as_ref().map(|p| p.display().to_string()),
            private_tmp_bytes: config.private_tmp,
            shared_tmp: config.shared_tmp,
            seccomp: config.seccomp,
            memory_limit: config.memory_limit,
            cpu_limit_millis: config.cpu_limit.map(|c| (c * 1000.0).round() as u64),
            wall_time_limit_ms: config.wall_time_limit.map(ms),
            cpu_time_limit_ms: config.cpu_time_limit.map(ms),
            max_pids: config.max_pids,
            max_file_size: config.max_file_size,
            max_open_files: config.max_open_files,
            max_output: config.max_output,
            clear_env: config.clear_env,
            env_names,
        }
    }
}

/// Builds the event for a finished run and hands it to the sink.
pub(crate) fn record(
    hook: &AuditHook,
    sandbox_id: &str,
    config: &SandboxConfig,
    cmd: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    result: &Result<ExecutionResult, SandboxError>,
) {
    let outcome = match result {
        Ok(r) => AuditOutcome::Completed {
            exit_code: r.exit_code,
            signal: r.signal,
            duration_ms: r.duration.as_millis() as u64,
            timed_out: r.killed_by_timeout,
            out_of_memory: r.killed_by_oom,
            tmp_limit_hit: r.killed_by_tmp_limit,
            cpu_limit_hit: r.killed_by_cpu_limit,
            output_truncated: r.output_truncated,
            stdout_bytes: r.stdout.len() as u64,
            stderr_bytes: r.stderr.len() as u64,
            peak_memory: r.peak_memory,
            cpu_time_ms: r.cpu_time.map(|d| d.as_millis() as u64),
            blocked_hosts: r.blocked_hosts.clone(),
        },
        Err(e) => AuditOutcome::Failed {
            error: e.to_string(),
        },
    };
    let event = AuditEvent {
        ts_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64),
        sandbox_id: sandbox_id.to_string(),
        platform: crate::platform::name(),
        command: cmd.to_string(),
        args: args.iter().map(|a| a.to_string()).collect(),
        stdin_bytes: stdin.map_or(0, |s| s.len() as u64),
        policy: AuditPolicy::from_config(config),
        outcome,
    };
    // A sink that panics loses its event, not the caller's result.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook.0.record(&event)));
}

//! Execution result types.

use std::time::Duration;

/// Result of executing a command in the sandbox
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ExecutionResult {
    /// Standard output captured from the process
    pub stdout: String,

    /// Standard error captured from the process
    pub stderr: String,

    /// Exit code of the process (0 typically means success). When a signal
    /// killed it, `128 + signal` on every platform, as a shell reports it.
    pub exit_code: i32,

    /// Wall-clock duration of execution
    pub duration: Duration,

    /// Whether the process was killed due to timeout
    pub killed_by_timeout: bool,

    /// Whether the process was killed due to out-of-memory
    pub killed_by_oom: bool,

    /// Killed for exceeding `tmpfs("/tmp", size)`. Only where emulated with a private directory (macOS, Linux under AppArmor's userns restriction); a real tmpfs fails with ENOSPC.
    pub killed_by_tmp_limit: bool,

    /// Killed for exceeding `cpu_time_limit` summed across all processes (Linux cgroup, Windows Job Object), on top of per-process `RLIMIT_CPU` on Linux/macOS.
    pub killed_by_cpu_limit: bool,

    /// Signal that killed the process, if any
    pub signal: Option<i32>,

    /// Peak memory usage in bytes (if available)
    pub peak_memory: Option<u64>,

    /// CPU time consumed (if available)
    pub cpu_time: Option<Duration>,

    /// stdout or stderr exceeded `max_output`; the rest was dropped.
    pub output_truncated: bool,

    /// Whether the sandbox got its own `/proc`. False on Linux under AppArmor's `unprivileged_userns` restriction (see `docs/platform-linux.md`), which also skips the private hostname, or where mounting a fresh procfs failed (e.g. a container that masks parts of its `/proc`); the command then sees the host's.
    pub proc_isolated: bool,

    /// Hosts the `allow_network` proxy refused by policy, sorted, each once: a summary of
    /// [`network_refusals`](Self::network_refusals) without the connection failures.
    pub blocked_hosts: Vec<String>,

    /// Every destination the `allow_network` proxy didn't connect to this run, with why,
    /// sorted by host and port.
    pub network_refusals: Vec<NetworkRefusal>,
}

/// A destination the `allow_network` proxy didn't connect a run to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct NetworkRefusal {
    /// As the program asked for it, lowercased.
    pub host: String,
    pub port: u16,
    pub reason: RefusalReason,
    /// How many times the run asked for it.
    pub attempts: u32,
}

/// Why the proxy didn't connect. [`code`](Self::code) is what the program saw in the
/// response's `X-Proxy-Error` header.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum RefusalReason {
    /// Not on the allowlist.
    NotAllowed,
    /// On the deny list, with the reason given for the entry, if any.
    Denied(Option<String>),
    /// The name resolved only to loopback, private, link-local or other non-public addresses.
    NonPublicAddress,
    /// The TLS handshake inside the tunnel named another host (`require_host_match`).
    HostMismatch,
    /// Couldn't connect: the name didn't resolve, or the connection was refused.
    Unreachable,
    /// Connecting took too long.
    TimedOut,
}

impl RefusalReason {
    /// A short stable code for the reason: `not-allowed`, `denied`, `non-public-address`,
    /// `host-mismatch`, `unreachable`, `timed-out`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotAllowed => "not-allowed",
            Self::Denied(_) => "denied",
            Self::NonPublicAddress => "non-public-address",
            Self::HostMismatch => "host-mismatch",
            Self::Unreachable => "unreachable",
            Self::TimedOut => "timed-out",
        }
    }

    /// Whether the policy refused it, as opposed to the connection failing.
    pub fn by_policy(&self) -> bool {
        !matches!(self, Self::Unreachable | Self::TimedOut)
    }
}

impl NetworkRefusal {
    /// The policy-refused hosts among `refusals`, sorted, each once.
    pub(crate) fn blocked_hosts(refusals: &[NetworkRefusal]) -> Vec<String> {
        let mut hosts: Vec<String> = refusals
            .iter()
            .filter(|r| r.reason.by_policy())
            .map(|r| r.host.clone())
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }
}

impl ExecutionResult {
    /// Create a new ExecutionResult with default values
    pub fn new() -> Self {
        Self {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            duration: Duration::ZERO,
            killed_by_timeout: false,
            killed_by_oom: false,
            killed_by_tmp_limit: false,
            killed_by_cpu_limit: false,
            signal: None,
            peak_memory: None,
            cpu_time: None,
            blocked_hosts: Vec::new(),
            network_refusals: Vec::new(),
            output_truncated: false,
            proc_isolated: true,
        }
    }

    /// Check if execution was successful
    pub fn success(&self) -> bool {
        self.exit_code == 0
            && !self.killed_by_timeout
            && !self.killed_by_oom
            && !self.killed_by_tmp_limit
            && !self.killed_by_cpu_limit
            && self.signal.is_none()
    }

    /// Get failure reason if any
    pub fn failure_reason(&self) -> Option<String> {
        if self.killed_by_timeout {
            Some("Execution timed out".into())
        } else if self.killed_by_oom {
            Some("Out of memory".into())
        } else if self.killed_by_tmp_limit {
            Some("Exceeded the /tmp size limit".into())
        } else if self.killed_by_cpu_limit {
            Some("Exceeded the total CPU time limit".into())
        } else if let Some(sig) = self.signal {
            Some(format!("Killed by signal {}", sig))
        } else if self.exit_code != 0 {
            Some(format!("Exit code {}", self.exit_code))
        } else {
            None
        }
    }
}

impl Default for ExecutionResult {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_result_success() {
        let result = ExecutionResult {
            stdout: "hello".into(),
            stderr: String::new(),
            exit_code: 0,
            duration: Duration::from_millis(100),
            killed_by_timeout: false,
            killed_by_oom: false,
            killed_by_tmp_limit: false,
            killed_by_cpu_limit: false,
            signal: None,
            peak_memory: None,
            cpu_time: None,
            blocked_hosts: Vec::new(),
            network_refusals: Vec::new(),
            output_truncated: false,
            proc_isolated: true,
        };
        assert!(result.success());
        assert!(result.failure_reason().is_none());
    }

    #[test]
    fn test_execution_result_failure() {
        let result = ExecutionResult {
            stdout: String::new(),
            stderr: "error".into(),
            exit_code: 1,
            duration: Duration::from_millis(100),
            killed_by_timeout: false,
            killed_by_oom: false,
            killed_by_tmp_limit: false,
            killed_by_cpu_limit: false,
            signal: None,
            peak_memory: None,
            cpu_time: None,
            blocked_hosts: Vec::new(),
            network_refusals: Vec::new(),
            output_truncated: false,
            proc_isolated: true,
        };
        assert!(!result.success());
        assert_eq!(result.failure_reason(), Some("Exit code 1".into()));
    }

    #[test]
    fn test_execution_result_timeout() {
        let result = ExecutionResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 137,
            duration: Duration::from_secs(5),
            killed_by_timeout: true,
            killed_by_oom: false,
            killed_by_tmp_limit: false,
            killed_by_cpu_limit: false,
            signal: Some(9),
            peak_memory: None,
            cpu_time: None,
            blocked_hosts: Vec::new(),
            network_refusals: Vec::new(),
            output_truncated: false,
            proc_isolated: true,
        };
        assert!(!result.success());
        assert_eq!(result.failure_reason(), Some("Execution timed out".into()));
    }

    #[test]
    fn test_execution_result_oom() {
        let result = ExecutionResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 137,
            duration: Duration::from_secs(1),
            killed_by_timeout: false,
            killed_by_oom: true,
            killed_by_tmp_limit: false,
            killed_by_cpu_limit: false,
            signal: Some(9),
            peak_memory: Some(512 * 1024 * 1024),
            cpu_time: None,
            blocked_hosts: Vec::new(),
            network_refusals: Vec::new(),
            output_truncated: false,
            proc_isolated: true,
        };
        assert!(!result.success());
        assert_eq!(result.failure_reason(), Some("Out of memory".into()));
    }

    #[test]
    fn test_execution_result_signal() {
        let result = ExecutionResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 137,
            duration: Duration::from_secs(1),
            killed_by_timeout: false,
            killed_by_oom: false,
            killed_by_tmp_limit: false,
            killed_by_cpu_limit: false,
            signal: Some(9),
            peak_memory: None,
            cpu_time: None,
            blocked_hosts: Vec::new(),
            network_refusals: Vec::new(),
            output_truncated: false,
            proc_isolated: true,
        };
        assert!(!result.success());
        assert_eq!(result.failure_reason(), Some("Killed by signal 9".into()));
    }

    #[test]
    fn test_execution_result_tmp_limit() {
        let result = ExecutionResult {
            killed_by_tmp_limit: true,
            killed_by_cpu_limit: false,
            ..ExecutionResult::new()
        };
        assert!(!result.success());
        assert_eq!(
            result.failure_reason(),
            Some("Exceeded the /tmp size limit".into())
        );
    }
}

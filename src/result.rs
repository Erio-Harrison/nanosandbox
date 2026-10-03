//! Execution result types
//!
//! This module defines the result types returned from sandbox execution.

use std::time::Duration;

/// Result of executing a command in the sandbox
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ExecutionResult {
    /// Standard output captured from the process
    pub stdout: String,

    /// Standard error captured from the process
    pub stderr: String,

    /// Exit code of the process (0 typically means success)
    pub exit_code: i32,

    /// Wall-clock duration of execution
    pub duration: Duration,

    /// Whether the process was killed due to timeout
    pub killed_by_timeout: bool,

    /// Whether the process was killed due to out-of-memory
    pub killed_by_oom: bool,

    /// Whether the process was killed for writing more than `tmpfs("/tmp",
    /// size)` allows. Only where that is emulated with a private directory
    /// (macOS, and Linux under AppArmor's userns restriction); a real tmpfs
    /// fails the write with ENOSPC instead.
    pub killed_by_tmp_limit: bool,

    /// Signal that killed the process, if any
    pub signal: Option<i32>,

    /// Peak memory usage in bytes (if available)
    pub peak_memory: Option<u64>,

    /// CPU time consumed (if available)
    pub cpu_time: Option<Duration>,

    /// Hosts the `allow_network` proxy refused during the run, sorted: not
    /// on the allowlist, or resolving only to non-public addresses. Lets the
    /// caller see what a program tried to reach, and decide what to allow.
    pub blocked_hosts: Vec<String>,
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
            signal: None,
            peak_memory: None,
            cpu_time: None,
            blocked_hosts: Vec::new(),
        }
    }

    /// Check if execution was successful
    pub fn success(&self) -> bool {
        self.exit_code == 0
            && !self.killed_by_timeout
            && !self.killed_by_oom
            && !self.killed_by_tmp_limit
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
            signal: None,
            peak_memory: None,
            cpu_time: None,
            blocked_hosts: Vec::new(),
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
            signal: None,
            peak_memory: None,
            cpu_time: None,
            blocked_hosts: Vec::new(),
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
            signal: Some(9),
            peak_memory: None,
            cpu_time: None,
            blocked_hosts: Vec::new(),
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
            signal: Some(9),
            peak_memory: Some(512 * 1024 * 1024),
            cpu_time: None,
            blocked_hosts: Vec::new(),
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
            signal: Some(9),
            peak_memory: None,
            cpu_time: None,
            blocked_hosts: Vec::new(),
        };
        assert!(!result.success());
        assert_eq!(result.failure_reason(), Some("Killed by signal 9".into()));
    }

    #[test]
    fn test_execution_result_tmp_limit() {
        let result = ExecutionResult {
            killed_by_tmp_limit: true,
            ..ExecutionResult::new()
        };
        assert!(!result.success());
        assert_eq!(
            result.failure_reason(),
            Some("Exceeded the /tmp size limit".into())
        );
    }
}

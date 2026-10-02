//! Error types for nanosandbox
//!
//! This module defines all error types used throughout the nanosandbox library.

use std::path::PathBuf;
use thiserror::Error;

/// Main error type for nanosandbox operations
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum SandboxError {
    /// A setting this platform, or this system's configuration, can't
    /// enforce. Refused rather than run without it.
    #[error("{setting} isn't supported here: {reason}")]
    Unsupported { setting: String, reason: String },

    /// The configuration is inconsistent, such as a bind target that doesn't
    /// exist.
    #[error("Configuration error: {0}")]
    Config(String),

    /// A path the configuration names doesn't exist.
    #[error("Path not found: {0}")]
    PathNotFound(PathBuf),

    // Linux
    #[error("Unprivileged user namespaces disabled. Run: sudo sysctl kernel.unprivileged_userns_clone=1")]
    UserNamespaceDisabled,

    #[error("Cgroups v2 not available or not mounted")]
    CgroupV2Unavailable,

    #[error("Failed to create {ns_type} namespace: {reason}")]
    NamespaceCreation { ns_type: String, reason: String },

    #[error("Failed to create cgroup: {0}")]
    CgroupCreation(String),

    #[error("Failed to set {controller}.{setting} = {value}: {reason}")]
    CgroupSetting {
        controller: String,
        setting: String,
        value: String,
        reason: String,
    },

    // macOS
    #[error("sandbox-exec not available")]
    SandboxExecUnavailable,

    // Windows
    #[error("Failed to create job object: {0}")]
    JobObjectCreation(String),

    // Running the program
    #[error("Command not found: {0}")]
    CommandNotFound(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// A command, argument or path contains a NUL byte.
    #[error("NulError: {0}")]
    NulError(#[from] std::ffi::NulError),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type alias for nanosandbox operations
pub type Result<T> = std::result::Result<T, SandboxError>;

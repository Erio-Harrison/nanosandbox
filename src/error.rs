//! Error types for nanosandbox
//!
//! This module defines all error types used throughout the nanosandbox library.

use std::path::PathBuf;
use thiserror::Error;

/// Main error type for nanosandbox operations
#[derive(Error, Debug)]
pub enum SandboxError {
    // Platform errors
    #[error("Platform not supported: {platform}")]
    PlatformNotSupported { platform: String },

    #[error("Platform feature not available: {feature}")]
    PlatformFeatureUnavailable { feature: String },

    // Linux-specific
    #[error("Unprivileged user namespaces disabled. Run: sudo sysctl kernel.unprivileged_userns_clone=1")]
    UserNamespaceDisabled,

    #[error("Cgroups v2 not available or not mounted")]
    CgroupV2Unavailable,

    #[error("Failed to create {ns_type} namespace: {reason}")]
    NamespaceCreation { ns_type: String, reason: String },

    #[error("Failed to enter namespace: {0}")]
    NamespaceEnter(String),

    // macOS-specific
    #[error("sandbox-exec not available")]
    SandboxExecUnavailable,

    #[error("Failed to create sandbox profile: {0}")]
    SandboxProfileCreation(String),

    // Windows-specific
    #[error("Failed to create job object: {0}")]
    JobObjectCreation(String),

    #[error("Failed to create restricted token: {0}")]
    RestrictedTokenCreation(String),

    // Mount/filesystem errors
    #[error("Mount failed: {src} -> {target}: {reason}")]
    MountFailed {
        src: PathBuf,
        target: PathBuf,
        reason: String,
    },

    #[error("Path not found: {0}")]
    PathNotFound(PathBuf),

    #[error("Invalid mount permission for {path}: {reason}")]
    InvalidMountPermission { path: PathBuf, reason: String },

    // Cgroup errors (Linux)
    #[error("Failed to create cgroup: {0}")]
    CgroupCreation(String),

    #[error("Failed to set {controller}.{setting} = {value}: {reason}")]
    CgroupSetting {
        controller: String,
        setting: String,
        value: String,
        reason: String,
    },

    // Seccomp/security errors
    #[error("Failed to load security filter: {0}")]
    SecurityFilterLoad(String),

    #[error("Syscall blocked: {syscall}")]
    SyscallBlocked { syscall: String },

    // Execution errors
    #[error("Execution timeout after {duration:?}")]
    Timeout { duration: std::time::Duration },

    #[error("Memory limit exceeded: used {used} bytes, limit {limit} bytes")]
    MemoryExceeded { used: u64, limit: u64 },

    #[error("Process limit exceeded: {count} processes, limit {limit}")]
    ProcessLimitExceeded { count: u32, limit: u32 },

    #[error("Process killed by signal: {signal}")]
    Killed { signal: i32 },

    #[error("Command not found: {0}")]
    CommandNotFound(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    // Network errors
    #[error("Network access denied: {domain}")]
    NetworkDenied { domain: String },

    // IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("NulError: {0}")]
    NulError(#[from] std::ffi::NulError),

    // Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    // Other
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type alias for nanosandbox operations
pub type Result<T> = std::result::Result<T, SandboxError>;

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
    /// exist. `source` is `Some` only where the problem was detected via an
    /// underlying error (e.g. a path with a NUL byte); most of these are
    /// plain validation refusals with nothing to attach.
    #[error("Configuration error: {context}")]
    Config {
        context: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// A path the configuration names doesn't exist.
    #[error("Path not found: {0}")]
    PathNotFound(PathBuf),

    // Linux
    #[error(
        "Unprivileged user namespaces disabled. Run: sudo sysctl kernel.unprivileged_userns_clone=1"
    )]
    UserNamespaceDisabled,

    #[error("Cgroups v2 not available or not mounted")]
    CgroupV2Unavailable,

    #[error("Failed to create {ns_type} namespace: {context}: {source}")]
    NamespaceCreation {
        ns_type: String,
        context: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// `source` is `None` for a plain refusal with no underlying error (an
    /// existing directory the kernel didn't object to, but that we don't
    /// recognize as our own), and for the couple of sites where one exists
    /// but was already flattened to a `String` upstream to make a cached,
    /// `Clone`-able result possible (see `compute_own_scope` and
    /// `relocate_into_delegated_scope` in cgroup.rs) -- a trait-object
    /// source can't be `Clone`, so there's nothing left to attach by the
    /// time it reaches here.
    #[error("Failed to create cgroup: {context}")]
    CgroupCreation {
        context: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Failed to set {controller}.{setting} = {value}: {source}")]
    CgroupSetting {
        controller: String,
        setting: String,
        value: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
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

    #[error("Execution failed: {context}: {source}")]
    ExecutionFailed {
        context: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// A command, argument or path contains a NUL byte.
    #[error("NulError: {0}")]
    NulError(#[from] std::ffi::NulError),

    #[error("Internal error: {context}: {source}")]
    Internal {
        context: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// Result type alias for nanosandbox operations
pub type Result<T> = std::result::Result<T, SandboxError>;

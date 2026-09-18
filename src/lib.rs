//! # Nanosandbox
//!
//! A lightweight cross-platform sandbox for secure code execution.
//!
//! ## Platform Support
//!
//! | Platform | Implementation | Status |
//! |----------|----------------|--------|
//! | Linux | namespaces, cgroups v2, seccomp | ✅ Full support |
//! | macOS | sandbox-exec, App Sandbox | ✅ Full support |
//! | Windows | Job Objects, CreateRestrictedToken | ✅ Full support |
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use nanosandbox::{Sandbox, Permission, MB};
//! use std::time::Duration;
//!
//! let sandbox = Sandbox::builder()
//!     .mount("/data/input", "/input", Permission::ReadOnly)
//!     .memory_limit(512 * MB)
//!     .wall_time_limit(Duration::from_secs(30))
//!     .build()
//!     .unwrap();
//!
//! let result = sandbox.run("python3", &["-c", "print('hello')"]).unwrap();
//! println!("{}", result.stdout);
//! ```

pub mod error;
pub mod platform;
pub mod sandbox;
pub mod builder;
pub mod result;
pub mod network;

// Re-exports
pub use error::{Result, SandboxError};
pub use sandbox::Sandbox;
pub use builder::{SandboxBuilder, Permission, NetworkMode, SeccompProfile};
pub use result::ExecutionResult;

/// 1 KB in bytes
pub const KB: u64 = 1024;
/// 1 MB in bytes
pub const MB: u64 = 1024 * 1024;
/// 1 GB in bytes
pub const GB: u64 = 1024 * 1024 * 1024;

/// Check if the current platform supports sandboxing
pub fn is_platform_supported() -> bool {
    platform::is_supported()
}

/// Get the current platform name
pub fn platform_name() -> &'static str {
    platform::name()
}

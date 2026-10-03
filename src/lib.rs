//! # Nanosandbox
//!
//! A lightweight cross-platform sandbox for secure code execution.
//!
//! ## Platform Support
//!
//! | Platform | Implementation | Status |
//! |----------|----------------|--------|
//! | Linux | namespaces, cgroups v2, seccomp, Landlock | ✅ Full support |
//! | macOS | sandbox-exec, App Sandbox | ✅ Full support |
//! | Windows | Job Objects | Memory and CPU limits only; no file system or network isolation |
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use nanosandbox::{Sandbox, MB};
//! use std::time::Duration;
//!
//! let sandbox = Sandbox::builder()
//!     .read_only("/data/input")
//!     .memory_limit(512 * MB)
//!     .wall_time_limit(Duration::from_secs(30))
//!     .build()
//!     .unwrap();
//!
//! let result = sandbox.run("python3", &["-c", "print('hello')"]).unwrap();
//! println!("{}", result.stdout);
//! ```

mod builder;
pub mod error;
pub mod network;
pub(crate) mod platform;
pub mod result;
pub mod sandbox;

// Re-exports
#[cfg(target_os = "linux")]
pub use builder::Permission;
pub use builder::{SandboxBuilder, DEFAULT_MAX_OUTPUT, DEFAULT_PRIVATE_TMP_SIZE};
pub use error::{Result, SandboxError};
pub use result::ExecutionResult;
pub use sandbox::Sandbox;

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

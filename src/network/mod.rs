//! Network isolation and domain allowlisting through an HTTP proxy on every platform.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Sandbox Process                                                 │
//! │  HTTP_PROXY=http://127.0.0.1:PORT                               │
//! │  HTTPS_PROXY=http://127.0.0.1:PORT                              │
//! └────────────────────────────┬────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Nanosandbox HTTP Proxy                                              │
//! │  - Check domain whitelist                                        │
//! │  - Allowed → Forward request                                     │
//! │  - Denied  → Return 403                                          │
//! └────────────────────────────┬────────────────────────────────────┘
//!                              │
//!                              ▼
//!                         [Internet]
//! ```
//!
//! ## Platform-specific behavior
//!
//! | Platform | Network Isolation | Domain Whitelist |
//! |----------|-------------------|------------------|
//! | Linux    | network namespace | HTTP proxy       |
//! | macOS    | SBPL rules        | HTTP proxy       |
//! | Windows  | none: only `host_network()` is supported | none |
//!
//! Each run gets its own proxy listener (in its network namespace on Linux, a fresh loopback
//! port on macOS), closed with the run's open connections when it ends.

// // Windows refuses allow_network() for now, so nothing there uses the proxy.
#[cfg_attr(windows, allow(dead_code))]
mod manager;
#[cfg_attr(windows, allow(dead_code))]
mod proxy;

pub use manager::ProxiedNetwork;
#[cfg(target_os = "linux")]
pub(crate) use manager::SANDBOX_PROXY_PORT;
pub use proxy::HttpProxy;

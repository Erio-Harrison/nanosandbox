//! Network control module
//!
//! Provides cross-platform network isolation and domain whitelisting.
//!
//! ## Architecture
//!
//! All platforms use an HTTP proxy for domain whitelisting:
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
//! Each run gets a proxy listener of its own: inside its network namespace
//! on Linux, a fresh loopback port on macOS. It closes when the run ends,
//! taking the run's open connections with it.

mod manager;
mod proxy;

pub use manager::ProxiedNetwork;
#[cfg(target_os = "linux")]
pub(crate) use manager::SANDBOX_PROXY_PORT;
pub use proxy::HttpProxy;

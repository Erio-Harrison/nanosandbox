//! Network isolation and a destination allowlist through a local proxy on every platform.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Sandbox Process                                                 │
//! │  HTTP_PROXY=HTTPS_PROXY=http://127.0.0.1:PORT                   │
//! │  ALL_PROXY=socks5h://127.0.0.1:PORT                             │
//! └────────────────────────────┬────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Nanosandbox proxy (HTTP and SOCKS5 on one port)                │
//! │  - deny list, then allow list: host pattern, optional port      │
//! │  - resolve once; refuse non-public addresses                    │
//! │  - allowed → connect by address and relay                       │
//! │  - refused → 403 + X-Proxy-Error (SOCKS5: reply 2), recorded    │
//! └────────────────────────────┬────────────────────────────────────┘
//!                              │
//!                              ▼
//!                         [Internet]
//! ```
//!
//! ## Platform-specific behavior
//!
//! | Platform | Network Isolation | Allowlist |
//! |----------|-------------------|-----------|
//! | Linux    | network namespace | proxy     |
//! | macOS    | SBPL rules        | proxy     |
//! | Windows  | none: only `host_network()` is supported | none |
//!
//! Each run gets its own proxy listener (in its network namespace on Linux, a fresh loopback
//! port on macOS), closed with the run's open connections when it ends.

// // Windows refuses allow_network() for now, so nothing there uses the proxy.
#[cfg_attr(windows, allow(dead_code))]
mod manager;
#[cfg_attr(windows, allow(dead_code))]
mod proxy;

#[cfg(target_os = "linux")]
pub(crate) use manager::SANDBOX_PROXY_PORT;
pub use manager::{ProxiedNetwork, ProxyRules};
pub use proxy::HttpProxy;

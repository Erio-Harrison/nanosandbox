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
//! | Windows  | None (best effort)| HTTP proxy       |

mod proxy;
mod manager;

pub use proxy::HttpProxy;
pub use manager::ProxiedNetwork;

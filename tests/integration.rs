//! Integration tests entry point

#[path = "common/mod.rs"]
mod common;

#[path = "integration/basic_exec.rs"]
mod basic_exec;

#[path = "integration/resource_limits.rs"]
mod resource_limits;

#[path = "integration/error_handling.rs"]
mod error_handling;

#[path = "integration/concurrency.rs"]
mod concurrency;

#[path = "integration/proxy_advanced.rs"]
mod proxy_advanced;

#[path = "integration/observability.rs"]
mod observability;

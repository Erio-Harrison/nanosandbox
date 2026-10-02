//! Security tests entry point

#[path = "common/mod.rs"]
mod common;

#[path = "security/escape_attempts.rs"]
mod escape_attempts;

#[path = "security/resource_exhaustion.rs"]
mod resource_exhaustion;

#[path = "security/private_tmp.rs"]
mod private_tmp;

#[path = "security/read_rules.rs"]
mod read_rules;

#[cfg(target_os = "linux")]
#[path = "security/syscall_filter.rs"]
mod syscall_filter;

#[cfg(target_os = "linux")]
#[path = "security/rootfs.rs"]
mod rootfs;

#[cfg(target_os = "macos")]
#[path = "security/sbpl_rules.rs"]
mod sbpl_rules;

// P0: Process management tests (zombie, process groups, signals)
#[cfg(unix)]
#[path = "security/process_management.rs"]
mod process_management;

// P0: Resource enforcement tests (setrlimit, cgroups, OOM)
#[path = "security/resource_enforcement.rs"]
mod resource_enforcement;

// P0: Network security tests (IP bypass, proxy)
#[path = "security/network_security.rs"]
mod network_security;

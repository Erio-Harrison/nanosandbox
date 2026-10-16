//! Security tests entry point
#![cfg_attr(
    not(unix),
    allow(dead_code, unused_imports, unused_variables, unused_mut)
)]

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

#[path = "security/read_only_inside_writable.rs"]
#[cfg(unix)]
mod read_only_inside_writable;

#[path = "security/workspace_swap.rs"]
#[cfg(unix)]
mod workspace_swap;

#[cfg(target_os = "linux")]
#[path = "security/syscall_filter.rs"]
mod syscall_filter;

#[cfg(target_os = "linux")]
#[path = "security/rootfs.rs"]
mod rootfs;

#[cfg(target_os = "linux")]
#[path = "security/shared_tmp_dirs.rs"]
mod shared_tmp_dirs;

#[cfg(target_os = "macos")]
#[path = "security/sbpl_rules.rs"]
mod sbpl_rules;

#[cfg(target_os = "windows")]
#[path = "security/job_limits.rs"]
mod job_limits;

#[cfg(unix)]
#[path = "security/process_management.rs"]
mod process_management;

#[path = "security/resource_enforcement.rs"]
mod resource_enforcement;

#[path = "security/network_security.rs"]
mod network_security;

//! Linux namespace management
//!
//! Handles user namespace UID/GID mapping.

use crate::error::{Result, SandboxError};
use std::fs;

/// User namespace configuration
#[derive(Debug, Clone)]
pub struct UserNamespace {
    /// UID inside the namespace
    inner_uid: u32,
    /// GID inside the namespace
    inner_gid: u32,
}

impl UserNamespace {
    /// Create a new user namespace configuration
    pub fn new(uid: Option<u32>, gid: Option<u32>) -> Self {
        Self {
            inner_uid: uid.unwrap_or(1000),
            inner_gid: gid.unwrap_or(1000),
        }
    }

    /// Write UID/GID mappings for the child process
    pub fn write_mappings(&self, child_pid: i32) -> Result<()> {
        let outer_uid = unsafe { libc::getuid() };
        let outer_gid = unsafe { libc::getgid() };

        // Disable setgroups to allow unprivileged gid_map writes
        let setgroups_path = format!("/proc/{}/setgroups", child_pid);
        fs::write(&setgroups_path, "deny").map_err(|e| SandboxError::NamespaceCreation {
            ns_type: "user".into(),
            reason: format!("Failed to write setgroups: {}", e),
        })?;

        // Write UID mapping: inner_uid outer_uid 1
        let uid_map = format!("{} {} 1", self.inner_uid, outer_uid);
        let uid_map_path = format!("/proc/{}/uid_map", child_pid);
        fs::write(&uid_map_path, &uid_map).map_err(|e| SandboxError::NamespaceCreation {
            ns_type: "user".into(),
            reason: format!("Failed to write uid_map: {}", e),
        })?;

        // Write GID mapping: inner_gid outer_gid 1
        let gid_map = format!("{} {} 1", self.inner_gid, outer_gid);
        let gid_map_path = format!("/proc/{}/gid_map", child_pid);
        fs::write(&gid_map_path, &gid_map).map_err(|e| SandboxError::NamespaceCreation {
            ns_type: "user".into(),
            reason: format!("Failed to write gid_map: {}", e),
        })?;

        Ok(())
    }
}

impl Default for UserNamespace {
    fn default() -> Self {
        Self::new(Some(1000), Some(1000))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_namespace_default() {
        let ns = UserNamespace::default();
        assert_eq!(ns.inner_uid, 1000);
        assert_eq!(ns.inner_gid, 1000);
    }

    #[test]
    fn test_user_namespace_custom() {
        let ns = UserNamespace::new(Some(0), Some(0));
        assert_eq!(ns.inner_uid, 0);
        assert_eq!(ns.inner_gid, 0);
    }
}

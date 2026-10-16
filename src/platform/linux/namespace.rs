//! Linux user namespace UID/GID mapping.

use crate::error::{Result, SandboxError};
use std::fs;

/// `nobody` and `nogroup` on Linux, the ids nothing on the host belongs to.
pub(crate) const NOBODY: u32 = 65534;

/// Whether the caller is root: then the sandbox runs as nobody and drops inherited
/// supplementary groups (e.g. `root`, `docker`). Unprivileged callers can only map their own
/// ids and keep their groups.
pub(crate) fn runs_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// User namespace configuration
#[derive(Debug, Clone)]
pub struct UserNamespace {
    /// UID inside the namespace
    inner_uid: u32,
    /// GID inside the namespace
    inner_gid: u32,
    /// The host ids a root caller's sandbox runs as; `NOBODY` if unset.
    host_uid: Option<u32>,
    host_gid: Option<u32>,
}

impl UserNamespace {
    /// Create a new user namespace configuration
    pub fn new(uid: Option<u32>, gid: Option<u32>) -> Self {
        Self {
            inner_uid: uid.unwrap_or(1000),
            inner_gid: gid.unwrap_or(1000),
            host_uid: None,
            host_gid: None,
        }
    }

    /// For a root caller: run as these host ids instead of nobody.
    pub fn with_host_ids(mut self, uid: Option<u32>, gid: Option<u32>) -> Self {
        self.host_uid = uid;
        self.host_gid = gid;
        self
    }

    /// The host ids a root caller's sandbox runs as.
    pub fn host_ids(&self) -> (u32, u32) {
        (
            self.host_uid.unwrap_or(NOBODY),
            self.host_gid.unwrap_or(NOBODY),
        )
    }

    /// The UID and GID inside the namespace.
    pub fn ids(&self) -> (u32, u32) {
        (self.inner_uid, self.inner_gid)
    }

    /// Write UID/GID mappings for the child process
    pub fn write_mappings(&self, child_pid: i32) -> Result<()> {
        // Mapping a root caller's own ids would give the sandbox root-owner access to host files,
        // so root maps inner ids to nobody (or the chosen ids) and the child switches before exec.
        // Root is also mapped as 0 for child setup; NO_NEW_PRIVS blocks regaining it via setuid.
        let root = runs_as_root();
        let (outer_uid, outer_gid) = if root {
            self.host_ids()
        } else {
            unsafe { (libc::getuid(), libc::getgid()) }
        };
        let map = |inner: u32, outer: u32| {
            if root {
                format!("0 0 1\n{inner} {outer} 1")
            } else {
                format!("{inner} {outer} 1")
            }
        };

        // Unprivileged callers must give up setgroups to write gid_map; root keeps it to drop groups.
        if !runs_as_root() {
            let setgroups_path = format!("/proc/{}/setgroups", child_pid);
            fs::write(&setgroups_path, "deny").map_err(|e| SandboxError::NamespaceCreation {
                ns_type: "user".into(),
                context: "Failed to write setgroups".into(),
                source: Box::new(e),
            })?;
        }

        let uid_map = map(self.inner_uid, outer_uid);
        let uid_map_path = format!("/proc/{}/uid_map", child_pid);
        fs::write(&uid_map_path, &uid_map).map_err(|e| SandboxError::NamespaceCreation {
            ns_type: "user".into(),
            context: "Failed to write uid_map".into(),
            source: Box::new(e),
        })?;

        let gid_map = map(self.inner_gid, outer_gid);
        let gid_map_path = format!("/proc/{}/gid_map", child_pid);
        fs::write(&gid_map_path, &gid_map).map_err(|e| SandboxError::NamespaceCreation {
            ns_type: "user".into(),
            context: "Failed to write gid_map".into(),
            source: Box::new(e),
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

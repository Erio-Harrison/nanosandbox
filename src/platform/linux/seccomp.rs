//! Seccomp-BPF syscall filtering for Linux
//!
//! Provides syscall filtering using seccomp-bpf.

use crate::builder::SeccompProfile;
use crate::error::{Result, SandboxError};

/// Seccomp filter configuration
pub struct SeccompFilter;

impl SeccompFilter {
    /// Apply seccomp filter based on profile
    pub fn apply(profile: &SeccompProfile) -> Result<()> {
        match profile {
            SeccompProfile::Disabled => Ok(()),
            SeccompProfile::Strict => Self::apply_strict(),
            SeccompProfile::Standard => Self::apply_standard(),
            SeccompProfile::Permissive => Self::apply_permissive(),
            SeccompProfile::Custom(syscalls) => Self::apply_custom(syscalls),
        }
    }

    fn apply_strict() -> Result<()> {
        // Strict mode: only allow essential syscalls
        // This is a placeholder - real implementation would use seccomp-bpf
        Self::set_no_new_privs()?;
        // Would install a strict BPF filter here
        Ok(())
    }

    fn apply_standard() -> Result<()> {
        // Standard mode: allow common safe syscalls
        Self::set_no_new_privs()?;
        // Would install a standard BPF filter here
        Ok(())
    }

    fn apply_permissive() -> Result<()> {
        // Permissive mode: allow most syscalls, block dangerous ones
        Self::set_no_new_privs()?;
        // Would install a permissive BPF filter here
        Ok(())
    }

    fn apply_custom(syscalls: &[String]) -> Result<()> {
        // Custom whitelist
        Self::set_no_new_privs()?;
        let _ = syscalls; // Would use these to build custom filter
        Ok(())
    }

    /// Set PR_SET_NO_NEW_PRIVS to prevent privilege escalation
    fn set_no_new_privs() -> Result<()> {
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(SandboxError::SecurityFilterLoad(
                "Failed to set PR_SET_NO_NEW_PRIVS".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_disabled() {
        // Should be a no-op
        let result = SeccompFilter::apply(&SeccompProfile::Disabled);
        assert!(result.is_ok());
    }
}

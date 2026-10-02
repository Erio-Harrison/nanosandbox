//! What a sandbox may not read: credentials in the calling user's home
//! directory by default, anything `deny_read` adds, and the whole home
//! directory with `hide_home`. Paths the config grants (`read_only`,
//! `writable`, the working directory) stay readable even inside those.
//!
//! The rest of the file system stays readable: toolchains, package caches
//! and the user's projects live in the home directory too, and a sandbox
//! that can't build a project isn't much use to a coding agent. What can
//! leave the sandbox is limited by the network settings instead.

use crate::builder::SandboxConfig;
use std::path::{Path, PathBuf};

/// Under the home directory: credentials, tokens and keys of common tools,
/// shell histories (which collect secrets typed on the command line), and
/// browser profiles. Files and directories alike.
const SECRETS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".config/gcloud",
    ".kube",
    ".docker/config.json",
    ".netrc",
    ".git-credentials",
    ".config/gh",
    ".config/hub",
    ".npmrc",
    ".yarnrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".gem/credentials",
    ".terraform.d/credentials.tfrc.json",
    ".vault-token",
    ".password-store",
    ".local/share/keyrings",
    ".mozilla",
    ".config/google-chrome",
    ".config/chromium",
    ".config/BraveSoftware",
    "Library/Keychains",
    "Library/Cookies",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox",
    "Library/Application Support/BraveSoftware",
    "Library/Safari",
];

/// The calling user's home directory: `$HOME`, or the password database's.
pub(crate) fn home_dir() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        return Some(PathBuf::from(home));
    }
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let ret = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if ret != 0 || result.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    use std::os::unix::ffi::OsStrExt;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
}

/// The paths this run may not read, as they exist right now: resolved, and
/// only the ones that exist.
pub(crate) fn denied(config: &SandboxConfig) -> Vec<PathBuf> {
    let mut denied = Vec::new();
    if let Some(home) = home_dir() {
        if config.hide_home {
            denied.push(home);
        } else {
            denied.extend(SECRETS.iter().map(|s| home.join(s)));
            // Shell, REPL and database client histories: .bash_history,
            // .zsh_history, .python_history, .psql_history, ...
            if let Ok(entries) = std::fs::read_dir(&home) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if name.starts_with('.')
                        && (name.ends_with("_history") || name.ends_with("_hist"))
                    {
                        denied.push(entry.path());
                    }
                }
            }
        }
    }
    denied.extend(config.deny_read.iter().cloned());
    let mut denied: Vec<PathBuf> = denied
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect();
    denied.sort();
    denied.dedup();
    denied
}

/// Paths inside `denied` that are readable anyway, because the config names
/// them. A path above a denied one (the default working directory, `/`, or
/// `writable(home)`) doesn't make it readable again.
pub(crate) fn granted(config: &SandboxConfig, denied: &[PathBuf]) -> Vec<PathBuf> {
    config
        .mounts
        .iter()
        .flat_map(|m| [&m.source, &m.target])
        .chain(std::iter::once(&config.working_dir))
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .filter(|p| denied.iter().any(|d| p.starts_with(d)))
        .collect()
}

/// Paths whose subtrees together cover the whole file system except
/// `denied`, for an allow-list (Landlock) to express "everything but these".
/// Descends only along the way to each denied path, allowing every sibling
/// of it at each level. Symlinks there aren't followed: a link pointing into
/// a denied directory would otherwise allow it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn allowed_roots(denied: &[PathBuf]) -> Vec<PathBuf> {
    fn walk(dir: &Path, denied: &[PathBuf], out: &mut Vec<PathBuf>) {
        if denied.iter().any(|d| d == dir) {
            return;
        }
        if !denied.iter().any(|d| d.starts_with(dir)) {
            out.push(dir.to_path_buf());
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_symlink()) {
                continue;
            }
            walk(&entry.path(), denied, out);
        }
    }
    let mut out = Vec::new();
    walk(Path::new("/"), denied, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed_roots_leave_out_only_the_denied() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("a/secret")).unwrap();
        std::fs::create_dir_all(root.join("a/open")).unwrap();
        std::fs::write(root.join("a/file"), "").unwrap();
        std::os::unix::fs::symlink(root.join("a/secret"), root.join("a/link")).unwrap();

        let allowed = allowed_roots(&[root.join("a/secret")]);
        assert!(allowed.contains(&root.join("a/open")));
        assert!(allowed.contains(&root.join("a/file")));
        assert!(!allowed.iter().any(|p| p == &root.join("a/link")));
        assert!(!allowed.iter().any(|p| root.join("a/secret").starts_with(p)));
        // Everything outside is still covered, at the shallowest level.
        assert!(allowed.contains(&PathBuf::from("/usr")) || !Path::new("/usr").exists());
    }

    #[test]
    fn test_hide_home_denies_home_and_deny_read_adds() {
        let Some(home) = home_dir().and_then(|h| h.canonicalize().ok()) else {
            return;
        };
        let extra = tempfile::tempdir().unwrap();
        let config = SandboxConfig {
            hide_home: true,
            deny_read: vec![extra.path().to_path_buf()],
            ..Default::default()
        };
        let denied = denied(&config);
        assert!(denied.contains(&home));
        assert!(denied.contains(&extra.path().canonicalize().unwrap()));
    }
}

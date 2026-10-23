//! What a sandbox may not read: home-directory credentials by default, `deny_read` paths, and
//! all of home with `hide_home`. Config-granted paths stay readable inside those. The rest of
//! the fs stays readable so toolchains and projects work; the network settings limit egress.

use crate::builder::{Permission, SandboxConfig};
use std::path::{Path, PathBuf};

/// Under home: credentials, tokens, keys, shell histories and browser profiles.
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
    ".env",
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

/// Existing paths this run may not read, resolved.
pub(crate) fn denied(config: &SandboxConfig) -> Vec<PathBuf> {
    let mut denied = Vec::new();
    if let Some(home) = home_dir() {
        if config.hide_home {
            denied.push(home);
        } else {
            denied.extend(SECRETS.iter().map(|s| home.join(s)));
            // Shell, REPL and DB client histories.
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
    // Other runs' private temp dirs; a run's own comes back by its own rule.
    denied.push(super::private_tmp::container_location());
    let mut denied: Vec<PathBuf> = denied
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect();
    denied.sort();
    denied.dedup();
    denied
}

/// Paths inside `denied` the config names and so stay readable; a granted ancestor doesn't count.
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

/// Roots covering the whole fs except `denied`, for allow-list (Landlock) use: walks only
/// toward denied paths, allowing siblings; symlinks aren't followed (a link into a denied dir
/// would allow it).
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

/// Existing `.git/hooks` directories inside writable, caller-named dirs, which the sandbox is
/// kept from writing unless `allow_vcs_hook_writes`. A hook written there runs on the host the
/// next time the user runs git. `.git` may be a file pointing elsewhere (worktree/submodule).
pub(crate) fn vcs_protected_paths(config: &SandboxConfig) -> Vec<PathBuf> {
    if !config.protect_vcs_hooks {
        return Vec::new();
    }
    let mut out = Vec::new();
    for m in &config.mounts {
        if m.permission != Permission::ReadWrite || m.source != m.target {
            continue;
        }
        // Rooted at the mount target as given, so it lines up with the writable areas each backend
        // compares against (Linux: raw; macOS resolves both).
        if let Some(git_dir) = resolve_git_dir(&m.target) {
            let hooks = git_dir.join("hooks");
            if hooks.is_dir() && !out.contains(&hooks) {
                out.push(hooks);
            }
        }
    }
    out
}

/// The git directory for `workspace`: `<workspace>/.git` if a directory, or the `gitdir:` it
/// points at if a file (git worktrees and submodules use a `.git` file).
fn resolve_git_dir(workspace: &Path) -> Option<PathBuf> {
    let dot_git = workspace.join(".git");
    if dot_git.is_dir() {
        return Some(dot_git);
    }
    let pointer = std::fs::read_to_string(&dot_git).ok()?;
    let target = pointer.lines().next()?.strip_prefix("gitdir:")?.trim();
    let target = Path::new(target);
    Some(if target.is_absolute() {
        target.to_path_buf()
    } else {
        workspace.join(target)
    })
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

//! What a sandbox may not read: home-directory credentials by default, `deny_read` paths, and
//! all of home with `hide_home`. Config-granted paths stay readable inside those. The rest of
//! the fs stays readable so toolchains and projects work; the network settings limit egress.

use crate::builder::SandboxConfig;
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
    ".config/git/credentials",
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
    // AI coding tools' logins and session stores.
    ".codex",
    ".claude",
    ".claude.json",
    ".cursor",
    ".gemini",
    ".continue",
    ".aider",
    ".openai",
    ".anthropic",
    ".config/openai",
    ".config/claude",
    ".config/anthropic",
    ".config/copilot",
    ".config/github-copilot",
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

/// The credential paths under `home`: `SECRETS`, plus shell, REPL and DB client histories.
fn secrets_in(home: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = SECRETS.iter().map(|s| home.join(s)).collect();
    if let Ok(entries) = std::fs::read_dir(home) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') && (name.ends_with("_history") || name.ends_with("_hist")) {
                out.push(entry.path());
            }
        }
    }
    out
}

/// Existing paths this run may not read, resolved. With `hide_home` the home directory, and
/// still the credentials in it: a path the config grants back inside home (a toolchain
/// directory) doesn't bring those with it.
pub(crate) fn denied(config: &SandboxConfig) -> Vec<PathBuf> {
    let mut denied = Vec::new();
    if let Some(home) = home_dir() {
        if config.hide_home {
            denied.push(home.clone());
        }
        denied.extend(secrets_in(&home));
    }
    denied.extend(config.deny_read.iter().cloned());
    denied.extend(config.linked_secrets.iter().cloned());
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

/// Paths inside `denied` the config names and so stay readable (with `hide_home_except_toolchains`,
/// the toolchain directories too); a granted ancestor doesn't count, and neither does a denied
/// path inside a granted one (see [`denied_inside`]).
pub(crate) fn granted(config: &SandboxConfig, denied: &[PathBuf]) -> Vec<PathBuf> {
    let toolchains = match home_dir() {
        Some(home) if config.hide_home && config.expose_toolchains => {
            toolchain_dirs(&home, std::env::var_os("PATH").as_deref())
        }
        _ => Vec::new(),
    };
    config
        .mounts
        .iter()
        .flat_map(|m| [m.source.clone(), m.target.clone()])
        .chain(std::iter::once(config.working_dir.clone()))
        .chain(toolchains)
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .filter(|p| denied.iter().any(|d| p.starts_with(d)))
        .filter(|p| !denied.iter().any(|d| d == p))
        .collect()
}

/// The denied paths strictly inside `granted`, which must stay denied after the grant: a
/// toolchain directory's credentials file, a secret inside a workspace.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // Linux splits the grant instead
pub(crate) fn denied_inside(granted: &Path, denied: &[PathBuf]) -> Vec<PathBuf> {
    denied
        .iter()
        .filter(|d| *d != granted && d.starts_with(granted))
        .cloned()
        .collect()
}

/// Directories under `home` a toolchain lives in, of the ones that exist: well-known names, and
/// the home subtree of every `PATH` entry under home (`~/.cargo/bin` brings `~/.cargo`).
pub(crate) fn toolchain_dirs(home: &Path, path_var: Option<&std::ffi::OsStr>) -> Vec<PathBuf> {
    const KNOWN: &[&str] = &[
        ".cargo",
        ".rustup",
        ".nvm",
        ".npm",
        ".pnpm",
        ".bun",
        ".deno",
        ".volta",
        ".yarn",
        ".pyenv",
        ".poetry",
        ".local",
        ".cache",
        ".conda",
        "miniconda3",
        "anaconda3",
        ".config/pip",
        ".m2",
        ".gradle",
        ".sdkman",
        "go",
        ".gem",
        ".rbenv",
        ".rvm",
        ".ghcup",
        ".cabal",
        ".stack",
        ".opam",
        ".dotnet",
        ".nuget",
        ".asdf",
        ".nix-profile",
        "Library/Caches",
        "Library/Developer",
        "Library/Android",
        "Library/pnpm",
    ];
    // Configuration git reads from home and won't run without; `~/.config/git/credentials`
    // next to these is a credential store and stays hidden.
    const CONFIG: &[&str] = &[
        ".gitconfig",
        ".config/git/config",
        ".config/git/ignore",
        ".config/git/attributes",
    ];
    let mut out: Vec<PathBuf> = KNOWN
        .iter()
        .chain(CONFIG)
        .map(|k| home.join(k))
        .filter(|p| p.exists())
        .collect();
    if let Some(path_var) = path_var {
        for entry in std::env::split_paths(path_var) {
            // Only a `bin`/`sbin` directory names a tool's install root (`~/x/flutter/bin`
            // brings `~/x/flutter`); anything else on PATH under home (`~/Desktop`) is the
            // caller's to grant.
            let (Some(name), Some(parent)) =
                (entry.file_name().and_then(|n| n.to_str()), entry.parent())
            else {
                continue;
            };
            if !matches!(name, "bin" | "sbin") || !parent.starts_with(home) {
                continue;
            }
            let root = if parent == home {
                entry.as_path()
            } else {
                parent
            };
            if root.is_dir() && !out.iter().any(|o| o == root) {
                out.push(root.to_path_buf());
            }
        }
    }
    out
}

/// Where each toolchain is, for the programs that look for it under `$HOME` (rustup's proxies,
/// nvm, pyenv...): with the home directory hidden, `HOME` is the run's own directory, so they'd
/// look in the wrong place. Only for the directories that exist.
pub(crate) fn toolchain_env(home: &Path) -> Vec<(String, String)> {
    const VARS: &[(&str, &str)] = &[
        ("CARGO_HOME", ".cargo"),
        ("RUSTUP_HOME", ".rustup"),
        ("GOPATH", "go"),
        ("NVM_DIR", ".nvm"),
        ("PYENV_ROOT", ".pyenv"),
        ("BUN_INSTALL", ".bun"),
        ("DENO_INSTALL", ".deno"),
        ("VOLTA_HOME", ".volta"),
        ("SDKMAN_DIR", ".sdkman"),
        ("GRADLE_USER_HOME", ".gradle"),
        #[cfg(target_os = "macos")]
        ("PNPM_HOME", "Library/pnpm"),
        #[cfg(not(target_os = "macos"))]
        ("PNPM_HOME", ".local/share/pnpm"),
    ];
    VARS.iter()
        .map(|(var, dir)| (var, home.join(dir)))
        .filter(|(_, dir)| dir.is_dir())
        .map(|(var, dir)| (var.to_string(), dir.to_string_lossy().into_owned()))
        .collect()
}

/// Roots covering the whole fs except `denied`, for allow-list (Landlock) use.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn allowed_roots(denied: &[PathBuf]) -> Vec<PathBuf> {
    allowed_roots_under(Path::new("/"), denied)
}

/// Roots covering `root` except `denied`, for allow-list (Landlock) use: walks only toward
/// denied paths, allowing siblings; symlinks aren't followed (a link into a denied dir would
/// allow it).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn allowed_roots_under(root: &Path, denied: &[PathBuf]) -> Vec<PathBuf> {
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
    walk(root, denied, &mut out);
    out
}

/// Other names of the denied files. A hard link is a second name for the same file, and every
/// rule here is by name, so a link made on the host beforehand would read (or, in a writable
/// directory, write) the secret through the sandbox. Each denied regular file with more than one
/// link is looked for under the configured directories and home; the names found come back to
/// be denied too. A link that isn't found is refused: it's somewhere readable, and only the
/// host can remove it.
pub(crate) fn linked_secrets(config: &SandboxConfig) -> Result<Vec<PathBuf>, String> {
    use std::collections::HashMap;
    use std::os::unix::fs::MetadataExt;

    let home = home_dir();
    let mut roots: Vec<PathBuf> = config.deny_read.clone();
    if let Some(home) = &home {
        roots.extend(secrets_in(home));
    }
    // (dev, ino) -> (one denied name, links)
    let mut linked: HashMap<(u64, u64), (PathBuf, u64)> = HashMap::new();
    let mut seen_under_denied: HashMap<(u64, u64), u64> = HashMap::new();
    for root in &roots {
        let Ok(root) = root.canonicalize() else {
            continue;
        };
        let mut budget = 256usize;
        let mut stack = vec![(root, 0usize)];
        while let Some((path, depth)) = stack.pop() {
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                if depth < 3
                    && let Ok(entries) = std::fs::read_dir(&path)
                {
                    for entry in entries.flatten() {
                        if budget == 0 {
                            break;
                        }
                        budget -= 1;
                        stack.push((entry.path(), depth + 1));
                    }
                }
            } else if meta.is_file() && meta.nlink() > 1 {
                let key = (meta.dev(), meta.ino());
                *seen_under_denied.entry(key).or_default() += 1;
                linked.entry(key).or_insert((path, meta.nlink()));
            }
        }
    }
    // Names under the denied roots are accounted for already (GnuPG's lock files are hard links
    // to each other inside ~/.gnupg); only a file with names elsewhere needs the search.
    linked.retain(|key, (_, links)| seen_under_denied.get(key).copied().unwrap_or(0) < *links);
    if linked.is_empty() {
        return Ok(Vec::new());
    }

    // Where the other names could be: the configured directories first, then the rest of home,
    // same device only (a hard link can't cross file systems). Home is walked without its
    // bulk (caches, dependency and build trees): a name in there isn't found, and the build is
    // refused rather than the link read.
    const PRUNED: &[&str] = &[
        "Library",
        ".cache",
        ".Trash",
        "node_modules",
        "target",
        ".git",
        ".venv",
        "venv",
        "__pycache__",
    ];
    const MAX_ENTRIES: usize = 500_000;
    let mut search: Vec<PathBuf> = config
        .mounts
        .iter()
        .map(|m| m.source.clone())
        .chain(std::iter::once(config.working_dir.clone()))
        .filter_map(|p| p.canonicalize().ok())
        .collect();
    search.sort();
    search.dedup();
    let home = home.and_then(|h| h.canonicalize().ok());
    let denied_roots: Vec<PathBuf> = roots.iter().filter_map(|p| p.canonicalize().ok()).collect();
    let mut found: Vec<PathBuf> = Vec::new();
    let mut counts: HashMap<(u64, u64), u64> = seen_under_denied;
    let satisfied = |counts: &HashMap<(u64, u64), u64>| {
        linked
            .iter()
            .all(|(key, (_, links))| counts.get(key).copied().unwrap_or(0) >= *links)
    };
    let mut walked: Vec<PathBuf> = Vec::new();
    let mut entries_left = MAX_ENTRIES;
    'roots: for (root, prune) in search
        .iter()
        .map(|r| (r.clone(), false))
        .chain(home.iter().map(|h| (h.clone(), true)))
    {
        if walked.iter().any(|w| root.starts_with(w)) {
            continue;
        }
        let Ok(root_meta) = std::fs::metadata(&root) else {
            continue;
        };
        let dev = root_meta.dev();
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            if denied_roots.contains(&dir) || walked.contains(&dir) {
                continue; // already counted
            }
            if prune
                && dir
                    .file_name()
                    .is_some_and(|n| PRUNED.iter().any(|p| n == *p))
            {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                if entries_left == 0 {
                    break 'roots;
                }
                entries_left -= 1;
                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                if meta.is_symlink() || meta.dev() != dev {
                    continue;
                }
                if meta.is_dir() {
                    stack.push(entry.path());
                } else if meta.is_file() && meta.nlink() > 1 {
                    let key = (meta.dev(), meta.ino());
                    if linked.contains_key(&key) {
                        let path = entry.path();
                        if !denied_roots.iter().any(|d| path.starts_with(d)) {
                            found.push(path);
                        }
                        *counts.entry(key).or_default() += 1;
                        if satisfied(&counts) {
                            break 'roots;
                        }
                    }
                }
            }
        }
        walked.push(root);
    }
    for (key, (name, links)) in &linked {
        let seen = counts.get(key).copied().unwrap_or(0);
        if seen < *links {
            return Err(format!(
                "{} has {} names (hard links); {} of them can't be found under the sandbox's \
                 directories or home, so a command could read it by that name. Find it with \
                 `find / -xdev -samefile '{}' 2>/dev/null` and remove it",
                name.display(),
                links,
                links - seen,
                name.display()
            ));
        }
    }
    found.sort();
    found.dedup();
    Ok(found)
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
    fn test_toolchain_dirs_are_the_known_ones_that_exist_and_path_entries_under_home() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        for d in [
            ".cargo/bin",
            ".nvm",
            "mytools/bin",
            "develop/flutter/bin",
            "bin",
            "Desktop/proj/bin",
            ".ssh",
            ".config/git",
        ] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        std::fs::write(home.join(".gitconfig"), "").unwrap();
        std::fs::write(home.join(".config/git/config"), "").unwrap();
        std::fs::write(home.join(".config/git/credentials"), "").unwrap();
        let path = std::env::join_paths([
            home.join(".cargo/bin"),
            home.join("mytools/bin"),
            home.join("develop/flutter/bin"),
            home.join("bin"),
            home.join("Desktop/proj/bin"),
            home.join("missing/bin"),
            home.to_path_buf(),
            PathBuf::from("/usr/bin"),
        ])
        .unwrap();
        let dirs = toolchain_dirs(home, Some(&path));
        for expected in [
            ".cargo",
            ".nvm",
            "mytools",
            "develop/flutter",
            "bin",
            "Desktop/proj",
            ".gitconfig",
            ".config/git/config",
        ] {
            assert!(dirs.contains(&home.join(expected)), "{expected}: {dirs:?}");
        }
        // Not the whole of ~/develop or ~/Desktop for one tool in them, and not a PATH entry
        // that isn't a bin directory.
        for not in [
            ".rustup",
            "missing",
            ".ssh",
            "develop",
            "Desktop",
            "",
            ".config/git",
            ".config/git/credentials",
        ] {
            assert!(!dirs.contains(&home.join(not)), "{not}: {dirs:?}");
        }
        let path = std::env::join_paths([home.join("Desktop"), home.join("mytools")]).unwrap();
        let dirs = toolchain_dirs(home, Some(&path));
        for not in ["Desktop", "mytools"] {
            assert!(!dirs.contains(&home.join(not)), "{not}: {dirs:?}");
        }
        std::fs::create_dir_all(home.join(".rustup")).unwrap();
        let env = toolchain_env(home);
        assert!(env.contains(&(
            "CARGO_HOME".into(),
            home.join(".cargo").to_string_lossy().into_owned()
        )));
        assert!(env.contains(&(
            "RUSTUP_HOME".into(),
            home.join(".rustup").to_string_lossy().into_owned()
        )));
        assert!(!env.iter().any(|(k, _)| k == "GOPATH"));
        assert_eq!(
            denied_inside(
                &home.join(".cargo"),
                &[
                    home.join(".cargo/credentials"),
                    home.join(".cargo"),
                    home.join(".ssh")
                ]
            ),
            vec![home.join(".cargo/credentials")]
        );
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

#[cfg(test)]
mod linked_tests {
    use super::*;

    #[test]
    fn test_linked_secrets_finds_the_other_name_in_a_configured_dir() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        let ws = dir.path().join("ws");
        std::fs::create_dir(&vault).unwrap();
        std::fs::create_dir(&ws).unwrap();
        std::fs::write(vault.join("key"), "s").unwrap();
        std::fs::hard_link(vault.join("key"), ws.join("innocent")).unwrap();
        let config = SandboxConfig {
            deny_read: vec![vault.clone()],
            mounts: vec![crate::builder::Mount {
                source: ws.clone(),
                target: ws.clone(),
                permission: crate::builder::Permission::ReadWrite,
            }],
            working_dir: ws.clone(),
            ..Default::default()
        };
        let found = linked_secrets(&config).unwrap();
        assert_eq!(found, vec![ws.canonicalize().unwrap().join("innocent")]);
    }
}

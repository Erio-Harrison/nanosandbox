//! SBPL (Sandbox Profile Language) profile generation.

use crate::builder::{NetworkMode, Permission, SandboxConfig};
use crate::platform::read_rules;
use std::path::{Path, PathBuf};

use super::MacOSExecutor;
use super::run_marker::RunMarker;

const BASE_POLICY: &str = include_str!("policy/seatbelt_base_policy.sbpl");
const NETWORK_POLICY: &str = include_str!("policy/seatbelt_network_policy.sbpl");
const PREFERENCES_POLICY: &str = include_str!("policy/seatbelt_preferences_policy.sbpl");

/// Directories programs expect to write to regardless of the working directory
const DEFAULT_WRITABLE: [&str; 4] = [
    "/tmp",
    "/private/tmp",
    "/private/var/folders",
    "/private/var/tmp",
];

/// Gaps in the base policy found by running real programs under it:
/// `sysctl`(1) reads `sysctl.oidfmt.*` / `sysctl.name.*` metadata nodes to format
/// and name a value, on top of the name it was actually asked for; clang
/// needs dirhelper to resolve its scratch directory (falling back to
/// `/private/var/tmp` without it); and `echo > /dev/stdout` writes to
/// `/dev/fd/1`, which only duplicates a descriptor the program already has.
const EXTRA_BASE_POLICY: &str = r#"
(allow sysctl-read (sysctl-name-prefix "sysctl."))
(allow mach-lookup (global-name "com.apple.bsd.dirhelper"))
(allow file-write-data (regex #"^/dev/fd/[0-9]+$"))
"#;

/// Seatbelt policy text and the `-D key=value` definitions it refers to
pub(super) struct SeatbeltProfile {
    pub(super) policy: String,
    pub(super) params: Vec<(String, String)>,
}

/// Resolve symlinks (macOS /tmp is a link to /private/tmp) because Seatbelt
/// matches real paths. Paths that do not exist yet keep their resolved parent.
fn canonical_path(path: &Path) -> PathBuf {
    if let Ok(real) = path.canonicalize() {
        return real;
    }
    match (
        path.parent().and_then(|p| p.canonicalize().ok()),
        path.file_name(),
    ) {
        (Some(parent), Some(name)) => parent.join(name),
        _ => path.to_path_buf(),
    }
}

impl MacOSExecutor {
    /// Compose the SBPL profile: Codex-derived base policy, reads, writes, network.
    /// Paths are passed as `-D` parameters and referenced with `(param ...)`, so a
    /// path can never be parsed as policy text.
    pub(super) fn generate_profile(
        &self,
        config: &SandboxConfig,
        proxy_port: Option<u16>,
        private_tmp: Option<&Path>,
        marker: Option<&RunMarker>,
    ) -> SeatbeltProfile {
        let mut sections = vec![
            BASE_POLICY.to_string(),
            EXTRA_BASE_POLICY.to_string(),
            "(allow file-read*)".to_string(),
        ];

        // The working directory isn't writable by itself being one: it
        // defaults to "/", and code_judge makes it a ReadOnly mount. Either
        // way, that used to open it (all of "/", in the default case) for
        // writing. A ReadWrite mount is how to make it writable.
        let mut roots: Vec<PathBuf> = Vec::new();
        // Without the shared temp directories, only the run's own private one
        // (below) is left to write to: roots stay unlisted, so default-deny
        // covers them.
        let defaults: &[&str] = if config.shared_tmp {
            &DEFAULT_WRITABLE
        } else {
            &[]
        };
        let candidates = defaults
            .iter()
            .map(PathBuf::from)
            .chain(
                config
                    .mounts
                    .iter()
                    .filter(|m| m.permission == Permission::ReadWrite)
                    .map(|m| m.source.clone()),
            )
            .chain(private_tmp.map(Path::to_path_buf));
        // From where the paths led when the sandbox was built, not from where
        // they lead now: a command could have swapped one for a symlink.
        let resolve = |path: &Path| match config.pinned_path(path) {
            Some(real) => real.to_path_buf(),
            None => canonical_path(path),
        };
        for path in candidates {
            let root = resolve(&path);
            if !roots.contains(&root) {
                roots.push(root);
            }
        }

        let mut params = Vec::new();
        let mut write_rules = String::from("; allow writes to the writable roots\n");
        for (i, root) in roots.iter().enumerate() {
            let key = format!("WRITABLE_ROOT_{i}");
            write_rules.push_str(&format!(
                "(allow file-write* (subpath (param \"{key}\")))\n"
            ));
            params.push((key, root.to_string_lossy().into_owned()));
        }
        sections.push(write_rules);

        // The writable roots the configuration names, and every directory
        // above them, can't be removed or renamed. A root is inside its own
        // `subpath` rule, so without this a command could delete the
        // workspace, or move it aside, even where nothing above it is
        // writable, and put in its place a symlink to somewhere it can't
        // write.
        let mut fixed: Vec<PathBuf> = Vec::new();
        for m in config
            .mounts
            .iter()
            .filter(|m| m.permission == Permission::ReadWrite)
        {
            for dir in resolve(&m.source).ancestors() {
                if dir != Path::new("/") && !fixed.iter().any(|f| f == dir) {
                    fixed.push(dir.to_path_buf());
                }
            }
        }
        if !fixed.is_empty() {
            let mut rules = String::from("; the writable roots stay where they are\n");
            for (i, dir) in fixed.iter().enumerate() {
                let key = format!("FIXED_ROOT_{i}");
                rules.push_str(&format!(
                    "(deny file-write-unlink (literal (param \"{key}\")))\n"
                ));
                params.push((key, dir.to_string_lossy().into_owned()));
            }
            sections.push(rules);
        }

        // A read_only path inside a writable root takes writing away again,
        // as on Linux (where it's a read-only mount). The later deny wins.
        // Moving a directory above it away would take the path with it, and
        // a symlink put in that one's place would stand in for it, so none
        // of them can be removed or renamed: not only those inside the
        // writable root but those above it, which may be writable too (a
        // workspace under /tmp).
        let mut narrowed = String::from("; read_only inside a writable root\n");
        let mut n = 0;
        for m in config
            .mounts
            .iter()
            .filter(|m| m.permission == Permission::ReadOnly)
        {
            let path = resolve(&m.target);
            if !roots.iter().any(|r| path != *r && path.starts_with(r)) {
                continue;
            }
            let key = format!("READ_ONLY_{n}");
            narrowed.push_str(&format!("(deny file-write* (subpath (param \"{key}\")))\n"));
            params.push((key, path.to_string_lossy().into_owned()));
            n += 1;
            for ancestor in path.ancestors().skip(1) {
                let key = format!("READ_ONLY_{n}");
                narrowed.push_str(&format!(
                    "(deny file-write-unlink (literal (param \"{key}\")))\n"
                ));
                params.push((key, ancestor.to_string_lossy().into_owned()));
                n += 1;
            }
        }
        if n > 0 {
            sections.push(narrowed);
        }

        // Credentials, deny_read and hide_home: not their contents. Metadata
        // stays readable, as on Linux, where names stay visible. Paths the
        // config names inside them come back after: for the same operation,
        // the later rule wins. (An allow of `file-read*` doesn't override a
        // deny of `file-read-data`, whatever the order.)
        let denied = read_rules::denied(config);
        if !denied.is_empty() {
            let mut read_rules = String::from("; keep these from being read\n");
            for (i, path) in denied.iter().enumerate() {
                let key = format!("DENY_READ_{i}");
                read_rules.push_str(&format!(
                    "(deny file-read-data (subpath (param \"{key}\")))\n"
                ));
                params.push((key, path.to_string_lossy().into_owned()));
            }
            let mut granted = read_rules::granted(config, &denied);
            granted.dedup();
            for (i, path) in granted.iter().enumerate() {
                let key = format!("GRANT_READ_{i}");
                read_rules.push_str(&format!(
                    "(allow file-read-data (subpath (param \"{key}\")))\n"
                ));
                params.push((key, path.to_string_lossy().into_owned()));
            }
            sections.push(read_rules);
        }

        // Marks this run's processes for kill_run; see run_marker.rs.
        if let Some(marker) = marker {
            let mut rules = String::from("; this run's marker\n");
            for (i, (rule, path)) in marker.rules().into_iter().enumerate() {
                let key = format!("RUN_MARKER_{i}");
                rules.push_str(&rule.replace("{}", &key));
                rules.push('\n');
                params.push((key, path.to_string_lossy().into_owned()));
            }
            sections.push(rules);
        }

        match &config.network_mode {
            NetworkMode::None => {}
            NetworkMode::Host => {
                sections.push(format!(
                    "(allow network-outbound)\n(allow network-inbound)\n{NETWORK_POLICY}"
                ));
            }
            // Only the local proxy is reachable, so the domain allowlist cannot be
            // bypassed by connecting directly. Without a proxy port nothing is opened.
            NetworkMode::Proxied { .. } => {
                if let Some(port) = proxy_port {
                    sections.push(format!(
                        "(allow network-outbound (remote ip \"localhost:{port}\"))\n{NETWORK_POLICY}"
                    ));
                }
            }
        }

        sections.push(PREFERENCES_POLICY.to_string());
        sections.push("(deny mach-lookup (xpc-service-name-prefix \"\"))".to_string());
        // These fcntls mutate files through read-only descriptors, bypassing file-write*.
        sections.push("(deny system-fcntl (fcntl-command 80 110))".to_string());

        SeatbeltProfile {
            policy: sections.join("\n"),
            params,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::Mount;

    fn profile(config: &SandboxConfig, proxy_port: Option<u16>) -> SeatbeltProfile {
        MacOSExecutor::new().generate_profile(config, proxy_port, None, None)
    }

    #[test]
    fn test_generate_profile() {
        let p = profile(&SandboxConfig::default(), None);

        assert!(p.policy.contains("(version 1)"));
        assert!(p.policy.contains("(deny default)"));
        assert!(p.policy.contains("(allow signal (target same-sandbox))"));
        assert!(!p.policy.contains("(allow signal)"));
    }

    #[test]
    fn test_generate_profile_with_mounts() {
        let mut config = SandboxConfig::default();
        config.mounts.push(Mount {
            source: "/tmp/test_mount".into(),
            target: "/sandbox/test".into(),
            permission: Permission::ReadWrite,
        });

        let p = profile(&config, None);
        assert!(p.params.iter().any(|(_, v)| v.ends_with("test_mount")));
        assert!(!p.policy.contains("test_mount"));
    }

    #[test]
    fn test_shared_tmp_false_leaves_only_the_private_directory_writable() {
        let private = std::env::temp_dir().join("nanosandbox-tmp-test");
        let mut config = SandboxConfig::default();
        config.mounts.push(Mount {
            source: private.clone(),
            target: private.clone(),
            permission: Permission::ReadWrite,
        });

        let shared = MacOSExecutor::new().generate_profile(&config, None, Some(&private), None);
        assert!(writable(&shared).iter().any(|w| w == "/private/tmp"));
        assert!(
            writable(&shared)
                .iter()
                .any(|w| w == "/private/var/folders")
        );

        config.shared_tmp = false;
        let strict = MacOSExecutor::new().generate_profile(&config, None, Some(&private), None);
        let roots = writable(&strict);
        for shared_dir in ["/private/tmp", "/private/var/tmp", "/private/var/folders"] {
            assert!(
                !roots.iter().any(|w| w == shared_dir),
                "{shared_dir}: {roots:?}"
            );
        }
        // What was asked for explicitly is still there.
        assert!(
            roots.iter().any(|w| w.ends_with("nanosandbox-tmp-test")),
            "{roots:?}"
        );
    }

    /// The writable roots, canonicalized, as the profile's parameters hold them.
    fn writable(p: &SeatbeltProfile) -> Vec<String> {
        p.params
            .iter()
            .filter(|(k, _)| k.starts_with("WRITABLE_ROOT_"))
            .map(|(_, v)| v.clone())
            .collect()
    }

    #[test]
    fn test_working_dir_is_not_writable_by_itself() {
        // The default working_dir is "/".
        let p = profile(&SandboxConfig::default(), None);
        assert!(
            !writable(&p).contains(&"/".to_string()),
            "{:?}",
            writable(&p)
        );

        // code_judge: a ReadOnly mount as the working directory.
        let dir = std::env::current_dir().unwrap();
        let mut config = SandboxConfig {
            working_dir: dir.clone(),
            ..Default::default()
        };
        config.mounts.push(Mount {
            source: dir.clone(),
            target: dir.clone(),
            permission: Permission::ReadOnly,
        });
        let p = profile(&config, None);
        let dir = dir.canonicalize().unwrap().to_string_lossy().into_owned();
        assert!(!writable(&p).contains(&dir), "{:?}", writable(&p));
    }

    #[test]
    fn test_paths_are_parameters_not_policy_text() {
        let mut config = SandboxConfig::default();
        config.mounts.push(Mount {
            source: PathBuf::from("/tmp/x\") (allow file-write* (subpath \"/"),
            target: PathBuf::from("/tmp/x"),
            permission: Permission::ReadWrite,
        });

        let p = profile(&config, None);
        assert!(!p.policy.contains("(allow file-write* (subpath \"/\"))"));
        assert!(
            p.params
                .iter()
                .any(|(_, v)| v.contains("(allow file-write*"))
        );
    }

    #[test]
    fn test_generate_profile_network_none() {
        let p = profile(
            &SandboxConfig {
                network_mode: NetworkMode::None,
                ..Default::default()
            },
            None,
        );
        assert!(!p.policy.contains("(allow network-outbound"));
    }

    #[test]
    fn test_generate_profile_network_host() {
        let p = profile(
            &SandboxConfig {
                network_mode: NetworkMode::Host,
                ..Default::default()
            },
            None,
        );
        assert!(p.policy.contains("(allow network-outbound)"));
    }

    #[test]
    fn test_generate_profile_network_proxied_only_reaches_proxy() {
        let config = SandboxConfig {
            network_mode: NetworkMode::Proxied {
                allowed_domains: vec!["example.com".into()],
            },
            ..Default::default()
        };

        let p = profile(&config, Some(8080));
        assert!(p.policy.contains("(remote ip \"localhost:8080\")"));
        assert!(!p.policy.contains("(allow network-outbound)"));

        let p = profile(&config, None);
        assert!(!p.policy.contains("(allow network-outbound"));
    }
}

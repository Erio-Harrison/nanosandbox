//! SBPL (Sandbox Profile Language) profile generation.

use crate::builder::{NetworkMode, Permission, SandboxConfig};
use crate::platform::read_rules;
use std::path::{Path, PathBuf};

use super::MacOSExecutor;
use super::run_marker::RunMarker;

const BASE_POLICY: &str = include_str!("policy/seatbelt_base_policy.sbpl");
const NETWORK_POLICY: &str = include_str!("policy/seatbelt_network_policy.sbpl");
const PREFERENCES_POLICY: &str = include_str!("policy/seatbelt_preferences_policy.sbpl");

const DEFAULT_WRITABLE: [&str; 4] = [
    "/tmp",
    "/private/tmp",
    "/private/var/folders",
    "/private/var/tmp",
];

/// Base-policy gaps found with real programs: sysctl metadata nodes, clang's dirhelper,
/// and `/dev/fd/1` for `echo > /dev/stdout`. `/dev/tty` is the run's own controlling terminal
/// (`spawn_pty`; otherwise there is none and opening it fails), which the base policy's
/// `/dev/ttysN` rule doesn't cover for a terminal made before the sandbox applied.
const EXTRA_BASE_POLICY: &str = r#"
(allow sysctl-read (sysctl-name-prefix "sysctl."))
(allow mach-lookup (global-name "com.apple.bsd.dirhelper"))
(allow file-write-data (regex #"^/dev/fd/[0-9]+$"))
(allow file-read* file-write* file-ioctl (literal "/dev/tty"))
"#;

/// The certificate-verification daemons fetch OCSP and issuer URLs for a program outside the
/// allowlist; a certificate it evaluates can name any host. Dropped unless `allow_trustd`.
const TRUST_SERVICES: [&str; 2] = ["com.apple.trustd.agent", "com.apple.ocspd"];

fn without_trust_services(policy: &str) -> String {
    policy
        .lines()
        .filter(|line| !TRUST_SERVICES.iter().any(|s| line.contains(s)))
        .map(|line| format!("{line}\n"))
        .collect()
}

pub(super) struct SeatbeltProfile {
    pub(super) policy: String,
    pub(super) params: Vec<(String, String)>,
}

/// Seatbelt matches real paths, so resolve symlinks (/tmp -> /private/tmp).
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
    /// Compose the SBPL profile. Paths go in as `-D` params so they're never parsed as policy.
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

        // A working dir isn't writable just by being one (default "/", or a ReadOnly mount); use a ReadWrite mount.
        let mut roots: Vec<PathBuf> = Vec::new();
        // Without shared tmp only the private dir (below) is writable; roots stay unlisted.
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
        // Use the paths as they led at build time; a command could swap one for a symlink.
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
        // After the roots: the later rule wins, so other runs' dirs go and this run's returns.
        if let Some(own) = private_tmp {
            write_rules.push_str("(deny file-write* (subpath (param \"PRIVATE_TMPS\")))\n");
            params.push((
                "PRIVATE_TMPS".into(),
                crate::platform::private_tmp::container_location()
                    .to_string_lossy()
                    .into_owned(),
            ));
            write_rules.push_str("(allow file-write* (subpath (param \"PRIVATE_TMP_OWN_W\")))\n");
            params.push((
                "PRIVATE_TMP_OWN_W".into(),
                canonical_path(own).to_string_lossy().into_owned(),
            ));
        }
        sections.push(write_rules);

        // Writable roots and their ancestors can't be removed or renamed, else a command could
        // swap the workspace for a symlink.
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

        // A read_only path in a writable root loses write again (later deny wins); it and its
        // ancestors can't be removed or renamed, or a symlink could stand in for it. `.git/hooks`
        // is protected the same way, so a hook can't be written for the host's git to run.
        let narrow: Vec<PathBuf> = config
            .mounts
            .iter()
            .filter(|m| m.permission == Permission::ReadOnly)
            .map(|m| resolve(&m.target))
            .chain(
                read_rules::vcs_protected_paths(config)
                    .iter()
                    .map(|p| resolve(p)),
            )
            .collect();
        let mut narrowed = String::from("; read_only inside a writable root\n");
        let mut n = 0;
        for path in narrow {
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

        // Credentials/deny_read/hide_home deny contents, not metadata. Config paths inside come
        // back after. (allow `file-read*` doesn't override deny `file-read-data` in any order.)
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
            // In a writable root a denied path, or a directory above it, could be renamed to where
            // no deny applies; none of them can be removed or renamed.
            let in_root = |dir: &Path| roots.iter().any(|r| dir.starts_with(r));
            let mut fixed_denied: Vec<(&str, &Path)> = Vec::new();
            for path in denied.iter().filter(|p| in_root(p)) {
                fixed_denied.push(("subpath", path));
                for dir in path.ancestors().skip(1).take_while(|d| in_root(d)) {
                    if !fixed_denied.iter().any(|(_, f)| *f == dir) {
                        fixed_denied.push(("literal", dir));
                    }
                }
            }
            for (i, (filter, dir)) in fixed_denied.iter().enumerate() {
                let key = format!("DENY_READ_FIXED_{i}");
                read_rules.push_str(&format!(
                    "(deny file-write-unlink ({filter} (param \"{key}\")))\n"
                ));
                params.push((key, dir.to_string_lossy().into_owned()));
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
            if let Some(own) = private_tmp {
                read_rules
                    .push_str("(allow file-read-data (subpath (param \"PRIVATE_TMP_OWN\")))\n");
                params.push((
                    "PRIVATE_TMP_OWN".into(),
                    canonical_path(own).to_string_lossy().into_owned(),
                ));
            }
            sections.push(read_rules);
        }

        // Marks this run's processes for kill_run (run_marker.rs). No command may write, rename or
        // remove the markers dir or its ancestors, so it can't strip a concurrent run's markers.
        if let Some(marker) = marker {
            let mut rules = String::from("; this run's marker\n");
            if let Ok(dir) = super::run_marker::markers_dir() {
                rules.push_str("(deny file-write* (subpath (param \"MARKERS_DIR\")))\n");
                params.push(("MARKERS_DIR".into(), dir.to_string_lossy().into_owned()));
                for (i, ancestor) in dir.ancestors().enumerate() {
                    if ancestor == Path::new("/") {
                        break;
                    }
                    let key = format!("MARKERS_ABOVE_{i}");
                    rules.push_str(&format!(
                        "(deny file-write-unlink (literal (param \"{key}\")))\n"
                    ));
                    params.push((key, ancestor.to_string_lossy().into_owned()));
                }
            }
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
            // Only the local proxy is reachable, so the allowlist can't be bypassed; no port, nothing open.
            NetworkMode::Proxied { .. } => {
                if let Some(port) = proxy_port {
                    let network_policy = if config.allow_trustd {
                        NETWORK_POLICY.to_string()
                    } else {
                        without_trust_services(NETWORK_POLICY)
                    };
                    sections.push(format!(
                        "(allow network-outbound (remote ip \"localhost:{port}\"))\n{network_policy}"
                    ));
                }
            }
        }

        sections.push(PREFERENCES_POLICY.to_string());
        sections.push("(deny mach-lookup (xpc-service-name-prefix \"\"))".to_string());
        // These fcntls mutate files via read-only fds, bypassing file-write*.
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
        assert!(
            roots.iter().any(|w| w.ends_with("nanosandbox-tmp-test")),
            "{roots:?}"
        );
    }

    fn writable(p: &SeatbeltProfile) -> Vec<String> {
        p.params
            .iter()
            .filter(|(k, _)| k.starts_with("WRITABLE_ROOT_"))
            .map(|(_, v)| v.clone())
            .collect()
    }

    #[test]
    fn test_working_dir_is_not_writable_by_itself() {
        let p = profile(&SandboxConfig::default(), None);
        assert!(
            !writable(&p).contains(&"/".to_string()),
            "{:?}",
            writable(&p)
        );

        // code_judge: ReadOnly mount as working dir.
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

    /// trustd fetches URLs for the program outside the allowlist, so the proxied profile leaves
    /// it out unless asked; the host profile keeps it.
    #[test]
    fn test_proxied_profile_drops_trust_services_unless_allowed() {
        let proxied = || SandboxConfig {
            network_mode: NetworkMode::Proxied {
                allowed_domains: vec!["example.com".into()],
            },
            ..Default::default()
        };
        let p = profile(&proxied(), Some(8080));
        for service in TRUST_SERVICES {
            assert!(!p.policy.contains(service), "{service}");
        }
        assert!(p.policy.contains("com.apple.SecurityServer"));
        assert!(p.policy.contains("com.apple.networkd"));

        let p = profile(
            &SandboxConfig {
                allow_trustd: true,
                ..proxied()
            },
            Some(8080),
        );
        assert!(p.policy.contains("com.apple.trustd.agent"));
        let p = profile(
            &SandboxConfig {
                network_mode: NetworkMode::Host,
                ..Default::default()
            },
            None,
        );
        assert!(p.policy.contains("com.apple.trustd.agent"));
    }
}

//! The same protected place under many spellings: `deny_read` and `read_only`-inside-writable
//! can't depend on how a path is written. Every spelling is first checked to reach the place
//! from the host (one that doesn't proves nothing), and a sandbox without the rule must see
//! them through, or the matrix would pass by being blind.

#![cfg(unix)]

use nanosandbox::Sandbox;
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A path and the name it goes by in the report.
type Alias = (String, String);

struct Tree {
    _dir: tempfile::TempDir,
    root: PathBuf,
    ws: PathBuf,
}

const NFC: &str = "caf\u{e9}";
#[cfg(target_os = "macos")]
const NFD: &str = "cafe\u{301}";

fn tree(parent: &Path) -> Tree {
    let dir = crate::common::sandbox_tempdir_in(parent);
    let root = dir.path().canonicalize().unwrap();
    let ws = root.join("ws");
    for d in ["secrets/sub", "pub", "ro", NFC] {
        std::fs::create_dir_all(ws.join(d)).unwrap();
    }
    std::fs::write(ws.join("secrets/key"), "SECRET").unwrap();
    std::fs::write(ws.join(NFC).join("key"), "SECRET").unwrap();
    std::fs::write(ws.join("ro/key"), "SAFE").unwrap();
    std::fs::write(ws.join("ro_file"), "SAFE").unwrap();
    for d in [
        "ws",
        "ws/secrets",
        "ws/secrets/sub",
        "ws/pub",
        "ws/ro",
        &format!("ws/{NFC}"),
    ] {
        crate::common::chmod_open(&root.join(d));
    }
    for (name, target) in [
        ("secrets", ws.join("secrets")),
        ("ro", ws.join("ro")),
        (NFC, ws.join(NFC)),
    ] {
        std::os::unix::fs::symlink(&target, ws.join(format!("ln_{name}"))).unwrap();
        std::os::unix::fs::symlink(name, ws.join(format!("rel_{name}"))).unwrap();
        std::os::unix::fs::symlink(format!("ln_{name}"), ws.join(format!("chain_{name}"))).unwrap();
    }
    std::os::unix::fs::symlink(".", ws.join("ln_up")).unwrap();
    std::os::unix::fs::symlink(&ws, root.join("ln_ws")).unwrap();
    Tree {
        _dir: dir,
        root,
        ws,
    }
}

/// The ways to write the path of the directory `name` in the workspace. Relative ones are
/// relative to the workspace, where the command runs.
fn dir_aliases(t: &Tree, name: &str) -> Vec<Alias> {
    let (ws, root) = (&t.ws, &t.root);
    let abs = ws.join(name);
    let s = |p: &Path| p.to_string_lossy().into_owned();
    let ws_name = ws.file_name().unwrap().to_string_lossy().into_owned();
    let mut out: Vec<Alias> = vec![
        ("absolute".into(), s(&abs)),
        ("trailing slash".into(), format!("{}/", s(&abs))),
        ("dot segment".into(), format!("{}/./{name}", s(ws))),
        ("doubled slashes".into(), format!("{}//{name}", s(ws))),
        (
            "dotdot via a sibling".into(),
            format!("{}/pub/../{name}", s(ws)),
        ),
        ("dotdot back out".into(), format!("{}/{name}/sub/..", s(ws))),
        ("relative".into(), name.to_string()),
        ("relative with dot".into(), format!("./{name}")),
        ("relative via parent".into(), format!("../{ws_name}/{name}")),
        ("symlink to it".into(), s(&ws.join(format!("ln_{name}")))),
        (
            "relative symlink".into(),
            s(&ws.join(format!("rel_{name}"))),
        ),
        ("symlink chain".into(), s(&ws.join(format!("chain_{name}")))),
        (
            "workspace through a link".into(),
            format!("{}/ln_ws/{name}", s(root)),
        ),
        (
            "workspace through its own link".into(),
            format!("{}/ln_up/{name}", s(ws)),
        ),
        (
            "symlink with trailing slash".into(),
            format!("{}/", s(&ws.join(format!("ln_{name}")))),
        ),
    ];

    // Where the temp directory has an alias spelling of its own (macOS: /var is /private/var).
    let abs_s = s(&abs);
    if let Some(rest) = abs_s.strip_prefix("/private") {
        out.push(("without /private".into(), rest.to_string()));
    } else if abs_s.starts_with("/var/") || abs_s.starts_with("/tmp/") || abs_s.starts_with("/etc/")
    {
        out.push(("with /private".into(), format!("/private{abs_s}")));
    }

    #[cfg(target_os = "macos")]
    {
        out.push((
            "firmlink spelling".into(),
            format!("/System/Volumes/Data{abs_s}"),
        ));
        for entry in std::fs::read_dir("/Volumes")
            .into_iter()
            .flatten()
            .flatten()
        {
            if std::fs::read_link(entry.path()).is_ok_and(|t| t == Path::new("/")) {
                out.push((
                    "/Volumes volume name".into(),
                    format!("{}{abs_s}", entry.path().display()),
                ));
            }
        }
        // APFS here is case-insensitive unless the host check below drops these.
        let swapped: String = name
            .chars()
            .map(|c| {
                if c.is_lowercase() {
                    c.to_uppercase().next().unwrap()
                } else {
                    c
                }
            })
            .collect();
        out.push(("upper case".into(), format!("{}/{swapped}", s(ws))));
        let mixed: String = name
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_uppercase().next().unwrap()
                } else {
                    c
                }
            })
            .collect();
        out.push(("mixed case".into(), format!("{}/{mixed}", s(ws))));
        if let Ok(meta) = std::fs::metadata(&abs) {
            out.push((
                "by volume and inode".into(),
                format!("/.vol/{}/{}", meta.dev(), meta.ino()),
            ));
        }
        if name == NFC {
            out.push(("decomposed Unicode".into(), format!("{}/{NFD}", s(ws))));
            out.push((
                "decomposed, through a link".into(),
                format!("{}/ln_{NFD}", s(ws)),
            ));
        }
    }
    #[cfg(target_os = "linux")]
    {
        // Resolved by the command's own /proc; the host can't check these.
        out.push(("/proc/self/cwd".into(), format!("/proc/self/cwd/{name}")));
        out.push(("/proc/self/root".into(), format!("/proc/self/root{abs_s}")));
    }
    out
}

/// Whether `alias` reaches a directory holding `file` from the host.
fn reaches(t: &Tree, alias: &str, file: &str) -> bool {
    if alias.starts_with("/proc/self/") {
        return true; // the command's /proc, not this process's
    }
    let base = if alias.starts_with('/') {
        PathBuf::from(alias)
    } else {
        t.ws.join(alias)
    };
    base.join(file).exists()
}

fn script_for_reads(aliases: &[Alias], file: &str) -> String {
    let mut script = String::new();
    for (label, path) in aliases {
        let quoted = path.replace('\'', "'\\''");
        script.push_str(&format!(
            "out=$(cat '{quoted}/{file}' 2>/dev/null); case \"$out\" in *SECRET*) echo \"READ $(printf %s '{label}' | tr ' ' _)\";; esac\n\
             out=$(ls '{quoted}' 2>/dev/null); case \"$out\" in *{file}*) echo \"LIST $(printf %s '{label}' | tr ' ' _)\";; esac\n"
        ));
    }
    script
}

fn leaks(out: &str) -> Vec<String> {
    out.lines()
        .filter(|l| l.starts_with("READ ") || l.starts_with("LIST ") || l.starts_with("WROTE "))
        .map(String::from)
        .collect()
}

fn roots() -> Vec<PathBuf> {
    vec![
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")),
        std::env::temp_dir(),
    ]
}

#[test]
fn test_deny_read_holds_under_every_spelling_of_the_path() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    for parent in roots() {
        let t = tree(&parent);
        if crate::common::skip_if_unreachable_by_nobody(&t.ws) {
            return;
        }
        for name in ["secrets", NFC] {
            let aliases: Vec<Alias> = dir_aliases(&t, name)
                .into_iter()
                .filter(|(_, p)| reaches(&t, p, "key"))
                .collect();
            assert!(
                aliases.len() >= 12,
                "{name}: only {} spellings reach it from the host",
                aliases.len()
            );
            eprintln!(
                "{name} under {}: {:?}",
                parent.display(),
                aliases.iter().map(|(l, _)| l.as_str()).collect::<Vec<_>>()
            );
            let script = script_for_reads(&aliases, "key");

            // Without the rule every spelling reads: the matrix can see.
            let open = Sandbox::builder()
                .working_dir(&t.ws)
                .writable(&t.ws)
                .wall_time_limit(Duration::from_secs(20))
                .build()
                .unwrap();
            let seen = leaks(&open.run("sh", &["-c", &script]).unwrap().stdout);
            let blind: Vec<_> = aliases
                .iter()
                .map(|(label, _)| label.replace(' ', "_"))
                .filter(|label| {
                    !label.starts_with("workspace_through_a_link")
                        && !seen.contains(&format!("READ {label}"))
                })
                .collect();
            assert!(
                blind.is_empty(),
                "{name}: with no rule these couldn't read: {blind:?}"
            );

            let sandbox = Sandbox::builder()
                .working_dir(&t.ws)
                .writable(&t.ws)
                .deny_read(t.ws.join(name))
                .wall_time_limit(Duration::from_secs(20))
                .build()
                .unwrap();
            let result = sandbox.run("sh", &["-c", &script]).unwrap();
            let got = leaks(&result.stdout);
            assert!(
                got.is_empty(),
                "{name} under {}: read through {got:?}\nspellings: {:#?}",
                parent.display(),
                aliases
            );
            assert_eq!(
                std::fs::read_to_string(t.ws.join(name).join("key")).unwrap(),
                "SECRET"
            );
        }
        // A symlink to one denied file, named by that link and by the file.
        let sandbox = Sandbox::builder()
            .working_dir(&t.ws)
            .writable(&t.ws)
            .deny_read(t.ws.join("secrets/key"))
            .wall_time_limit(Duration::from_secs(20))
            .build()
            .unwrap();
        std::os::unix::fs::symlink(t.ws.join("secrets/key"), t.ws.join("ln_key")).unwrap();
        for read in [
            "cat ln_key",
            "cat secrets/key",
            "cat secrets/./key",
            "cat pub/../secrets/key",
            "cat ../ws/secrets/key",
            "cat ln_secrets/key",
            "cat rel_secrets/key",
        ] {
            let out = sandbox.run("sh", &["-c", read]).unwrap();
            assert!(!out.stdout.contains("SECRET"), "{read}: {}", out.stdout);
        }
    }
}

const WRITES: [(&str, &str); 8] = [
    ("append", "echo EVIL >> {p}/key"),
    ("truncate", ": > {p}/key"),
    ("remove", "rm -f {p}/key"),
    ("rename away", "mv {p}/key {p}/key.x"),
    ("create", "echo EVIL > {p}/new"),
    ("mkdir", "mkdir {p}/d"),
    (
        "hard link, then write",
        "ln {p}/key hl_{n} && echo EVIL >> hl_{n}",
    ),
    ("chmod", "chmod 000 {p}/key"),
];

#[test]
fn test_read_only_inside_writable_holds_under_every_spelling_of_the_path() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    for parent in roots() {
        let t = tree(&parent);
        if crate::common::skip_if_unreachable_by_nobody(&t.ws) {
            return;
        }
        let aliases: Vec<Alias> = dir_aliases(&t, "ro")
            .into_iter()
            .filter(|(label, p)| {
                // A link is itself in the writable area: removing or renaming it is fine, and
                // the aliases that end in one are tried with the operations that follow it.
                !label.contains("symlink") && !label.contains("chain") && reaches(&t, p, "key")
            })
            .collect();
        assert!(aliases.len() >= 10, "only {} spellings", aliases.len());

        let mut script = String::new();
        for (n, (label, path)) in aliases.iter().enumerate() {
            let label = label.replace(' ', "_");
            let quoted = path.replace('\'', "'\\''");
            for (op, cmd) in WRITES {
                let cmd = cmd
                    .replace("{p}", &format!("'{quoted}'"))
                    .replace("{n}", &n.to_string());
                script.push_str(&format!(
                    "( {cmd} ) >/dev/null 2>&1 && echo \"WROTE {label} / {op}\"\n"
                ));
            }
        }
        let build = || {
            Sandbox::builder()
                .working_dir(&t.ws)
                .writable(&t.ws)
                .read_only(t.ws.join("ro"))
                .wall_time_limit(Duration::from_secs(30))
                .build()
                .unwrap()
        };

        // Without the rule the writes land: the matrix can see. (Different run, same tree.)
        let probe = tree(&parent);
        let open = Sandbox::builder()
            .working_dir(&probe.ws)
            .writable(&probe.ws)
            .wall_time_limit(Duration::from_secs(30))
            .build()
            .unwrap();
        let probe_aliases: Vec<Alias> = dir_aliases(&probe, "ro")
            .into_iter()
            .filter(|(label, p)| {
                !label.contains("symlink") && !label.contains("chain") && reaches(&probe, p, "key")
            })
            .collect();
        let mut probe_script = String::new();
        for (label, path) in &probe_aliases {
            let label = label.replace(' ', "_");
            probe_script.push_str(&format!(
                "( echo EVIL >> '{path}/key' ) >/dev/null 2>&1 && echo \"WROTE {label} / append\"\n"
            ));
        }
        let wrote = leaks(&open.run("sh", &["-c", &probe_script]).unwrap().stdout);
        let blind: Vec<_> = probe_aliases
            .iter()
            .map(|(label, _)| label.replace(' ', "_"))
            .filter(|label| {
                !label.starts_with("workspace_through_a_link")
                    && !wrote.contains(&format!("WROTE {label} / append"))
            })
            .collect();
        assert!(
            blind.is_empty(),
            "with no rule these couldn't write: {blind:?}"
        );

        let result = build().run("sh", &["-c", &script]).unwrap();
        let got = leaks(&result.stdout);
        let read = |p: &str| std::fs::read_to_string(t.ws.join(p)).ok();
        let names: Vec<String> = std::fs::read_dir(t.ws.join("ro"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            got.is_empty() && read("ro/key").as_deref() == Some("SAFE") && names == ["key"],
            "under {}: succeeded: {got:#?}\nkey {:?}, ro holds {names:?}",
            parent.display(),
            read("ro/key")
        );
    }
}

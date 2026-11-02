//! Every combination of where the workspace is, how it is granted, and which rules sit on it,
//! checked for what each rule promises and for nothing else being blocked. The rules were
//! each tested alone; a bug lived where two met (a denied path inside a workspace under a
//! tmpfs directory).

#![cfg(unix)]

use nanosandbox::Sandbox;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
struct Combo {
    writable: bool,
    deny_dir: bool,
    deny_file: bool,
    read_only_dir: bool,
    hide_home: bool,
    private_tmp: bool,
    /// Run from a subdirectory of the workspace rather than its root.
    in_subdir: bool,
}

fn parents() -> Vec<(String, PathBuf)> {
    let mut out = vec![
        (
            "target".to_string(),
            PathBuf::from(env!("CARGO_TARGET_TMPDIR")),
        ),
        ("/tmp".to_string(), PathBuf::from("/tmp")),
        ("/var/tmp".to_string(), PathBuf::from("/var/tmp")),
    ];
    if Path::new("/dev/shm").is_dir() {
        out.push(("/dev/shm".into(), PathBuf::from("/dev/shm")));
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from)
        && home.is_dir()
    {
        out.push(("$HOME".into(), home));
    }
    out
}

fn combos() -> Vec<Combo> {
    let mut out = Vec::new();
    for bits in 0..16u32 {
        for writable in [true, false] {
            for private_tmp in [true, false] {
                let read_only_dir = bits & 4 != 0;
                if read_only_dir && !writable {
                    continue; // nothing to take writing away from
                }
                out.push(Combo {
                    writable,
                    deny_dir: bits & 1 != 0,
                    deny_file: bits & 2 != 0,
                    read_only_dir,
                    hide_home: bits & 8 != 0,
                    private_tmp,
                    in_subdir: out.len() % 2 == 1,
                });
            }
        }
    }
    out
}

/// What the script printed, as `name=yes|no`.
fn answers(stdout: &str) -> std::collections::BTreeMap<String, bool> {
    stdout
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v == "yes"))
        .collect()
}

#[test]
fn test_rules_hold_in_every_combination_of_place_grant_and_rule() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    let canary_dir = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(format!(".nanosandbox-matrix-canary-{}", std::process::id())));
    if let Some(dir) = &canary_dir {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("canary"), "CANARY").unwrap();
    }
    let mut problems = Vec::new();
    let mut ran = 0;
    for (place, parent) in parents() {
        for combo in combos() {
            let dir = crate::common::sandbox_tempdir_in(&parent);
            let ws = dir.path().canonicalize().unwrap();
            if crate::common::skip_if_unreachable_by_nobody(&ws) {
                return;
            }
            for d in ["sd", "ro", "sub"] {
                std::fs::create_dir_all(ws.join(d)).unwrap();
                crate::common::chmod_open(&ws.join(d));
            }
            crate::common::chmod_open(&ws);
            std::fs::write(ws.join("sd/key"), "SECRET").unwrap();
            std::fs::write(ws.join(".env"), "SECRET").unwrap();
            std::fs::write(ws.join("ro/f"), "SAFE").unwrap();
            std::fs::write(ws.join("open.txt"), "fine").unwrap();
            for f in ["sd/key", ".env", "ro/f", "open.txt"] {
                crate::common::chmod_open(&ws.join(f));
            }

            let mut b = Sandbox::builder()
                .working_dir(if combo.in_subdir {
                    ws.join("sub")
                } else {
                    ws.clone()
                })
                .wall_time_limit(Duration::from_secs(20));
            b = if combo.writable {
                b.writable(&ws)
            } else {
                b.read_only(&ws)
            };
            if combo.deny_dir {
                b = b.deny_read(ws.join("sd"));
            }
            if combo.deny_file {
                b = b.deny_read(ws.join(".env"));
            }
            if combo.read_only_dir {
                b = b.read_only(ws.join("ro"));
            }
            if combo.hide_home {
                b = b.hide_home();
            }
            if !combo.private_tmp {
                b = b.no_private_tmp();
            }
            let describe = format!("{place} {combo:?}");
            let sandbox = match b.build() {
                Ok(s) => s,
                Err(e) => {
                    problems.push(format!("{describe}: refused to build: {e}"));
                    continue;
                }
            };

            let w = |name: &str, path: String| {
                format!("( echo x >> '{path}' ) 2>/dev/null && echo {name}=yes || echo {name}=no\n")
            };
            let r = |name: &str, path: String, word: &str| {
                format!(
                    "case \"$(cat '{path}' 2>/dev/null)\" in *{word}*) echo {name}=yes;; *) echo {name}=no;; esac\n"
                )
            };
            let p = |s: &str| ws.join(s).display().to_string();
            let mut script = String::new();
            script += &r("secret_dir", p("sd/key"), "SECRET");
            script += &r("secret_file", p(".env"), "SECRET");
            script += &r("open", p("open.txt"), "fine");
            script += &r("ro_readable", p("ro/f"), "SAFE");
            script += &w("write_ro", p("ro/f"));
            script += &w("write_new", p("new.txt"));
            script += &w("write_open", p("open.txt"));
            if let Some(dir) = &canary_dir {
                script += &r("canary", dir.join("canary").display().to_string(), "CANARY");
            }
            let out = match sandbox.run("sh", &["-c", &script]) {
                Ok(o) => o,
                Err(e) => {
                    problems.push(format!("{describe}: run failed: {e}"));
                    continue;
                }
            };
            ran += 1;
            let got = answers(&out.stdout);
            let mut expect = vec![
                ("secret_dir", !combo.deny_dir),
                ("secret_file", !combo.deny_file),
                ("open", true),
                ("ro_readable", true),
                ("write_ro", combo.writable && !combo.read_only_dir),
                ("write_new", combo.writable),
                ("write_open", combo.writable),
            ];
            if combo.hide_home && canary_dir.is_some() {
                expect.push(("canary", false));
            }
            for (name, want) in expect {
                if got.get(name) != Some(&want) {
                    problems.push(format!(
                        "{describe}: {name} is {:?}, should be {want}",
                        got.get(name)
                    ));
                }
            }
            // What the rules protect is checked on the host too, not from the answers.
            if !combo.writable || combo.read_only_dir {
                let now = std::fs::read_to_string(ws.join("ro/f")).unwrap_or_default();
                if now != "SAFE" {
                    problems.push(format!("{describe}: ro/f changed on the host: {now:?}"));
                }
            }
        }
    }
    if let Some(dir) = &canary_dir {
        let _ = std::fs::remove_dir_all(dir);
    }
    assert!(
        problems.is_empty(),
        "{} problems in {ran} combinations, first:\n{}",
        problems.len(),
        problems[..problems.len().min(12)].join("\n")
    );
    eprintln!("{ran} combinations checked");
    assert!(ran >= 150, "only {ran} combinations ran");
}

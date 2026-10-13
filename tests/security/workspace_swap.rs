//! A command can't redirect the sandbox's writable directory by swapping the
//! directory, or one above it, for a symlink to somewhere it may not write.
//!
//! Each test makes a victim directory the sandbox is never given, lets a
//! command try the swap, and checks the victim afterwards: the swap itself
//! may be refused (macOS, where the roots can't be removed), or may go
//! through (Linux, where the parent is writable) and the next run refuse.

use nanosandbox::Sandbox;
use std::path::{Path, PathBuf};
use std::time::Duration;

struct Layout {
    _tmp: tempfile::TempDir,
    parent: PathBuf,
    ws: PathBuf,
    victim: PathBuf,
}

fn layout() -> Layout {
    let tmp = crate::common::sandbox_tempdir_in(env!("CARGO_TARGET_TMPDIR"));
    let root = tmp.path().canonicalize().unwrap();
    let parent = root.join("parent");
    let ws = parent.join("ws");
    let victim = root.join("victim");
    for d in [&parent, &ws, &victim] {
        std::fs::create_dir_all(d).unwrap();
        crate::common::chmod_open(d);
    }
    std::fs::write(victim.join("precious.txt"), "do not touch").unwrap();
    Layout {
        _tmp: tmp,
        parent,
        ws,
        victim,
    }
}

fn sandbox(builder: nanosandbox::SandboxBuilder) -> Sandbox {
    builder
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap()
}

fn sh(sandbox: &Sandbox, script: &str) {
    // A refused run is as good as a failed command here.
    let _ = sandbox.run("sh", &["-c", script]);
}

fn assert_victim_untouched(victim: &Path) {
    let names: Vec<String> = std::fs::read_dir(victim)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        ["precious.txt"],
        "the victim was written to: {names:?}"
    );
    assert_eq!(
        std::fs::read_to_string(victim.join("precious.txt")).unwrap(),
        "do not touch"
    );
}

/// The usual layout: a workspace in a directory the sandbox can't write.
#[test]
fn a_command_cannot_swap_its_workspace_for_a_symlink() {
    let l = layout();
    if crate::common::skip_if_unreachable_by_nobody(&l.ws) {
        return;
    }
    let sb = sandbox(Sandbox::builder().working_dir(&l.ws).writable(&l.ws));
    // Pinning the paths must leave the workspace writable.
    let out = sb
        .run(
            "sh",
            &[
                "-c",
                "echo ok > fine.txt && mkdir sub && echo ok > sub/deep.txt",
            ],
        )
        .unwrap();
    assert_eq!(out.exit_code, 0, "{}", out.stderr);
    assert!(l.ws.join("fine.txt").exists() && l.ws.join("sub/deep.txt").exists());
    let (ws, victim) = (l.ws.display(), l.victim.display());
    sh(&sb, &format!("rm -rf {ws}; ln -s {victim} {ws}"));
    sh(
        &sb,
        &format!(
            "echo PWNED > {ws}/pwned.txt; echo X >> {ws}/precious.txt; rm -f {ws}/precious.txt"
        ),
    );
    assert_victim_untouched(&l.victim);
    assert!(
        l.ws.symlink_metadata().unwrap().is_dir(),
        "the workspace was replaced"
    );
}

/// A workspace inside a directory the sandbox can write, which lets it move
/// the workspace aside.
#[test]
fn a_command_cannot_swap_a_workspace_that_sits_in_a_writable_parent() {
    let l = layout();
    if crate::common::skip_if_unreachable_by_nobody(&l.ws) {
        return;
    }
    let sb = sandbox(
        Sandbox::builder()
            .working_dir(&l.ws)
            .writable(&l.parent)
            .writable(&l.ws),
    );
    let out = sb.run("sh", &["-c", "echo ok > fine.txt"]).unwrap();
    assert_eq!(
        out.exit_code, 0,
        "the workspace must stay writable: {}",
        out.stderr
    );
    let (ws, victim) = (l.ws.display(), l.victim.display());
    sh(&sb, &format!("mv {ws} {ws}.bak; ln -s {victim} {ws}"));
    sh(
        &sb,
        &format!("echo PWNED > {ws}/pwned.txt; rm -f {ws}/precious.txt"),
    );
    // Whatever it did to the parent, the victim is as it was.
    assert_victim_untouched(&l.victim);
}

/// A directory above the workspace swapped, not the workspace.
#[test]
fn a_command_cannot_swap_a_directory_above_its_workspace() {
    let l = layout();
    let (a, deep) = (l.parent.join("a"), l.parent.join("a/b/ws"));
    std::fs::create_dir_all(&deep).unwrap();
    for d in [&a, &a.join("b"), &deep] {
        crate::common::chmod_open(d);
    }
    // The same shape, in the victim, for the swap to land in.
    std::fs::create_dir_all(l.victim.join("b/ws")).unwrap();
    crate::common::chmod_open(&l.victim.join("b"));
    crate::common::chmod_open(&l.victim.join("b/ws"));
    if crate::common::skip_if_unreachable_by_nobody(&deep) {
        return;
    }
    let sb = sandbox(
        Sandbox::builder()
            .working_dir(&deep)
            .writable(&l.parent)
            .writable(&deep),
    );
    let (a_s, v) = (a.display(), l.victim.display());
    sh(&sb, &format!("mv {a_s} {a_s}.bak; ln -s {v} {a_s}"));
    sh(&sb, &format!("echo PWNED > {a_s}/b/ws/pwned.txt"));
    assert!(
        !l.victim.join("b/ws/pwned.txt").exists(),
        "a directory above the workspace was swapped, and written through"
    );
}

/// Replaced by someone else, between runs: refused, clearly, and put back
/// to a real directory it runs again.
#[test]
fn a_workspace_replaced_between_runs_is_refused_and_a_real_one_is_not() {
    let l = layout();
    if crate::common::skip_if_unreachable_by_nobody(&l.ws) {
        return;
    }
    let sb = sandbox(Sandbox::builder().working_dir(&l.ws).writable(&l.ws));
    assert!(sb.run("echo", &["fine"]).is_ok());

    std::fs::remove_dir_all(&l.ws).unwrap();
    std::os::unix::fs::symlink(&l.victim, &l.ws).unwrap();
    let err = sb.run("echo", &["no"]).unwrap_err().to_string();
    assert!(err.contains("was replaced"), "{err}");

    // Deleted and made again at the same path: the same place, so it's fine.
    std::fs::remove_file(&l.ws).unwrap();
    std::fs::create_dir(&l.ws).unwrap();
    crate::common::chmod_open(&l.ws);
    let out = sb.run("echo", &["back"]).unwrap();
    assert_eq!(out.stdout, "back\n");
    assert_victim_untouched(&l.victim);
}

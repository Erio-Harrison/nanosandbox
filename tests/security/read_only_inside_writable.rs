//! A `read_only` path inside a writable one (the workspace, say) is read-only
//! again: on Linux a read-only mount, on macOS a deny rule. It can't be
//! written, replaced, renamed or removed, nor can the directories above it be
//! moved out of the way, while the rest of the workspace stays writable.

use nanosandbox::Sandbox;
use std::path::Path;
use std::time::Duration;

fn workspace() -> tempfile::TempDir {
    let ws = crate::common::sandbox_tempdir_in(env!("CARGO_TARGET_TMPDIR"));
    let root = ws.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join(".dc")).unwrap();
    std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
    std::fs::write(root.join(".dc/settings.json"), "SAFE").unwrap();
    std::fs::write(root.join(".dc/other.json"), "other").unwrap();
    std::fs::write(root.join(".git/hooks/pre-commit"), "hook").unwrap();
    // The sandbox's user (nobody, for a root caller) has to be able to
    // write what the tests then expect to be refused.
    for p in [".dc", ".git", ".git/hooks"] {
        crate::common::chmod_open(&root.join(p));
    }
    ws
}

fn sandbox(root: &Path) -> nanosandbox::Result<Sandbox> {
    Sandbox::builder()
        .working_dir(root)
        .writable(root)
        .read_only(root.join(".dc/settings.json"))
        .read_only(root.join(".git/hooks"))
        .wall_time_limit(Duration::from_secs(10))
        .build()
}

fn sh(sandbox: &Sandbox, script: &str) -> String {
    let out = sandbox.run("sh", &["-c", script]).unwrap();
    format!("{}{}", out.stdout, out.stderr)
}

#[test]
fn test_read_only_inside_writable_cannot_be_changed_or_moved() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    let ws = workspace();
    let root = ws.path().canonicalize().unwrap();
    if crate::common::skip_if_unreachable_by_nobody(&root) {
        return;
    }
    let sandbox = sandbox(&root).unwrap();

    // None of these may get through. Each one's result is checked on the
    // host after, not from what the shell says.
    for attack in [
        "echo EVIL > .dc/settings.json",
        "echo EVIL >> .dc/settings.json",
        ": > .dc/settings.json",
        "rm -f .dc/settings.json",
        "mv .dc/settings.json .dc/x",
        "echo EVIL > .dc/new && mv .dc/new .dc/settings.json",
        "ln .dc/settings.json hl.txt && echo EVIL > hl.txt",
        "mv .dc .dc.bak",
        "mv .dc .dc.bak && mkdir .dc && echo EVIL > .dc/settings.json",
        "mv .git .git.bak && mkdir -p .git/hooks && echo EVIL > .git/hooks/pre-commit",
        "rm -rf .dc",
        "echo EVIL > .git/hooks/pre-commit",
        "echo EVIL > .git/hooks/post-commit",
        "rm -f .git/hooks/pre-commit",
        "mv .git/hooks .git/hooks.bak",
        "rm -rf .git/hooks",
    ] {
        let _ = sh(&sandbox, attack);
    }
    let read = |p: &str| std::fs::read_to_string(root.join(p)).ok();
    assert_eq!(read(".dc/settings.json").as_deref(), Some("SAFE"));
    assert_eq!(read(".git/hooks/pre-commit").as_deref(), Some("hook"));
    assert!(!root.join(".git/hooks/post-commit").exists());
    assert!(root.join(".dc").is_dir() && !root.join(".dc.bak").exists());
    assert!(root.join(".git").is_dir() && !root.join(".git.bak").exists());
    assert!(root.join(".git/hooks").is_dir() && !root.join(".git/hooks.bak").exists());

    // The rest of the workspace is still writable.
    let out = sh(
        &sandbox,
        "echo ok > newfile.txt && echo ok > .dc/other.json && echo ok > .dc/brandnew.json \
         && echo ok > .git/config && echo done",
    );
    assert!(out.contains("done"), "{out}");
    assert_eq!(read("newfile.txt").as_deref(), Some("ok\n"));
    assert_eq!(read(".dc/brandnew.json").as_deref(), Some("ok\n"));
}

/// Without mounting, Linux can't take writing away inside a writable area:
/// it says so at build(), rather than leaving the path writable.
#[cfg(target_os = "linux")]
#[test]
fn test_read_only_inside_writable_is_refused_where_it_cannot_be_enforced() {
    let restricted =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .is_ok_and(|v| v.trim() == "1");
    if !restricted || unsafe { libc::geteuid() } == 0 {
        return;
    }
    let ws = workspace();
    let err = sandbox(&ws.path().canonicalize().unwrap())
        .err()
        .expect("should be refused");
    assert!(
        err.to_string().contains("read_only inside a writable"),
        "{err}"
    );
}

/// The workspace itself may sit in a writable directory (macOS's shared
/// /tmp, say): then it can be moved away and a fake put in its place, with
/// a symlink for `.dc` pointing at a file the sandbox may write.
#[test]
fn test_the_workspace_itself_cannot_be_swapped_out() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    let outer = workspace();
    let outer_root = outer.path().canonicalize().unwrap();
    if crate::common::skip_if_unreachable_by_nobody(&outer_root) {
        return;
    }
    let ws = outer_root.join("ws");
    std::fs::create_dir_all(ws.join(".dc")).unwrap();
    std::fs::write(ws.join(".dc/settings.json"), "SAFE").unwrap();
    crate::common::chmod_open(&ws);
    crate::common::chmod_open(&ws.join(".dc"));
    let evil = outer_root.join("evil");
    std::fs::create_dir(&evil).unwrap();
    std::fs::write(evil.join("settings.json"), "EVIL").unwrap();
    crate::common::chmod_open(&evil);

    let sandbox = Sandbox::builder()
        .working_dir(&ws)
        .writable(&outer_root)
        .writable(&ws)
        .read_only(ws.join(".dc/settings.json"))
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();
    let (w, e) = (ws.display(), evil.display());
    for attack in [
        format!("mv {w} {w}.bak; mkdir {w}; ln -s {e} {w}/.dc"),
        format!("mv {w} {w}.bak && mkdir -p {w}/.dc && echo EVIL > {w}/.dc/settings.json"),
        format!("cd /; rm -rf {w}"),
    ] {
        let _ = sh(&sandbox, &attack);
    }
    assert_eq!(
        std::fs::read_to_string(ws.join(".dc/settings.json"))
            .as_deref()
            .ok(),
        Some("SAFE"),
        "the workspace was swapped out"
    );
    assert!(!outer_root.join("ws.bak").exists());
}

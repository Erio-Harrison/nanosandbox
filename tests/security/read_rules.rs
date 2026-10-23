//! What a sandbox can't read: home credentials by default, `deny_read` paths, and the whole home with
//! `hide_home`, except what `read_only`/`writable` name inside them.

use nanosandbox::Sandbox;

/// Whether the sandbox can read the contents of `file`.
fn can_read(sandbox: &Sandbox, file: &std::path::Path) -> bool {
    let script = format!("cat '{}' >/dev/null 2>&1", file.display());
    sandbox.run("sh", &["-c", &script]).unwrap().exit_code == 0
}

fn home() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("HOME").unwrap())
}

#[test]
#[cfg(unix)]
fn test_deny_read_with_read_only_inside() {
    // Not under /tmp, which is a fresh tmpfs inside Linux sandboxes.
    let dir = crate::common::sandbox_tempdir_in(env!("CARGO_TARGET_TMPDIR"));
    if crate::common::skip_if_unreachable_by_nobody(dir.path()) {
        return;
    }
    std::fs::create_dir(dir.path().join("open")).unwrap();
    std::fs::write(dir.path().join("secret"), "s").unwrap();
    std::fs::write(dir.path().join("open/file"), "o").unwrap();

    let sandbox = Sandbox::builder()
        .deny_read(dir.path())
        .read_only(dir.path().join("open"))
        .build()
        .unwrap();
    assert!(!can_read(&sandbox, &dir.path().join("secret")));
    assert!(can_read(&sandbox, &dir.path().join("open/file")));

    let unrestricted = Sandbox::builder().build().unwrap();
    assert!(can_read(&unrestricted, &dir.path().join("secret")));
}

#[test]
#[cfg(unix)]
fn test_hide_home_except_what_is_named() {
    let hidden = crate::common::sandbox_tempdir_in(home());
    let shown = crate::common::sandbox_tempdir_in(home());
    if crate::common::skip_if_unreachable_by_nobody(shown.path()) {
        return;
    }
    std::fs::write(hidden.path().join("f"), "h").unwrap();
    std::fs::write(shown.path().join("f"), "s").unwrap();

    let sandbox = Sandbox::builder()
        .hide_home()
        .read_only(shown.path())
        .build()
        .unwrap();
    assert!(!can_read(&sandbox, &hidden.path().join("f")));
    assert!(can_read(&sandbox, &shown.path().join("f")));

    let sandbox = Sandbox::builder().build().unwrap();
    assert!(can_read(&sandbox, &hidden.path().join("f")));
}

/// A deny_read path inside a writable directory stays unreadable, also after renaming it, or
/// the directory it's in, or linking or copying it; the rest of the directory works as usual.
#[test]
#[cfg(unix)]
fn test_deny_read_inside_a_writable_dir() {
    let dir = crate::common::sandbox_tempdir_in(env!("CARGO_TARGET_TMPDIR"));
    if crate::common::skip_if_unreachable_by_nobody(dir.path()) {
        return;
    }
    let ws = dir.path();
    std::fs::create_dir_all(ws.join("parent/secrets")).unwrap();
    std::fs::write(ws.join(".env"), "SECRET").unwrap();
    std::fs::write(ws.join("parent/secrets/key"), "SECRET").unwrap();

    let built = Sandbox::builder()
        .working_dir(ws)
        .writable(ws)
        .deny_read(ws.join(".env"))
        .deny_read(ws.join("parent/secrets"))
        .build();
    if crate::common::skip_without_userns_privileges() {
        // Hiding them needs a mount; refused rather than left readable.
        assert!(built.is_err());
        return;
    }
    let sandbox = built.unwrap();
    for cmd in [
        "cat .env",
        "cat parent/secrets/key",
        "mv .env moved; cat moved",
        "mv parent/secrets s; cat s/key",
        "mv parent p; cat p/secrets/key",
        "ln .env linked; cat linked",
        "cp .env copied; cat copied",
    ] {
        let r = sandbox.run("sh", &["-c", cmd]).unwrap();
        assert!(
            !r.stdout.contains("SECRET"),
            "{cmd}: read it ({})",
            r.stdout
        );
    }
    assert_eq!(std::fs::read_to_string(ws.join(".env")).unwrap(), "SECRET");
    assert!(ws.join("parent/secrets/key").exists());
    let r = sandbox
        .run("sh", &["-c", "echo ok > new && cat new"])
        .unwrap();
    assert_eq!(r.stdout.trim(), "ok", "{}", r.stderr);
}

/// SSH keys can't be read by default; checked only where ~/.ssh has a file.
#[test]
#[cfg(unix)]
fn test_credentials_unreadable_by_default() {
    let Some(file) = std::fs::read_dir(home().join(".ssh"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.is_file() && std::fs::read(p).is_ok())
    else {
        eprintln!("skipping: no readable file in ~/.ssh");
        return;
    };
    let sandbox = Sandbox::builder().build().unwrap();
    assert!(
        !can_read(&sandbox, &file),
        "{} was readable",
        file.display()
    );
}

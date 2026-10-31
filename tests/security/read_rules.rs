//! What a sandbox can't read: home credentials by default, `deny_read` paths, and the whole home with
//! `hide_home`, except what `read_only`/`writable` name inside them.

use nanosandbox::Sandbox;

/// Whether the sandbox can read the contents of `file`.
fn can_read(sandbox: &Sandbox, file: &std::path::Path) -> bool {
    let script = format!("cat '{}' >/dev/null 2>&1", file.display());
    sandbox.run("sh", &["-c", &script]).unwrap().exit_code == 0
}

/// What the sandbox sees in `file` (on Linux a hidden file reads as empty rather than failing).
fn contents(sandbox: &Sandbox, file: &std::path::Path) -> String {
    let script = format!("cat '{}' 2>/dev/null", file.display());
    sandbox.run("sh", &["-c", &script]).unwrap().stdout
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

/// A path granted back inside a denied one doesn't bring the denied paths inside it: a
/// toolchain directory comes back without its credentials file.
#[test]
#[cfg(unix)]
fn test_a_denied_path_inside_a_granted_one_stays_denied() {
    let dir = crate::common::sandbox_tempdir_in(env!("CARGO_TARGET_TMPDIR"));
    if crate::common::skip_if_unreachable_by_nobody(dir.path()) {
        return;
    }
    std::fs::create_dir_all(dir.path().join("tool/bin")).unwrap();
    std::fs::write(dir.path().join("tool/bin/x"), "x").unwrap();
    std::fs::write(dir.path().join("tool/credentials"), "s").unwrap();
    let sandbox = Sandbox::builder()
        .deny_read(dir.path())
        .read_only(dir.path().join("tool"))
        .deny_read(dir.path().join("tool/credentials"))
        .build()
        .unwrap();
    assert!(can_read(&sandbox, &dir.path().join("tool/bin/x")));
    assert!(!can_read(&sandbox, &dir.path().join("tool/credentials")));
}

/// A hard link made on the host is another name for a denied file. At build the denied files
/// with more than one name are looked for under the sandbox's directories, and the other names
/// denied too; one that can't be found refuses the build.
#[test]
#[cfg(unix)]
fn test_a_hard_link_to_a_denied_file_is_denied_or_refused() {
    let dir = crate::common::sandbox_tempdir_in(env!("CARGO_TARGET_TMPDIR"));
    if crate::common::skip_if_unreachable_by_nobody(dir.path()) {
        return;
    }
    // Linux: a mount over the link in a writable directory, so not under the AppArmor restriction.
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    let vault = dir.path().join("vault");
    let ws = dir.path().join("ws");
    let elsewhere = dir.path().join("elsewhere");
    for d in [&vault, &ws, &elsewhere] {
        std::fs::create_dir(d).unwrap();
    }
    std::fs::write(vault.join("key"), "secret").unwrap();
    std::fs::hard_link(vault.join("key"), ws.join("innocent.txt")).unwrap();

    let sandbox = Sandbox::builder()
        .deny_read(&vault)
        .writable(&ws)
        .working_dir(&ws)
        .build()
        .unwrap();
    assert!(!contents(&sandbox, &vault.join("key")).contains("secret"));
    assert!(!contents(&sandbox, &ws.join("innocent.txt")).contains("secret"));
    // Writing through the link doesn't reach the secret (macOS refuses it; on Linux the mount
    // over the link swallows it).
    let _ = sandbox
        .run("sh", &["-c", "echo pwned >> innocent.txt"])
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(vault.join("key")).unwrap(),
        "secret"
    );
    // Siblings are untouched.
    let r = sandbox
        .run("sh", &["-c", "echo ok > other && cat other"])
        .unwrap();
    assert_eq!(r.stdout.trim(), "ok", "{}", r.stderr);

    // A second name the sandbox can't find: refused, naming the file.
    std::fs::hard_link(vault.join("key"), elsewhere.join("copy")).unwrap();
    match Sandbox::builder()
        .deny_read(&vault)
        .writable(&ws)
        .working_dir(&ws)
        .build()
    {
        Err(nanosandbox::SandboxError::Config { context, .. }) => {
            assert!(context.contains("hard links"), "{context}");
            assert!(context.contains("key"), "{context}");
        }
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("built with a link to the secret somewhere readable"),
    }
    // Named as a directory of the sandbox, it's found and denied.
    let sandbox = Sandbox::builder()
        .deny_read(&vault)
        .writable(&ws)
        .read_only(&elsewhere)
        .working_dir(&ws)
        .build()
        .unwrap();
    assert!(!contents(&sandbox, &elsewhere.join("copy")).contains("secret"));
}

/// The agent preset hides the home directory but keeps the toolchains and caches in it.
#[test]
#[cfg(unix)]
fn test_agent_preset_hides_home_except_toolchains() {
    let ws = crate::common::sandbox_tempdir_in(env!("CARGO_TARGET_TMPDIR"));
    if crate::common::skip_if_unreachable_by_nobody(ws.path()) {
        return;
    }
    let home = home();
    let tag = format!("nanosandbox-test-{}", std::process::id());
    let in_home = home.join(format!(".{tag}"));
    let cache = home.join(".cache");
    let was_there = cache.is_dir();
    std::fs::create_dir_all(&cache).unwrap();
    let in_cache = cache.join(&tag);
    std::fs::write(&in_home, "home").unwrap();
    std::fs::write(&in_cache, "cache").unwrap();
    struct Cleanup(Vec<std::path::PathBuf>, Option<std::path::PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for p in &self.0 {
                let _ = std::fs::remove_file(p);
            }
            if let Some(d) = &self.1 {
                let _ = std::fs::remove_dir(d);
            }
        }
    }
    let _cleanup = Cleanup(
        vec![in_home.clone(), in_cache.clone()],
        (!was_there).then(|| cache.clone()),
    );

    let sandbox = Sandbox::agent_executor(ws.path()).build().unwrap();
    assert!(!can_read(&sandbox, &in_home), "home root readable");
    assert!(can_read(&sandbox, &in_cache), "~/.cache not readable");
    std::fs::write(ws.path().join("file"), "ws").unwrap();
    assert!(can_read(&sandbox, &ws.path().join("file")));

    let plain = Sandbox::builder().build().unwrap();
    assert!(can_read(&plain, &in_home));
}

/// With `report_denials()` the result says which paths the sandbox refused, and how.
#[test]
#[cfg(target_os = "macos")]
fn test_denied_paths_are_reported_when_asked() {
    let dir = crate::common::sandbox_tempdir_in(env!("CARGO_TARGET_TMPDIR"));
    let secret = dir.path().join("secret");
    std::fs::write(&secret, "s").unwrap();
    let ws = dir.path().join("ws");
    std::fs::create_dir(&ws).unwrap();
    let script = format!(
        "cat '{}' >/dev/null 2>&1; cat '{}' >/dev/null 2>&1; echo x > '{}/new' 2>/dev/null; echo done",
        secret.display(),
        secret.display(),
        dir.path().display()
    );

    // The reporting sandbox goes first: the log coalesces a denial repeated within about a
    // second, so a quiet run's denials just before could hide the reporting run's.
    let reporting = Sandbox::builder()
        .deny_read(&secret)
        .writable(&ws)
        .working_dir(&ws)
        .report_denials()
        .build()
        .unwrap();
    let r = reporting.run("sh", &["-c", &script]).unwrap();
    assert_eq!(r.stdout.trim(), "done");
    let real = |p: &std::path::Path| p.canonicalize().unwrap();
    let read = r
        .denied_paths
        .iter()
        .find(|d| d.path == real(&secret) && d.operation == "file-read-data")
        .unwrap_or_else(|| panic!("{:?}", r.denied_paths));
    assert!(read.count >= 1, "{read:?}");
    assert!(
        r.denied_paths.iter().any(|d| {
            d.path == real(dir.path()).join("new") && d.operation.starts_with("file-write")
        }),
        "{:?}",
        r.denied_paths
    );
    // Only this run's: the next one starts empty.
    let r = reporting.run("true", &[]).unwrap();
    assert!(r.denied_paths.is_empty(), "{:?}", r.denied_paths);

    // Without the flag, nothing is collected.
    let quiet = Sandbox::builder()
        .deny_read(&secret)
        .writable(&ws)
        .working_dir(&ws)
        .build()
        .unwrap();
    let r = quiet.run("sh", &["-c", &script]).unwrap();
    assert_eq!(r.stdout.trim(), "done");
    assert!(r.denied_paths.is_empty());
}

/// Naming home itself with hide_home asks for all of it: the grant wins over the hiding (the
/// credentials inside stay denied).
#[test]
#[cfg(unix)]
fn test_hide_home_with_home_itself_granted_keeps_home_readable() {
    let home = home();
    if crate::common::skip_if_unreachable_by_nobody(&home) {
        return;
    }
    let sandbox = Sandbox::builder()
        .hide_home()
        .read_only(&home)
        .build()
        .unwrap();
    let result = sandbox
        .run("sh", &["-c", &format!("ls {} > /dev/null", home.display())])
        .unwrap();
    assert_eq!(result.exit_code, 0, "{result:?}");
    let ssh = home.join(".ssh");
    if ssh.is_dir() {
        assert!(!can_read(&sandbox, &ssh));
    }
}

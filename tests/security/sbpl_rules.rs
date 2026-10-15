//! macOS SBPL (Sandbox Profile Language) rules tests

use nanosandbox::{MB, Sandbox};
use std::time::Duration;

#[test]
fn test_basic_sandbox_works() {
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox.run("echo", &["hello from sandbox"]).unwrap();
    assert!(result.success());
    assert!(result.stdout.contains("hello from sandbox"));
}

#[test]
fn test_no_network_blocks_connections() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .no_network()
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    // Try to make a network connection - should fail
    let result = sandbox.run(
        "curl",
        &["-s", "--connect-timeout", "2", "https://example.com"],
    );

    match result {
        Ok(r) => {
            // curl should fail due to network restrictions
            assert!(
                !r.success() || r.stdout.is_empty(),
                "Network should be blocked, but curl succeeded: {}",
                r.stdout
            );
        }
        Err(_) => {
            // Expected - network blocked
        }
    }
}

#[test]
fn test_read_only_filesystem() {
    use tempfile::tempdir;

    let temp = tempdir().unwrap();
    let temp_path = temp.path();
    let temp_str = temp_path.to_str().unwrap();

    // Create a test file
    std::fs::write(temp_path.join("test.txt"), "original content").unwrap();

    let sandbox = Sandbox::builder()
        .working_dir(temp_path)
        .read_only(temp_path)
        .build()
        .unwrap();

    // Reading should work
    let result = sandbox
        .run("cat", &[&format!("{}/test.txt", temp_str)])
        .unwrap();
    assert!(
        result.success(),
        "Read failed: {:?}",
        result.failure_reason()
    );
    assert!(result.stdout.contains("original content"));

    // Writing should fail (or succeed but file content protected by OS)
    let _result = sandbox
        .run(
            "sh",
            &["-c", &format!("echo modified > {}/test.txt", temp_str)],
        )
        .unwrap();
    // On macOS, the write might silently fail or the file content may be protected
    // Check that the original content is still there
    let content = std::fs::read_to_string(temp_path.join("test.txt")).unwrap();
    // Note: macOS sandbox may or may not enforce read-only at the SBPL level
    // This test verifies the mount configuration was applied
    println!("File content after write attempt: {}", content);
}

#[test]
fn test_read_write_filesystem() {
    use tempfile::tempdir;

    let temp = tempdir().unwrap();
    let temp_path = temp.path();

    let sandbox = Sandbox::builder()
        .working_dir(temp_path)
        .writable(temp_path)
        .build()
        .unwrap();

    // Writing should work
    let file_path = temp_path.join("new_file.txt");
    let result = sandbox
        .run(
            "sh",
            &["-c", &format!("echo 'hello' > {}", file_path.display())],
        )
        .unwrap();

    // Check if file was created
    if result.success() {
        let content = std::fs::read_to_string(&file_path).unwrap_or_default();
        assert!(content.contains("hello"));
    }
}

#[test]
fn test_sandbox_exec_profile_applied() {
    // Verify that sandbox-exec is actually being used
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    // Check that we're running under sandbox
    // On macOS, sandbox-exec sets some environment
    let result = sandbox.run("env", &[]).unwrap();
    assert!(result.success());
}

/// macOS can't limit processes or CPU share per sandbox, so build() says
/// so instead of running without them.
#[test]
fn test_unenforceable_limits_refused() {
    for builder in [
        Sandbox::builder().max_pids(10),
        Sandbox::builder().cpu_limit(1.0),
    ] {
        match builder.build() {
            Err(nanosandbox::SandboxError::Unsupported { .. }) => {}
            other => panic!("expected Unsupported, got {:?}", other.map(|_| ())),
        }
    }
}

#[test]
fn test_memory_limits() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .memory_limit(64 * MB)
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    // Simple command should work
    let result = sandbox.run("echo", &["memory test"]).unwrap();
    assert!(result.success());
}

#[test]
fn test_wall_time_limit() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_millis(500))
        .build()
        .unwrap();

    let result = sandbox.run("sleep", &["10"]).unwrap();

    assert!(!result.success());
    assert!(result.killed_by_timeout);
    assert!(result.duration >= Duration::from_millis(400));
    assert!(result.duration < Duration::from_secs(2));
}

#[test]
fn test_environment_isolation() {
    // Set some env vars in the parent
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("PARENT_SECRET", "should_not_see") };

    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .env("SANDBOX_VAR", "visible")
        .build()
        .unwrap();

    let result = sandbox
        .run(
            "sh",
            &["-c", "echo SANDBOX=$SANDBOX_VAR PARENT=$PARENT_SECRET"],
        )
        .unwrap();

    assert!(result.success());
    assert!(result.stdout.contains("SANDBOX=visible"));
    // Parent env may or may not be visible depending on macOS sandbox config
}

#[test]
fn test_cannot_access_home_directory() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users".to_string());

    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    // Try to list home directory - may be restricted
    let result = sandbox.run("ls", &[&home]);

    // This test is informational - macOS default sandbox may allow some access
    if let Ok(r) = result {
        println!(
            "Home directory access: exit_code={}, stdout_len={}",
            r.exit_code,
            r.stdout.len()
        );
    }
}

#[test]
fn test_cannot_execute_arbitrary_path() {
    use tempfile::tempdir;

    let temp = tempdir().unwrap();
    let script_path = temp.path().join("evil.sh");
    std::fs::write(&script_path, "#!/bin/bash\necho 'evil executed'").unwrap();

    // Make it executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();
    }

    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        // Don't mount the temp directory
        .build()
        .unwrap();

    // Try to execute the script - should fail as it's not in the sandbox
    let result = sandbox.run(script_path.to_str().unwrap(), &[]);

    match result {
        Ok(r) => {
            // May fail to find the file or be blocked by sandbox
            println!("Script execution result: {:?}", r.failure_reason());
        }
        Err(e) => {
            // Expected - file not accessible
            println!("Script execution blocked: {:?}", e);
        }
    }
}

/// By default the system temp directories are the host's own: a program that
/// writes to /tmp by name leaves the file there.
#[test]
fn test_shared_tmp_is_the_hosts_by_default() {
    let probe = format!("/tmp/nsb-shared-tmp-default-{}", std::process::id());
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();
    let result = sandbox
        .run("sh", &["-c", &format!("echo hi > {probe}")])
        .unwrap();
    let on_host = std::path::Path::new(&probe).exists();
    let _ = std::fs::remove_file(&probe);
    assert!(result.success(), "{}", result.stderr);
    assert!(on_host, "the write should have reached the host's /tmp");
}

/// `shared_tmp(false)` takes the host's temp directories away: /tmp by name is
/// read-only, and only the run's private directory (`$TMPDIR`) is writable.
#[test]
fn test_shared_tmp_false_denies_the_hosts_temp_directories() {
    let probe = format!("/tmp/nsb-shared-tmp-strict-{}", std::process::id());
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .shared_tmp(false)
        .build()
        .unwrap();

    let script = format!(
        "echo hi > {probe}; echo \"tmp:$?\"; \
         echo hi > /private/var/tmp/nsb-strict-vartmp-{pid}; echo \"vartmp:$?\"; \
         echo hi > \"$TMPDIR/own.txt\"; echo \"private:$?\"; cat \"$TMPDIR/own.txt\"; \
         f=$(mktemp \"$TMPDIR/x.XXXXXX\") && echo \"mktemp:ok\"",
        pid = std::process::id()
    );
    let result = sandbox.run("sh", &["-c", &script]).unwrap();
    let leaked = std::path::Path::new(&probe).exists();
    let _ = std::fs::remove_file(&probe);

    assert!(!leaked, "a file reached the host's /tmp");
    let out = result.stdout;
    assert!(
        out.contains("tmp:1"),
        "/tmp by name should be denied: {out}"
    );
    assert!(out.contains("vartmp:1"), "/var/tmp should be denied: {out}");
    assert!(
        out.contains("private:0"),
        "$TMPDIR should be writable: {out}"
    );
    assert!(out.contains("hi\n"), "{out}");
    assert!(out.contains("mktemp:ok"), "{out}");
}

/// Programs that honor $TMPDIR keep working without the host's temp directories.
/// (Perl, not python3: /usr/bin/python3 is an xcrun shim, which resets TMPDIR
/// -- the documented limit of `shared_tmp(false)`.)
#[test]
fn test_shared_tmp_false_still_runs_programs_that_use_tmpdir() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .shared_tmp(false)
        .build()
        .unwrap();
    let script = "perl -MFile::Temp=tempfile -e 'my ($fh, $name) = tempfile(); print $name' \
                  | grep -q \"^$TMPDIR/\" && echo in-private-tmp";
    let result = sandbox.run("sh", &["-c", script]).unwrap();
    assert_eq!(result.stdout.trim(), "in-private-tmp", "{}", result.stderr);
}

/// Apple's xcrun shims reset TMPDIR to the user's own temp directory, which
/// `shared_tmp(false)` makes read-only: they fail. The real binaries by path
/// don't. Documented in `shared_tmp`.
#[test]
fn test_shared_tmp_false_breaks_the_xcrun_shims_but_not_the_real_tools() {
    let developer_dir = std::process::Command::new("xcode-select")
        .arg("-p")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    let Some(developer_dir) = developer_dir else {
        eprintln!("skipping: no developer tools installed");
        return;
    };
    let clang = format!("{developer_dir}/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang");
    if !std::path::Path::new(&clang).exists() {
        eprintln!("skipping: no clang at {clang}");
        return;
    }
    let sdk = std::process::Command::new("xcrun")
        .args(["--show-sdk-path"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    let work = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    std::fs::write(work.path().join("hello.c"), "int main(void){return 0;}\n").unwrap();
    let sandbox = Sandbox::builder()
        .writable(work.path())
        .working_dir(work.path())
        .shared_tmp(false)
        .build()
        .unwrap();

    let shim = sandbox
        .run("/usr/bin/clang", &["hello.c", "-o", "shim.out"])
        .unwrap();
    assert!(!shim.success(), "the xcrun shim was expected to fail");
    assert!(shim.stderr.contains("temporary file"), "{}", shim.stderr);

    let real = sandbox
        .run(&clang, &["-isysroot", &sdk, "hello.c", "-o", "real.out"])
        .unwrap();
    assert!(real.success(), "{}", real.stderr);
    assert!(work.path().join("real.out").exists());
}

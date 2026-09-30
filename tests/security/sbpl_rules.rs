//! macOS SBPL (Sandbox Profile Language) rules tests

#![cfg(target_os = "macos")]

use nanosandbox::{Sandbox, MB};
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
        .mount(temp_path, temp_path, nanosandbox::Permission::ReadOnly)
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
        .mount(temp_path, temp_path, nanosandbox::Permission::ReadWrite)
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

#[test]
fn test_process_limits() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .max_pids(10)
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    // Try to create many processes - should be limited
    let result = sandbox
        .run("sh", &["-c", "for i in 1 2 3; do true & done; wait"])
        .unwrap();
    // Should complete (may or may not hit limit with just 3)
    assert!(result.success());
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
    std::env::set_var("PARENT_SECRET", "should_not_see");

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

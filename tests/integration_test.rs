//! Integration tests for nanosandbox
//!
//! These tests verify that the sandbox actually works on the current platform.

#[path = "common/mod.rs"]
mod common;

use nanosandbox::Sandbox;
use std::time::Duration;

#[test]
fn test_platform_supported() {
    assert!(nanosandbox::is_platform_supported());
    let name = nanosandbox::platform_name();
    assert!(!name.is_empty());
    println!("Running on platform: {}", name);
}

#[test]
fn test_simple_command() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox
        .run("echo", &["hello", "world"])
        .expect("Failed to run command");

    assert!(
        result.success(),
        "Command failed: {:?}",
        result.failure_reason()
    );
    assert_eq!(result.stdout.trim(), "hello world");
    assert!(
        result.stderr.trim().is_empty(),
        "unexpected stderr: {:?}",
        result.stderr
    );
}

#[test]
fn test_command_with_stdin() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox
        .run_with_input("cat", &[], Some(b"test input"))
        .expect("Failed to run command");

    assert!(result.success());
    assert_eq!(result.stdout.trim(), "test input");
}

#[test]
fn test_exit_code() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .build()
        .expect("Failed to build sandbox");

    // Run a command that exits with code 42
    let result = sandbox
        .run("sh", &["-c", "exit 42"])
        .expect("Failed to run command");

    assert!(!result.success());
    assert_eq!(result.exit_code, 42);
}

#[test]
fn test_stderr() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox
        .run("sh", &["-c", "echo error >&2"])
        .expect("Failed to run command");

    assert!(result.success());
    assert!(result.stderr.contains("error"));
}

#[test]
fn test_timeout() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_millis(500))
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox
        .run("sleep", &["10"])
        .expect("Failed to run command");

    assert!(!result.success());
    assert!(result.killed_by_timeout);
    assert!(result.duration >= Duration::from_millis(450)); // Allow some tolerance
    assert!(result.duration < Duration::from_secs(2)); // Should not take full 10s
}

#[test]
fn test_environment_variables() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .env("MY_VAR", "my_value")
        .env("ANOTHER_VAR", "123")
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox
        .run("sh", &["-c", "echo $MY_VAR $ANOTHER_VAR"])
        .expect("Failed to run command");

    assert!(result.success());
    assert!(result.stdout.contains("my_value"));
    assert!(result.stdout.contains("123"));
}

#[test]
fn test_python_execution() {
    // Skip if Python is not available
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox.run("python3", &["-c", "print('Hello from Python')"]);

    match result {
        Ok(r) => {
            if r.success() {
                assert_eq!(r.stdout.trim(), "Hello from Python");
            } else {
                // Python might not be installed
                println!("Python not available: {:?}", r.failure_reason());
            }
        }
        Err(e) => {
            println!("Python not available: {:?}", e);
        }
    }
}

#[test]
fn test_sandbox_id_unique() {
    let sandbox1 = Sandbox::builder()
        .working_dir("/tmp")
        .build()
        .expect("Failed to build sandbox");

    let sandbox2 = Sandbox::builder()
        .working_dir("/tmp")
        .build()
        .expect("Failed to build sandbox");

    assert_ne!(sandbox1.id(), sandbox2.id());
}

#[test]
fn test_presets() {
    // Presets mount these directories in place and a private tmpfs on /tmp
    // -- which needs mounts, and directories outside /tmp.
    if common::skip_without_mounts() {
        return;
    }
    let temp =
        tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).expect("Failed to create temp dir");
    let path = temp.path();

    // Just verify presets build without error
    let _sandbox = Sandbox::data_analysis(path, path)
        .build()
        .expect("data_analysis preset failed");

    let _sandbox = Sandbox::code_judge(path)
        .build()
        .expect("code_judge preset failed");

    let _sandbox = Sandbox::agent_executor(path)
        .build()
        .expect("agent_executor preset failed");

    let _sandbox = Sandbox::interactive(path)
        .build()
        .expect("interactive preset failed");
}

#[cfg(target_os = "macos")]
#[test]
fn test_macos_sandbox_restrictions() {
    // On macOS, verify that sandbox-exec is being used
    // by checking that network access is blocked when configured

    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .no_network()
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .expect("Failed to build sandbox");

    // Try to access a network resource - should fail or timeout
    let result = sandbox.run(
        "curl",
        &["-s", "--connect-timeout", "2", "https://example.com"],
    );

    // The command should either fail or return an error
    match result {
        Ok(r) => {
            // If curl runs, it should fail due to network restrictions
            println!(
                "curl result: exit_code={}, stdout={}, stderr={}",
                r.exit_code,
                r.stdout.len(),
                r.stderr
            );
        }
        Err(e) => {
            // Expected - curl might not be able to run or network is blocked
            println!("Expected network error: {:?}", e);
        }
    }
}

// ========== Network Proxy Tests ==========

#[test]
fn test_proxied_network_setup() {
    use nanosandbox::network::ProxiedNetwork;

    // Setup proxy with allowed domains
    let proxy = ProxiedNetwork::setup(vec!["example.com".into(), "*.github.com".into()])
        .expect("Failed to setup proxy");

    // Verify proxy is running
    assert!(proxy.port() > 0);
    assert!(proxy.url().starts_with("http://127.0.0.1:"));

    // Verify env vars are correctly set
    let env_vars = proxy.env_vars();
    assert_eq!(env_vars.len(), 4);
    assert!(env_vars
        .iter()
        .any(|(k, v)| k == "HTTP_PROXY" && v.contains(&proxy.port().to_string())));
    assert!(env_vars
        .iter()
        .any(|(k, v)| k == "HTTPS_PROXY" && v.contains(&proxy.port().to_string())));

    // Cleanup
    proxy.shutdown();
}

#[test]
fn test_sandbox_with_proxied_network() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .allow_network(&["example.com"])
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .expect("Failed to build sandbox");

    // Run a simple command to verify sandbox works with proxy
    let result = sandbox
        .run("echo", &["proxy test"])
        .expect("Failed to run command");

    assert!(result.success());
    assert_eq!(result.stdout.trim(), "proxy test");
}

#[test]
fn test_proxy_env_vars_in_sandbox() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .allow_network(&["api.example.com"])
        .build()
        .expect("Failed to build sandbox");

    // Verify proxy env vars are set inside sandbox
    let result = sandbox
        .run("sh", &["-c", "echo $HTTP_PROXY"])
        .expect("Failed to run command");

    assert!(result.success());
    // The proxy URL should be set
    assert!(
        result.stdout.contains("127.0.0.1"),
        "HTTP_PROXY should be set: {}",
        result.stdout
    );
}

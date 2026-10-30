//! Integration tests: the sandbox works on the current platform.
#![cfg_attr(
    not(unix),
    allow(dead_code, unused_imports, unused_variables, unused_mut)
)]

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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
fn test_exit_code() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox
        .run("sh", &["-c", "exit 42"])
        .expect("Failed to run command");

    assert!(!result.success());
    assert_eq!(result.exit_code, 42);
}

#[test]
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
fn test_python_execution() {
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
                println!("Python not available: {:?}", r.failure_reason());
            }
        }
        Err(e) => {
            println!("Python not available: {:?}", e);
        }
    }
}

#[test]
#[cfg(unix)]
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
#[cfg(unix)]
fn test_presets() {
    // Presets mount these directories in place and a private tmpfs on /tmp
    // -- which needs mounts, and directories outside /tmp.
    if common::skip_without_userns_privileges() {
        return;
    }
    let temp = common::sandbox_tempdir_in(env!("CARGO_TARGET_TMPDIR"));
    let path = temp.path();

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
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .no_network()
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox.run(
        "curl",
        &["-s", "--connect-timeout", "2", "https://example.com"],
    );

    match result {
        Ok(r) => {
            println!(
                "curl result: exit_code={}, stdout={}, stderr={}",
                r.exit_code,
                r.stdout.len(),
                r.stderr
            );
        }
        Err(e) => {
            println!("Expected network error: {:?}", e);
        }
    }
}

#[test]
fn test_proxied_network_setup() {
    use nanosandbox::network::{ProxiedNetwork, ProxyRules};

    let mut proxy = ProxiedNetwork::setup(ProxyRules {
        allowed: vec!["example.com".into(), "*.github.com:443".into()],
        ..Default::default()
    })
    .expect("Failed to setup proxy");

    let env_vars = ProxiedNetwork::env_vars(4321);
    for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        assert!(
            env_vars
                .iter()
                .any(|(k, v)| k == key && v == "http://127.0.0.1:4321")
        );
    }
    for key in ["ALL_PROXY", "all_proxy"] {
        assert!(
            env_vars
                .iter()
                .any(|(k, v)| k == key && v == "socks5h://127.0.0.1:4321")
        );
    }

    proxy.shutdown();
}

#[test]
#[cfg(unix)]
fn test_sandbox_with_proxied_network() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .allow_network(&["example.com"])
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox
        .run("echo", &["proxy test"])
        .expect("Failed to run command");

    assert!(result.success());
    assert_eq!(result.stdout.trim(), "proxy test");
}

#[test]
#[cfg(unix)]
fn test_proxy_env_vars_in_sandbox() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .allow_network(&["api.example.com"])
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox
        .run("sh", &["-c", "echo $HTTP_PROXY"])
        .expect("Failed to run command");

    assert!(result.success());
    assert!(
        result.stdout.contains("127.0.0.1"),
        "HTTP_PROXY should be set: {}",
        result.stdout
    );

    // ... but loopback isn't sent through it: by default the proxy only
    // refuses it.
    let result = sandbox
        .run("sh", &["-c", "echo $NO_PROXY"])
        .expect("Failed to run command");
    assert!(
        result.stdout.contains("127.0.0.1") && result.stdout.contains("localhost"),
        "NO_PROXY should name loopback: {}",
        result.stdout
    );
}

/// With private destinations allowed, the host's local services are reached
/// through the proxy, so loopback must not be on NO_PROXY.
#[test]
#[cfg(unix)]
fn test_loopback_goes_through_the_proxy_when_private_destinations_are_allowed() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .allow_network(&["api.example.com"])
        .allow_private_destinations()
        .build()
        .expect("Failed to build sandbox");
    let result = sandbox
        .run("sh", &["-c", "echo \"[${NO_PROXY-unset}]\""])
        .expect("Failed to run command");
    assert_eq!(result.stdout.trim(), "[unset]");
}

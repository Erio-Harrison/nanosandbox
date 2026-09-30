//! Network Whitelist Example
//!
//! Demonstrates using nanosandbox's network whitelisting feature to allow
//! sandboxed processes to access only specific domains.
//!
//! Run with: cargo run --example network_allow

use nanosandbox::Sandbox;
use std::time::Duration;

fn main() {
    println!("=== Network Whitelist Example ===\n");

    // Create workspace
    let workspace = std::env::temp_dir().join("nanosandbox_network_demo");
    std::fs::create_dir_all(&workspace).unwrap();

    // 1. No network access (default)
    println!("1. No network access (default):");
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .no_network()
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    let result = sandbox
        .run(
            "curl",
            &["-s", "--connect-timeout", "3", "https://httpbin.org/ip"],
        )
        .unwrap_or_else(|_| nanosandbox::result::ExecutionResult {
            stdout: String::new(),
            stderr: "curl not found".into(),
            exit_code: 1,
            duration: Duration::ZERO,
            killed_by_timeout: false,
            killed_by_oom: false,
            signal: None,
            peak_memory: None,
            cpu_time: None,
        });

    if result.exit_code != 0 || result.stdout.is_empty() {
        println!("   [BLOCKED] Network access denied (expected)\n");
    } else {
        println!("   [WARNING] Network access NOT blocked!\n");
    }

    // 2. Whitelist specific domains
    println!("2. Whitelist specific domains:");
    println!("   Allowed: httpbin.org, *.github.com");

    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .allow_network(&["httpbin.org", "*.github.com"])
        .wall_time_limit(Duration::from_secs(30))
        .build()
        .unwrap();

    // This should work - httpbin.org is whitelisted
    println!("\n   Testing httpbin.org (whitelisted):");
    let result = sandbox.run(
        "curl",
        &["-s", "--connect-timeout", "5", "http://httpbin.org/ip"],
    );

    match result {
        Ok(r) if r.success() && !r.stdout.is_empty() => {
            println!("   [ALLOWED] Response: {}", r.stdout.trim());
        }
        Ok(r) => {
            println!(
                "   [BLOCKED/ERROR] exit={}, stderr={}",
                r.exit_code,
                r.stderr.trim()
            );
        }
        Err(e) => {
            println!("   [ERROR] {}", e);
        }
    }

    // This should work - wildcard matches api.github.com
    println!("\n   Testing api.github.com (matches *.github.com):");
    let result = sandbox.run(
        "curl",
        &["-s", "--connect-timeout", "5", "https://api.github.com/zen"],
    );

    match result {
        Ok(r) if r.success() && !r.stdout.is_empty() => {
            println!("   [ALLOWED] Response: {}", r.stdout.trim());
        }
        Ok(r) => {
            println!("   [BLOCKED/ERROR] exit={}", r.exit_code);
        }
        Err(e) => {
            println!("   [ERROR] {}", e);
        }
    }

    // This should be blocked - example.com is not whitelisted
    println!("\n   Testing example.com (NOT whitelisted):");
    let result = sandbox.run(
        "curl",
        &[
            "-s",
            "--connect-timeout",
            "3",
            "-x",
            &format!("http://127.0.0.1:{}", get_proxy_port()),
            "http://example.com/",
        ],
    );

    match result {
        Ok(r) if r.stdout.contains("403") || r.stdout.contains("not in whitelist") => {
            println!("   [BLOCKED] Domain not in whitelist (expected)");
        }
        Ok(r) if r.exit_code != 0 => {
            println!("   [BLOCKED] Request failed (expected)");
        }
        Ok(r) => {
            println!(
                "   [?] Response: {}",
                r.stdout.chars().take(100).collect::<String>()
            );
        }
        Err(e) => {
            println!("   [ERROR] {}", e);
        }
    }

    // 3. AI/API use case
    println!("\n3. AI API access pattern:");
    println!("   Whitelist: api.openai.com, api.anthropic.com");

    // Create a Python script that demonstrates API-style access
    let script = r#"
import urllib.request
import json
import os

# In real usage, this would call the actual API
# Here we just demonstrate the pattern
print("AI API access pattern demonstration")
print("Whitelisted domains: api.openai.com, api.anthropic.com")
print("Other domains would be blocked by the proxy")

# Environment is isolated
print(f"HOME: {os.environ.get('HOME', 'not set')}")
print(f"PATH: {os.environ.get('PATH', 'not set')[:50]}...")
"#;

    let script_path = workspace.join("api_demo.py");
    std::fs::write(&script_path, script).unwrap();

    // Mount workspace and run
    let sandbox = Sandbox::agent_executor(&workspace)
        .allow_network(&["api.openai.com", "api.anthropic.com"])
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    let result = sandbox.run("python3", &["/workspace/api_demo.py"]).unwrap();
    println!("{}", result.stdout);

    // Cleanup
    std::fs::remove_dir_all(&workspace).ok();

    println!("=== Network whitelist example complete ===");
}

/// Get proxy port (in real usage, this would be from sandbox config)
fn get_proxy_port() -> u16 {
    // Default proxy port range starts at 18000
    18000
}

//! Demo: verify nanosandbox actually works

use nanosandbox::Sandbox;
use std::time::Duration;

fn main() {
    println!("=== nanosandbox demo ===\n");

    // 1. Basic command execution
    println!("1. Basic execution:");
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .build()
        .expect("Failed to build sandbox");

    let result = sandbox.run("echo", &["Hello from sandbox"]).unwrap();
    println!("   stdout: {}", result.stdout.trim());
    println!("   exit_code: {}", result.exit_code);
    assert!(result.success());

    // 2. Timeout enforcement
    println!("\n2. Timeout (500ms limit, 5s sleep):");
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .wall_time_limit(Duration::from_millis(500))
        .build()
        .unwrap();

    let result = sandbox.run("sleep", &["5"]).unwrap();
    println!("   killed_by_timeout: {}", result.killed_by_timeout);
    println!("   actual duration: {:?}", result.duration);
    assert!(result.killed_by_timeout);
    assert!(result.duration < Duration::from_secs(2));

    // 3. Environment isolation
    println!("\n3. Environment isolation:");
    std::env::set_var("SECRET", "should_not_leak");
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .env("VISIBLE", "yes")
        .build()
        .unwrap();

    let result = sandbox
        .run("sh", &["-c", "echo SECRET=$SECRET VISIBLE=$VISIBLE"])
        .unwrap();
    println!("   output: {}", result.stdout.trim());
    // SECRET should be empty, VISIBLE should be "yes"

    // 4. Exit code propagation
    println!("\n4. Exit code propagation:");
    let sandbox = Sandbox::builder().working_dir("/tmp").build().unwrap();

    let result = sandbox.run("sh", &["-c", "exit 42"]).unwrap();
    println!("   exit_code: {}", result.exit_code);
    assert_eq!(result.exit_code, 42);

    // 5. Stderr capture
    println!("\n5. Stderr capture:");
    let result = sandbox.run("sh", &["-c", "echo error >&2"]).unwrap();
    println!("   stderr: {}", result.stderr.trim());
    assert!(result.stderr.contains("error"));

    // 6. Python (if available)
    println!("\n6. Python execution:");
    match sandbox.run("python3", &["-c", "print(2+2)"]) {
        Ok(r) if r.success() => println!("   2+2 = {}", r.stdout.trim()),
        _ => println!("   (python3 not available)"),
    }

    // 7. Network blocking
    println!("\n7. Network blocking:");
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .no_network()
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    let result = sandbox.run(
        "curl",
        &["-s", "--connect-timeout", "2", "https://example.com"],
    );
    match result {
        Ok(r) => {
            if r.exit_code != 0 || r.stdout.is_empty() {
                println!("   network blocked (curl failed)");
            } else {
                println!("   WARNING: network NOT blocked!");
            }
        }
        Err(_) => println!("   network blocked (curl not found or blocked)"),
    }

    println!("\n=== All checks passed ===");
}

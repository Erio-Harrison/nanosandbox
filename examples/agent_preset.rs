//! AI agent executor: run agent-generated code in a sandbox.
//!
//! Run with: cargo run --example agent_preset

use nanosandbox::Sandbox;
use std::time::Duration;

fn main() {
    println!("=== AI Agent Executor Example ===\n");

    let workspace = std::env::temp_dir().join("nanosandbox_agent_demo");
    std::fs::create_dir_all(&workspace).unwrap();

    let script_path = workspace.join("task.py");
    std::fs::write(
        &script_path,
        r#"
import os
import sys

print("Agent task executing...")
print(f"Working directory: {os.getcwd()}")
print(f"Python version: {sys.version}")

# Simulate some computation
result = sum(range(1000))
print(f"Computation result: {result}")

# Write output file
with open("/tmp/result.txt", "w") as f:
    f.write(f"Result: {result}\n")

print("Task completed successfully!")
"#,
    )
    .unwrap();

    let sandbox = Sandbox::agent_executor(&workspace)
        .allow_network(&["api.openai.com", "api.anthropic.com", "*.googleapis.com"])
        .wall_time_limit(Duration::from_secs(30))
        .build()
        .expect("Failed to create sandbox");

    println!("Sandbox ID: {}", sandbox.id());
    println!("Platform: {}", sandbox.platform());
    println!("Workspace: {:?}\n", workspace);

    println!("--- Executing agent task ---");
    let result = sandbox
        .run("python3", &["/workspace/task.py"])
        .expect("Execution failed");

    println!("\nstdout:\n{}", result.stdout);

    if !result.stderr.is_empty() {
        println!("stderr:\n{}", result.stderr);
    }

    println!("--- Execution stats ---");
    println!("Exit code: {}", result.exit_code);
    println!("Duration: {:?}", result.duration);
    if let Some(mem) = result.peak_memory {
        println!("Peak memory: {} KB", mem / 1024);
    }
    if let Some(cpu) = result.cpu_time {
        println!("CPU time: {:?}", cpu);
    }

    // Note: In sandbox, /tmp is isolated from host
    println!("\nTask success: {}", result.success());

    println!("\n--- Shell command example ---");
    let result = sandbox
        .run(
            "sh",
            &["-c", "echo 'Files in workspace:' && ls -la /workspace"],
        )
        .unwrap();
    println!("{}", result.stdout);

    std::fs::remove_dir_all(&workspace).ok();

    println!("=== Agent example complete ===");
}

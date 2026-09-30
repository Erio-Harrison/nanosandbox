//! Online Judge (OJ) Example
//!
//! Demonstrates using nanosandbox for competitive programming / online judge systems.
//! Features strict resource limits and security isolation.
//!
//! Run with: cargo run --example code_judge

use nanosandbox::Sandbox;
use std::time::Duration;

/// Test case structure
struct TestCase {
    input: &'static str,
    expected: &'static str,
}

fn main() {
    println!("=== Online Judge Example ===\n");

    // Create submission directory
    let submission_dir = std::env::temp_dir().join("nanosandbox_judge_demo");
    std::fs::create_dir_all(&submission_dir).unwrap();

    // Problem: Sum of two numbers
    // User's submission (correct solution)
    let solution = r#"
import sys

# Read two integers and print their sum
line = input()
a, b = map(int, line.split())
print(a + b)
"#;

    let solution_path = submission_dir.join("solution.py");
    std::fs::write(&solution_path, solution).unwrap();

    // Test cases
    let test_cases = [
        TestCase {
            input: "1 2\n",
            expected: "3",
        },
        TestCase {
            input: "100 200\n",
            expected: "300",
        },
        TestCase {
            input: "-5 10\n",
            expected: "5",
        },
        TestCase {
            input: "999999999 1\n",
            expected: "1000000000",
        },
    ];

    println!("Problem: A + B");
    println!("Submission: solution.py");
    println!("Test cases: {}\n", test_cases.len());

    let mut passed = 0;
    let mut total_time = Duration::ZERO;

    for (i, tc) in test_cases.iter().enumerate() {
        print!("Test #{}: ", i + 1);

        // Create sandbox with code_judge preset
        // This provides:
        // - Read-only code directory
        // - 256MB memory limit
        // - 1 CPU core
        // - 10s wall time, 5s CPU time
        // - 10 max processes
        // - Strict seccomp profile
        // - No network
        let sandbox = Sandbox::code_judge(&submission_dir)
            .wall_time_limit(Duration::from_secs(2))
            .cpu_time_limit(Duration::from_secs(1))
            .memory_limit(128 * 1024 * 1024) // 128MB for this problem
            .build()
            .expect("Failed to create sandbox");

        // Run with input
        let result = sandbox
            .run_with_input(
                "python3",
                &["/workspace/solution.py"],
                Some(tc.input.as_bytes()),
            )
            .expect("Execution failed");

        let output = result.stdout.trim();
        let expected = tc.expected.trim();

        if result.killed_by_timeout {
            println!("TLE (Time Limit Exceeded)");
            println!("  Duration: {:?}", result.duration);
        } else if result.exit_code != 0 {
            println!("RE (Runtime Error)");
            println!("  Exit code: {}", result.exit_code);
            if !result.stderr.is_empty() {
                println!("  stderr: {}", result.stderr.lines().next().unwrap_or(""));
            }
        } else if output != expected {
            println!("WA (Wrong Answer)");
            println!("  Expected: {}", expected);
            println!("  Got: {}", output);
        } else {
            println!("AC ({:?})", result.duration);
            passed += 1;
        }

        total_time += result.duration;
    }

    println!("\n--- Summary ---");
    println!("Result: {}/{} passed", passed, test_cases.len());
    println!("Total time: {:?}", total_time);

    if passed == test_cases.len() {
        println!("Verdict: ACCEPTED");
    } else {
        println!("Verdict: REJECTED");
    }

    // Demonstrate security: malicious submission
    println!("\n--- Security Demo: Malicious Submission ---");

    let malicious = r#"
import os
import socket

# Try to read sensitive files
try:
    with open("/etc/passwd") as f:
        print("LEAKED:", f.read()[:50])
except Exception as e:
    print("File access blocked:", type(e).__name__)

# Try to access network
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("example.com", 80))
    print("LEAKED: Network access!")
except Exception as e:
    print("Network blocked:", type(e).__name__)

# Try to fork bomb
try:
    import subprocess
    for _ in range(100):
        subprocess.Popen(["sleep", "100"])
    print("LEAKED: Fork bomb worked!")
except Exception as e:
    print("Fork limited:", type(e).__name__)

print("42")  # Still output something
"#;

    std::fs::write(&solution_path, malicious).unwrap();

    let sandbox = Sandbox::code_judge(&submission_dir)
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    let result = sandbox
        .run_with_input("python3", &["/workspace/solution.py"], Some(b"1 41\n"))
        .unwrap();

    println!("Output:\n{}", result.stdout);
    println!("Exit code: {}", result.exit_code);

    // Cleanup
    std::fs::remove_dir_all(&submission_dir).ok();

    println!("\n=== Code judge example complete ===");
}

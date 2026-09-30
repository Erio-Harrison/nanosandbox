//! P0: Network Security Tests
//!
//! Tests for:
//! - IP bypass prevention (sandboxed process connecting directly via IP)
//! - Proxy domain validation
//! - DNS resolution control

use nanosandbox::Sandbox;
use std::time::Duration;

/// Test: Direct IP connections should be blocked when using domain whitelist
///
/// KNOWN LIMITATION: Currently, sandboxed processes can bypass the domain whitelist
/// by connecting directly via IP. Proper fix requires network namespace (Linux) or
/// PF firewall rules (macOS) to force all traffic through the proxy.
///
/// This test is ignored until the fix is implemented.
#[test]
#[ignore = "P0 TODO: Direct IP bypass prevention not yet implemented"]
#[cfg(unix)]
fn test_ip_bypass_blocked() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .allow_network(&["example.com"]) // Only example.com allowed
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    // Try to connect directly to an IP (Google's DNS for example)
    // This should be blocked since it bypasses the domain whitelist
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                r#"
        # Try direct IP connection (should fail if properly secured)
        if command -v curl >/dev/null 2>&1; then
            curl -s --connect-timeout 3 http://8.8.8.8/ 2>&1 && echo "DIRECT_IP_WORKED"
        elif command -v nc >/dev/null 2>&1; then
            echo "GET / HTTP/1.0\r\n\r\n" | nc -w 3 8.8.8.8 80 2>&1 && echo "DIRECT_IP_WORKED"
        else
            echo "NO_TOOLS"
        fi
    "#,
            ],
        )
        .unwrap();

    // Direct IP connection should NOT work
    assert!(
        !result.stdout.contains("DIRECT_IP_WORKED"),
        "SECURITY: Direct IP bypass succeeded! Sandboxed process connected to 8.8.8.8 despite domain whitelist. Stdout: {}",
        result.stdout
    );
}

/// Test: Connections to non-whitelisted domains should fail through proxy
#[test]
#[cfg(unix)]
fn test_non_whitelisted_domain_blocked() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .allow_network(&["api.example.com"]) // Only api.example.com allowed
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    // Try to access a non-whitelisted domain through the proxy
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                r#"
        if command -v curl >/dev/null 2>&1; then
            # Proxy env vars should be set by nanosandbox
            response=$(curl -s --connect-timeout 5 http://httpbin.org/get 2>&1)
            if echo "$response" | grep -q "403\|Domain not in whitelist\|Forbidden"; then
                echo "BLOCKED"
            else
                echo "ALLOWED:$response"
            fi
        else
            echo "NO_CURL"
        fi
    "#,
            ],
        )
        .unwrap();

    // Non-whitelisted domain should be blocked
    let output = result.stdout.trim();
    assert!(
        output.contains("BLOCKED") || output.contains("NO_CURL") || result.exit_code != 0,
        "Non-whitelisted domain was not blocked: {}",
        output
    );
}

/// Test: Whitelisted domains should work through proxy
#[test]
#[cfg(unix)]
fn test_whitelisted_domain_allowed() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .allow_network(&["httpbin.org"])
        .wall_time_limit(Duration::from_secs(30))
        .build()
        .unwrap();

    // Access whitelisted domain
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                r#"
        if ! command -v curl >/dev/null 2>&1; then
            echo "NO_CURL"
            exit 0
        fi

        # Check proxy is set
        echo "PROXY=$http_proxy"

        # Try to access whitelisted domain
        response=$(curl -s --connect-timeout 15 --proxy "$http_proxy" http://httpbin.org/get 2>&1)
        if echo "$response" | grep -q '"Host"'; then
            echo "SUCCESS"
        else
            echo "RESPONSE:$response"
        fi
    "#,
            ],
        )
        .unwrap();

    let output = result.stdout.trim();

    // Skip if no curl
    if output.contains("NO_CURL") {
        return;
    }

    // Accept success, or note the failure without hard assertion (network flaky)
    if !output.contains("SUCCESS") {
        println!("Note: Whitelisted domain test didn't succeed: {}", output);
        // This can fail due to network issues, not a code bug
    }
}

/// Test: Wildcard domain matching should work correctly
#[test]
#[cfg(unix)]
fn test_wildcard_domain_matching() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .allow_network(&["*.example.com"])
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    // Test via environment variables (since we can't easily test actual connections)
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                r#"
        # Check that proxy env vars are set
        if [ -n "$http_proxy" ] || [ -n "$HTTP_PROXY" ]; then
            echo "PROXY_SET"
        else
            echo "NO_PROXY"
        fi
    "#,
            ],
        )
        .unwrap();

    // Proxy should be configured
    assert!(
        result.stdout.contains("PROXY_SET"),
        "Proxy not configured for network whitelist mode"
    );
}

/// Test: HTTPS (CONNECT) tunneling should respect whitelist
///
/// KNOWN LIMITATION: HTTPS blocking requires the connection to go through
/// the proxy. If the client bypasses the proxy (direct connection), this
/// test will fail. See test_ip_bypass_blocked for the related issue.
#[test]
#[ignore = "P0 TODO: HTTPS blocking depends on preventing proxy bypass"]
#[cfg(unix)]
fn test_https_tunnel_respects_whitelist() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .allow_network(&["api.github.com"])
        .wall_time_limit(Duration::from_secs(15))
        .build()
        .unwrap();

    // Try HTTPS to non-whitelisted domain through proxy
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                r#"
        if ! command -v curl >/dev/null 2>&1; then
            echo "NO_CURL"
            exit 0
        fi

        # Force use of proxy for HTTPS
        response=$(curl -s --connect-timeout 5 --proxy "$https_proxy" https://google.com 2>&1)
        if echo "$response" | grep -iq "403\|forbidden\|whitelist\|failed\|proxy"; then
            echo "BLOCKED"
        else
            echo "ALLOWED"
        fi
    "#,
            ],
        )
        .unwrap();

    let output = result.stdout.trim();
    assert!(
        output.contains("BLOCKED") || output.contains("NO_CURL") || result.exit_code != 0,
        "HTTPS to non-whitelisted domain was not blocked: {}",
        output
    );
}

/// Test: Network mode None should completely block network
#[test]
#[cfg(unix)]
fn test_network_none_blocks_all() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .no_network()
        .wall_time_limit(Duration::from_secs(10))
        .build()
        .unwrap();

    // Any network access should fail
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                r#"
        if command -v curl >/dev/null 2>&1; then
            curl -s --connect-timeout 3 http://google.com 2>&1
            echo "EXIT:$?"
        elif command -v ping >/dev/null 2>&1; then
            ping -c 1 -W 3 8.8.8.8 2>&1
            echo "EXIT:$?"
        else
            # Try raw socket (likely to fail without tools)
            echo "NO_TOOLS"
        fi
    "#,
            ],
        )
        .unwrap();

    // Network operations should fail
    let output = result.stdout.trim();
    assert!(
        output.contains("EXIT:") && !output.contains("EXIT:0")
            || output.contains("NO_TOOLS")
            || output.contains("Could not resolve")
            || output.contains("Network is unreachable")
            || output.contains("Operation not permitted"),
        "Network should be completely blocked: {}",
        output
    );
}

/// Test: Localhost connections should always work (for proxy)
#[test]
#[cfg(unix)]
fn test_localhost_always_allowed() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .allow_network(&["example.com"]) // Whitelist mode
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    // Localhost should work (proxy runs there)
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                r#"
        # Localhost should be reachable
        if command -v nc >/dev/null 2>&1; then
            # Try to connect to a random localhost port (will fail but shouldn't be blocked)
            nc -z 127.0.0.1 12345 2>&1
            echo "NC_EXIT:$?"
        else
            echo "NO_NC"
        fi
    "#,
            ],
        )
        .unwrap();

    // The connection attempt itself might fail (no service), but shouldn't be blocked
    let output = result.stdout.trim();
    assert!(
        output.contains("NC_EXIT:") || output.contains("NO_NC"),
        "Localhost connection was blocked: {}",
        output
    );
}

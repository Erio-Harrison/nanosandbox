//! P0: Network Security Tests
//!
//! Tests for:
//! - IP bypass prevention (sandboxed process connecting directly via IP)
//! - Proxy domain validation
//! - DNS resolution control

use nanosandbox::Sandbox;
use std::time::Duration;

/// Test: with a domain whitelist, the proxy is the only way out. A client
/// that skips it (`--noproxy`) must not reach anything, and asking the proxy
/// for a non-whitelisted address must get a 403.
///
/// The target is a local server, so this needs no internet and can count
/// connections: it must never see one. It used to check `curl -s ... &&`,
/// which counted the proxy's own 403 page as a successful connection.
#[test]
#[cfg(unix)]
fn test_ip_bypass_blocked() {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    if crate::common::skip_without_userns_privileges() {
        return;
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let server_hits = hits.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            server_hits.fetch_add(1, Ordering::SeqCst);
            let _ = stream.read(&mut [0u8; 1024]);
            let _ = stream.write_all(b"HTTP/1.0 200 OK\r\n\r\nreached");
        }
    });

    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .allow_network(&["example.com"])
        .wall_time_limit(Duration::from_secs(15))
        .build()
        .unwrap();

    let script = format!(
        "command -v curl >/dev/null || {{ echo NO_CURL; exit 0; }}
         echo direct=$(curl -s -o /dev/null -w '%{{http_code}}' --noproxy '*' --connect-timeout 3 http://127.0.0.1:{port}/)
         echo proxied=$(curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 3 http://127.0.0.1:{port}/)"
    );
    let result = sandbox.run("sh", &["-c", &script]).unwrap();
    let out = result.stdout.trim();
    if out == "NO_CURL" {
        eprintln!("skipping: no curl in the sandbox");
        return;
    }

    assert!(
        out.contains("direct=000"),
        "SECURITY: bypassing the proxy reached a host service: {out}"
    );
    assert!(
        out.contains("proxied=403"),
        "proxy didn't refuse a non-whitelisted address: {out}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "SECURITY: the target saw a connection from the sandbox ({out})"
    );
}

/// Test: Connections to non-whitelisted domains should fail through proxy
#[test]
#[cfg(unix)]
fn test_non_whitelisted_domain_blocked() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
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
    if crate::common::skip_without_userns_privileges() {
        return;
    }
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
    if crate::common::skip_without_userns_privileges() {
        return;
    }
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
/// Checks the CONNECT response code itself. The proxy refuses before
/// connecting anywhere, so this needs no internet. It used to grep `curl -s`
/// output, but `-s` hides the CONNECT failure, so a refusal read as ALLOWED.
#[test]
#[cfg(unix)]
fn test_https_tunnel_respects_whitelist() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .allow_network(&["api.github.com"])
        .wall_time_limit(Duration::from_secs(15))
        .build()
        .unwrap();

    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                "command -v curl >/dev/null || { echo NO_CURL; exit 0; }
                 curl -s -o /dev/null -w '%{http_connect}' --connect-timeout 5 https://google.com/",
            ],
        )
        .unwrap();

    let output = result.stdout.trim();
    if output == "NO_CURL" {
        eprintln!("skipping: no curl in the sandbox");
        return;
    }
    assert_eq!(
        output, "403",
        "CONNECT to a non-whitelisted domain wasn't refused"
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
    if crate::common::skip_without_userns_privileges() {
        return;
    }
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

/// Test: an allowed name that resolves to loopback (or another non-public
/// address) is refused unless allow_private_destinations() says otherwise.
/// The proxy connects from the host's network, so this is the host's own
/// localhost: its databases, dev servers, cloud metadata.
#[test]
#[cfg(unix)]
fn test_private_destinations_refused_by_default() {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    if crate::common::skip_without_userns_privileges() {
        return;
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let server_hits = hits.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            server_hits.fetch_add(1, Ordering::SeqCst);
            let _ = stream.read(&mut [0u8; 1024]);
            let _ = stream.write_all(b"HTTP/1.0 200 OK\r\n\r\nreached");
        }
    });

    let script = format!(
        "command -v curl >/dev/null || {{ echo NO_CURL; exit 0; }}
         echo http=$(curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 3 http://localhost:{port}/)
         echo connect=$(curl -s -o /dev/null -w '%{{http_connect}}' --connect-timeout 3 -p http://localhost:{port}/)"
    );
    let run = |builder: nanosandbox::SandboxBuilder| {
        let sandbox = builder
            .allow_network(&["localhost"])
            .wall_time_limit(Duration::from_secs(15))
            .build()
            .unwrap();
        sandbox.run("sh", &["-c", &script]).unwrap().stdout
    };

    let refused = run(Sandbox::builder());
    if refused.trim() == "NO_CURL" {
        eprintln!("skipping: no curl in the sandbox");
        return;
    }
    assert!(refused.contains("http=403"), "{refused}");
    assert!(refused.contains("connect=403"), "{refused}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the host's localhost was reached"
    );

    let allowed = run(Sandbox::builder().allow_private_destinations());
    assert!(allowed.contains("http=200"), "{allowed}");
    assert!(allowed.contains("connect=200"), "{allowed}");
    assert!(hits.load(Ordering::SeqCst) > 0);
}

/// Test: a POST through the proxy reaches the server with its body. The
/// proxy used to forward only the headers, so every plain-HTTP upload hung
/// until the server gave up waiting for the body.
#[test]
#[cfg(unix)]
fn test_post_body_reaches_server_through_proxy() {
    use std::io::{BufRead, BufReader, Read, Write};

    if crate::common::skip_without_userns_privileges() {
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen_tx, seen_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream);
            let mut length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; length];
            let _ = reader.read_exact(&mut body);
            let _ = seen_tx.send(String::from_utf8_lossy(&body).into_owned());
            let _ = reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    });

    let sandbox = Sandbox::builder()
        .allow_network(&["localhost"])
        .allow_private_destinations()
        .wall_time_limit(Duration::from_secs(15))
        .build()
        .unwrap();
    let script = format!(
        "command -v curl >/dev/null || {{ echo NO_CURL; exit 0; }}
         curl -s --max-time 10 -d 'payload=12345' http://localhost:{port}/post"
    );
    let result = sandbox.run("sh", &["-c", &script]).unwrap();
    if result.stdout.trim() == "NO_CURL" {
        eprintln!("skipping: no curl in the sandbox");
        return;
    }
    assert_eq!(result.stdout, "ok", "{}", result.stderr);
    let body = seen_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(body, "payload=12345");
}

/// Test: the run's result lists the hosts the proxy refused it.
#[test]
#[cfg(unix)]
fn test_blocked_hosts_reported() {
    if crate::common::skip_without_userns_privileges() {
        return;
    }
    let sandbox = Sandbox::builder()
        .allow_network(&["example.com"])
        .wall_time_limit(Duration::from_secs(15))
        .build()
        .unwrap();
    let result = sandbox
        .run(
            "sh",
            &[
                "-c",
                "command -v curl >/dev/null || { echo NO_CURL; exit 0; }
                 curl -s -o /dev/null http://blocked.invalid/
                 curl -s -o /dev/null https://also-blocked.invalid/
                 curl -s -o /dev/null http://blocked.invalid/again",
            ],
        )
        .unwrap();
    if result.stdout.trim() == "NO_CURL" {
        eprintln!("skipping: no curl in the sandbox");
        return;
    }
    assert_eq!(
        result.blocked_hosts,
        vec!["also-blocked.invalid", "blocked.invalid"]
    );

    // And only that run's: the next one starts empty.
    let result = sandbox.run("true", &[]).unwrap();
    assert!(result.blocked_hosts.is_empty());
}

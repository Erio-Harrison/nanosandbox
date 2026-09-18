//! HTTP Proxy implementation for domain whitelisting
//!
//! Implements a simple HTTP/HTTPS proxy that checks domain against a whitelist
//! before forwarding requests.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// Connection timeout for proxy connections
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Data transfer timeout (idle timeout)
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(300);

/// HTTP Proxy server with domain whitelist
pub struct HttpProxy {
    allowed_domains: Arc<HashSet<String>>,
    listen_addr: SocketAddr,
}

impl HttpProxy {
    /// Create a new HTTP proxy
    ///
    /// # Arguments
    ///
    /// * `allowed_domains` - List of allowed domains (supports wildcards like `*.example.com`)
    /// * `port` - Port to listen on (use 0 for random available port)
    pub fn new(allowed_domains: Vec<String>, port: u16) -> Self {
        Self {
            allowed_domains: Arc::new(allowed_domains.into_iter().collect()),
            listen_addr: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    /// Get the listen address
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Run the proxy server
    ///
    /// This will block until the shutdown signal is received.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        let actual_addr = listener.local_addr()?;
        tracing::info!("HTTP proxy listening on {}", actual_addr);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let allowed = Arc::clone(&self.allowed_domains);
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(stream, &allowed).await {
                                    tracing::debug!("Connection from {} error: {}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("Accept error: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Proxy shutting down");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Run the proxy server without shutdown signal (for simpler use cases)
    pub async fn run_forever(&self) -> std::io::Result<()> {
        let (_tx, rx) = watch::channel(false);
        self.run(rx).await
    }

    async fn handle_connection(
        mut client: TcpStream,
        allowed: &HashSet<String>,
    ) -> std::io::Result<()> {
        // Read ALL headers at once to avoid BufReader buffering issues
        let mut reader = BufReader::new(&mut client);
        let mut all_headers = String::new();

        // Read headers until empty line
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break; // EOF
            }
            all_headers.push_str(&line);
            if line == "\r\n" || line == "\n" {
                break; // End of headers
            }
        }

        let first_line = all_headers.lines().next().unwrap_or("");

        if first_line.starts_with("CONNECT ") {
            // HTTPS tunnel request - pass the client (headers already consumed)
            Self::handle_connect(client, first_line, &all_headers, allowed).await
        } else {
            // Regular HTTP request
            Self::handle_http(client, first_line, &all_headers, allowed).await
        }
    }

    /// Handle CONNECT requests (HTTPS tunneling)
    async fn handle_connect(
        mut client: TcpStream,
        first_line: &str,
        _all_headers: &str, // Headers already consumed
        allowed: &HashSet<String>,
    ) -> std::io::Result<()> {
        // Parse: CONNECT host:port HTTP/1.1
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Self::send_error(&mut client, 400, "Bad Request").await;
        }

        let host_port = parts[1];
        let host = host_port.split(':').next().unwrap_or("");
        let port = host_port
            .split(':')
            .nth(1)
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(443);

        tracing::debug!("CONNECT request to {}:{}", host, port);

        if !Self::is_allowed(host, allowed) {
            tracing::info!("Blocked CONNECT to {} (not in whitelist)", host);
            return Self::send_error(&mut client, 403, "Domain not in whitelist").await;
        }

        // Headers already read in handle_connection, no need to read again

        // Connect to target with timeout
        let remote = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect(format!("{}:{}", host, port))
        ).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::debug!("Failed to connect to {}:{}: {}", host, port, e);
                return Self::send_error(&mut client, 502, "Bad Gateway").await;
            }
            Err(_) => {
                tracing::debug!("Connection timeout to {}:{}", host, port);
                return Self::send_error(&mut client, 504, "Gateway Timeout").await;
            }
        };

        // Send 200 Connection Established
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        // Bidirectional copy with timeout
        let (mut cr, mut cw) = client.into_split();
        let (mut rr, mut rw) = remote.into_split();

        let client_to_remote = tokio::io::copy(&mut cr, &mut rw);
        let remote_to_client = tokio::io::copy(&mut rr, &mut cw);

        let transfer_result = tokio::time::timeout(
            TRANSFER_TIMEOUT,
            async {
                tokio::select! {
                    r1 = client_to_remote => {
                        if let Err(e) = r1 {
                            tracing::debug!("Client to remote error: {}", e);
                        }
                    }
                    r2 = remote_to_client => {
                        if let Err(e) = r2 {
                            tracing::debug!("Remote to client error: {}", e);
                        }
                    }
                }
            }
        ).await;

        if transfer_result.is_err() {
            tracing::debug!("Transfer timeout for CONNECT tunnel");
        }

        Ok(())
    }

    /// Handle regular HTTP requests
    async fn handle_http(
        mut client: TcpStream,
        first_line: &str,
        all_headers: &str,
        allowed: &HashSet<String>,
    ) -> std::io::Result<()> {
        // Parse: GET http://host/path HTTP/1.1
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Self::send_error(&mut client, 400, "Bad Request").await;
        }

        let url = parts[1];

        // Extract host from URL or Host header
        let host = if url.starts_with("http://") {
            url.trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("")
        } else {
            // Relative URL - need to read Host header
            // For simplicity, reject requests without absolute URL
            return Self::send_error(&mut client, 400, "Absolute URL required").await;
        };

        tracing::debug!("HTTP request to {}", host);

        if !Self::is_allowed(host, allowed) {
            tracing::info!("Blocked HTTP to {} (not in whitelist)", host);
            return Self::send_error(&mut client, 403, "Domain not in whitelist").await;
        }

        // Parse target host and port from URL
        let host_port = url
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("");
        let target_host = host_port.split(':').next().unwrap_or(host_port);
        let target_port = host_port
            .split(':')
            .nth(1)
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(80);

        // Convert absolute URL to relative path for the origin server
        // "GET http://example.com/path HTTP/1.1" -> "GET /path HTTP/1.1"
        let path = url
            .trim_start_matches("http://")
            .find('/')
            .map(|i| &url.trim_start_matches("http://")[i..])
            .unwrap_or("/");
        let method = parts[0];
        let version = parts.get(2).unwrap_or(&"HTTP/1.1");
        let rewritten_first_line = format!("{} {} {}\r\n", method, path, version);

        // Build headers with rewritten first line
        let mut headers = rewritten_first_line;
        // Skip the first line from all_headers, append the rest
        if let Some(rest) = all_headers.find("\r\n").or(all_headers.find("\n")) {
            headers.push_str(&all_headers[rest + if all_headers[rest..].starts_with("\r\n") { 2 } else { 1 }..]);
        }

        // Connect to target with timeout
        let mut remote = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect(format!("{}:{}", target_host, target_port))
        ).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::debug!("Failed to connect to {}:{}: {}", target_host, target_port, e);
                return Self::send_error(&mut client, 502, "Bad Gateway").await;
            }
            Err(_) => {
                tracing::debug!("Connection timeout to {}:{}", target_host, target_port);
                return Self::send_error(&mut client, 504, "Gateway Timeout").await;
            }
        };

        // Forward request
        remote.write_all(headers.as_bytes()).await?;

        // For HTTP: wait for response to complete (server closes connection)
        // Unlike CONNECT tunnels, HTTP is request-response, not bidirectional
        let transfer_result = tokio::time::timeout(
            TRANSFER_TIMEOUT,
            tokio::io::copy(&mut remote, &mut client)
        ).await;

        match transfer_result {
            Ok(Ok(bytes)) => {
                tracing::debug!("HTTP response transferred {} bytes", bytes);
            }
            Ok(Err(e)) => {
                tracing::debug!("HTTP transfer error: {}", e);
            }
            Err(_) => {
                tracing::debug!("HTTP transfer timeout");
            }
        }

        Ok(())
    }

    /// Check if domain is in whitelist
    fn is_allowed(host: &str, allowed: &HashSet<String>) -> bool {
        // Remove port if present
        let domain = host.split(':').next().unwrap_or(host).to_lowercase();

        // Exact match
        if allowed.contains(&domain) {
            return true;
        }

        // Wildcard match (*.example.com)
        for pattern in allowed.iter() {
            if let Some(stripped) = pattern.strip_prefix("*.") {
                // stripped is ".example.com"
                if domain.ends_with(stripped) {
                    return true;
                }
                // Also match the base domain (*.example.com matches example.com)
                if domain == stripped {
                    return true;
                }
            }
        }

        false
    }

    async fn send_error(client: &mut TcpStream, code: u16, msg: &str) -> std::io::Result<()> {
        let body = format!(
            "<html><body><h1>{} {}</h1><p>Nanosandbox proxy</p></body></html>",
            code, msg
        );
        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            code, msg, body.len(), body
        );
        client.write_all(response.as_bytes()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_allowed_exact() {
        let allowed: HashSet<String> = vec!["example.com".to_string()].into_iter().collect();

        assert!(HttpProxy::is_allowed("example.com", &allowed));
        assert!(HttpProxy::is_allowed("example.com:443", &allowed));
        assert!(!HttpProxy::is_allowed("other.com", &allowed));
    }

    #[test]
    fn test_is_allowed_wildcard() {
        let allowed: HashSet<String> = vec!["*.example.com".to_string()].into_iter().collect();

        assert!(HttpProxy::is_allowed("sub.example.com", &allowed));
        assert!(HttpProxy::is_allowed("deep.sub.example.com", &allowed));
        assert!(HttpProxy::is_allowed("example.com", &allowed)); // Base domain also matches
        assert!(!HttpProxy::is_allowed("other.com", &allowed));
    }

    #[test]
    fn test_is_allowed_case_insensitive() {
        let allowed: HashSet<String> = vec!["example.com".to_string()].into_iter().collect();

        assert!(HttpProxy::is_allowed("EXAMPLE.COM", &allowed));
        assert!(HttpProxy::is_allowed("Example.Com", &allowed));
    }
}

//! HTTP Proxy implementation for domain whitelisting
//!
//! Implements a simple HTTP/HTTPS proxy that checks domain against a whitelist
//! before forwarding requests.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// Connection timeout for proxy connections
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Data transfer timeout (idle timeout)
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(300);

/// Request line plus headers. The proxy runs in the host process, so a client
/// that never ends its headers mustn't be able to grow this without bound.
const MAX_HEADER_BYTES: u64 = 64 * 1024;

/// How long a client gets to send its request headers.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);

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
            // Hosts are lowercased before matching, so patterns must be too.
            allowed_domains: Arc::new(
                allowed_domains
                    .into_iter()
                    .map(|d| d.to_lowercase())
                    .collect(),
            ),
            listen_addr: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    /// Get the listen address
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Run the proxy server
    ///
    /// This will block until the shutdown signal is received. If `bound` is
    /// given, the actual listen address (or the bind error) is sent on it as
    /// soon as the listener is up, before the accept loop starts — so a
    /// caller never has to guess a port and race a second bind against it.
    pub async fn run(
        &self,
        mut shutdown: watch::Receiver<bool>,
        bound: Option<std::sync::mpsc::Sender<std::io::Result<SocketAddr>>>,
    ) -> std::io::Result<()> {
        let listener = match TcpListener::bind(self.listen_addr).await {
            Ok(listener) => listener,
            Err(e) => {
                let kind = e.kind();
                if let Some(tx) = bound {
                    let _ = tx.send(Err(std::io::Error::new(kind, e.to_string())));
                }
                return Err(e);
            }
        };
        let actual_addr = listener.local_addr()?;
        if let Some(tx) = bound {
            let _ = tx.send(Ok(actual_addr));
        }
        tracing::info!("HTTP proxy listening on {}", actual_addr);

        let stop = async move {
            while shutdown.changed().await.is_ok() {
                if *shutdown.borrow() {
                    break;
                }
            }
            tracing::info!("Proxy shutting down");
        };
        Self::serve(listener, Arc::clone(&self.allowed_domains), stop).await;
        Ok(())
    }

    /// The domains this proxy lets through.
    #[cfg(target_os = "linux")]
    pub(crate) fn allowed_domains(&self) -> Arc<HashSet<String>> {
        Arc::clone(&self.allowed_domains)
    }

    /// Accepts and proxies connections on `listener` until `stop` completes.
    /// Also used for listeners bound inside a sandbox's own network namespace
    /// (see `ProxiedNetwork::attach`), so it doesn't need `&self`.
    pub(crate) async fn serve(
        listener: TcpListener,
        allowed: Arc<HashSet<String>>,
        stop: impl std::future::Future<Output = ()>,
    ) {
        tokio::pin!(stop);
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let allowed = Arc::clone(&allowed);
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
                _ = &mut stop => break,
            }
        }
    }

    /// Run the proxy server without shutdown signal (for simpler use cases)
    pub async fn run_forever(&self) -> std::io::Result<()> {
        let (_tx, rx) = watch::channel(false);
        self.run(rx, None).await
    }

    async fn handle_connection(
        mut client: TcpStream,
        allowed: &HashSet<String>,
    ) -> std::io::Result<()> {
        // Read ALL headers at once to avoid BufReader buffering issues
        let mut reader = BufReader::new(&mut client);
        let all_headers =
            match tokio::time::timeout(HEADER_TIMEOUT, Self::read_headers(&mut reader)).await {
                Ok(Ok(Some(headers))) => headers,
                Ok(Ok(None)) => {
                    drop(reader);
                    return Self::send_error(&mut client, 431, "Request Header Fields Too Large")
                        .await;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    tracing::debug!("Timed out waiting for request headers");
                    return Ok(());
                }
            };

        let first_line = all_headers.lines().next().unwrap_or("");

        if first_line.starts_with("CONNECT ") {
            // HTTPS tunnel request - pass the client (headers already consumed)
            Self::handle_connect(client, first_line, &all_headers, allowed).await
        } else {
            // Regular HTTP request
            Self::handle_http(client, first_line, &all_headers, allowed).await
        }
    }

    /// Reads up to and including the blank line ending the headers, or to EOF.
    /// `None` if they run past `MAX_HEADER_BYTES`.
    async fn read_headers<R: AsyncBufRead + Unpin>(
        reader: &mut R,
    ) -> std::io::Result<Option<String>> {
        let mut all_headers = String::new();
        loop {
            let budget = MAX_HEADER_BYTES - all_headers.len() as u64;
            let mut line = String::new();
            let n = (&mut *reader).take(budget).read_line(&mut line).await?;
            all_headers.push_str(&line);
            if n == 0 || line == "\r\n" || line == "\n" {
                return Ok(Some(all_headers));
            }
            if !line.ends_with('\n') {
                // Either the budget ran out mid-line, or EOF did.
                let within = (all_headers.len() as u64) < MAX_HEADER_BYTES;
                return Ok(within.then_some(all_headers));
            }
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
            TcpStream::connect(format!("{}:{}", host, port)),
        )
        .await
        {
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

        let transfer_result = tokio::time::timeout(TRANSFER_TIMEOUT, async {
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
        })
        .await;

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
            headers.push_str(
                &all_headers[rest
                    + if all_headers[rest..].starts_with("\r\n") {
                        2
                    } else {
                        1
                    }..],
            );
        }

        // Connect to target with timeout
        let mut remote = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect(format!("{}:{}", target_host, target_port)),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::debug!(
                    "Failed to connect to {}:{}: {}",
                    target_host,
                    target_port,
                    e
                );
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
        let transfer_result =
            tokio::time::timeout(TRANSFER_TIMEOUT, tokio::io::copy(&mut remote, &mut client)).await;

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
            // "*.example.com": example.com itself, or anything ending in
            // ".example.com". Keeping the dot is what stops it matching
            // "evilexample.com".
            if let Some(dot_base) = pattern.strip_prefix('*') {
                if dot_base.starts_with('.')
                    && (domain.ends_with(dot_base) || domain == dot_base[1..])
                {
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
        // Only on a label boundary.
        assert!(!HttpProxy::is_allowed("evilexample.com", &allowed));
        assert!(!HttpProxy::is_allowed("evilexample.com:443", &allowed));
        assert!(!HttpProxy::is_allowed("example.com.evil.com", &allowed));
    }

    #[test]
    fn test_whitelist_entries_are_case_insensitive() {
        let proxy = HttpProxy::new(vec!["Mixed.Org".into(), "*.Upper.COM".into()], 0);
        assert!(HttpProxy::is_allowed("mixed.org", &proxy.allowed_domains));
        assert!(HttpProxy::is_allowed("a.upper.com", &proxy.allowed_domains));
    }

    #[tokio::test]
    async fn test_header_size_is_capped() {
        let mut ok: &[u8] = b"GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\nbody";
        assert_eq!(
            HttpProxy::read_headers(&mut ok).await.unwrap().as_deref(),
            Some("GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\n")
        );

        // One endless line, then many short ones: both stop at the cap
        // instead of buffering everything.
        let long = vec![b'a'; 1024 * 1024];
        assert_eq!(HttpProxy::read_headers(&mut &long[..]).await.unwrap(), None);
        let many = b"X: y\r\n".repeat(100_000);
        assert_eq!(HttpProxy::read_headers(&mut &many[..]).await.unwrap(), None);
    }

    #[test]
    fn test_is_allowed_case_insensitive() {
        let allowed: HashSet<String> = vec!["example.com".to_string()].into_iter().collect();

        assert!(HttpProxy::is_allowed("EXAMPLE.COM", &allowed));
        assert!(HttpProxy::is_allowed("Example.Com", &allowed));
    }
}

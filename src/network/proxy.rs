//! HTTP Proxy implementation for domain whitelisting
//!
//! Implements a simple HTTP/HTTPS proxy that checks domain against a whitelist
//! before forwarding requests.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

/// What the proxy lets through.
#[derive(Clone, Debug)]
pub(crate) struct Policy {
    /// Lowercased; `*.example.com` also matches subdomains.
    domains: HashSet<String>,
    /// Whether an allowed name may lead to a loopback, private, link-local
    /// (cloud metadata) or other non-public address. The proxy connects
    /// from the host's network, so by default it doesn't: that would hand
    /// the sandbox the host's own services and internal network.
    allow_private: bool,
}

/// HTTP Proxy server with domain whitelist
pub struct HttpProxy {
    policy: Arc<Policy>,
    listen_addr: SocketAddr,
}

/// Why the proxy didn't connect to a destination.
enum ConnectError {
    /// It resolved only to addresses the policy refuses.
    NotPublic,
    Failed(std::io::Error),
    TimedOut,
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
            policy: Arc::new(Policy {
                // Hosts are lowercased before matching, so patterns must be too.
                domains: allowed_domains
                    .into_iter()
                    .map(|d| d.to_lowercase())
                    .collect(),
                allow_private: false,
            }),
            listen_addr: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    /// Let allowed domains lead to loopback, private, link-local and other
    /// non-public addresses too. Off by default.
    pub fn allow_private_destinations(mut self, allow: bool) -> Self {
        Arc::make_mut(&mut self.policy).allow_private = allow;
        self
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
        Self::serve(listener, Arc::clone(&self.policy), stop).await;
        Ok(())
    }

    /// What this proxy lets through.
    #[cfg(target_os = "linux")]
    pub(crate) fn policy(&self) -> Arc<Policy> {
        Arc::clone(&self.policy)
    }

    /// Accepts and proxies connections on `listener` until `stop` completes.
    /// Also used for listeners bound inside a sandbox's own network namespace
    /// (see `ProxiedNetwork::attach`), so it doesn't need `&self`.
    pub(crate) async fn serve(
        listener: TcpListener,
        policy: Arc<Policy>,
        stop: impl std::future::Future<Output = ()>,
    ) {
        tokio::pin!(stop);
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let policy = Arc::clone(&policy);
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(stream, &policy).await {
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

    async fn handle_connection(mut client: TcpStream, policy: &Policy) -> std::io::Result<()> {
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
            Self::handle_connect(client, first_line, &all_headers, policy).await
        } else {
            // Regular HTTP request
            Self::handle_http(client, first_line, &all_headers, policy).await
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
        policy: &Policy,
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

        if !Self::is_allowed(host, &policy.domains) {
            tracing::info!("Blocked CONNECT to {} (not in whitelist)", host);
            return Self::send_error(&mut client, 403, "Domain not in whitelist").await;
        }

        // Headers already read in handle_connection, no need to read again

        let remote = match Self::connect(host, port, policy).await {
            Ok(r) => r,
            Err(e) => return Self::refuse(&mut client, host, port, e).await,
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
        policy: &Policy,
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

        if !Self::is_allowed(host, &policy.domains) {
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

        let mut remote = match Self::connect(target_host, target_port, policy).await {
            Ok(r) => r,
            Err(e) => return Self::refuse(&mut client, target_host, target_port, e).await,
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

    /// Resolves `host` once and connects to one of the addresses the policy
    /// allows. Connecting by address, not by name again, means the name
    /// can't resolve to something else in between (DNS rebinding).
    async fn connect(host: &str, port: u16, policy: &Policy) -> Result<TcpStream, ConnectError> {
        let attempt = async {
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
                .await
                .map_err(ConnectError::Failed)?
                .collect();
            let usable: Vec<&SocketAddr> = resolved
                .iter()
                .filter(|a| policy.allow_private || is_public(a.ip()))
                .collect();
            if usable.is_empty() && !resolved.is_empty() {
                return Err(ConnectError::NotPublic);
            }
            let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "no address");
            for addr in usable {
                match TcpStream::connect(addr).await {
                    Ok(stream) => return Ok(stream),
                    Err(e) => last = e,
                }
            }
            Err(ConnectError::Failed(last))
        };
        tokio::time::timeout(CONNECT_TIMEOUT, attempt)
            .await
            .unwrap_or(Err(ConnectError::TimedOut))
    }

    async fn refuse(
        client: &mut TcpStream,
        host: &str,
        port: u16,
        e: ConnectError,
    ) -> std::io::Result<()> {
        match e {
            ConnectError::NotPublic => {
                tracing::info!("Blocked {host}:{port}: resolves to a non-public address");
                Self::send_error(client, 403, "Destination address not allowed").await
            }
            ConnectError::Failed(e) => {
                tracing::debug!("Failed to connect to {host}:{port}: {e}");
                Self::send_error(client, 502, "Bad Gateway").await
            }
            ConnectError::TimedOut => {
                tracing::debug!("Connection timeout to {host}:{port}");
                Self::send_error(client, 504, "Gateway Timeout").await
            }
        }
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

/// Whether `ip` is on the public internet: not loopback, private, link-local
/// (where cloud metadata services live), shared (CGNAT), multicast,
/// reserved or the like. IPv6 addresses that embed an IPv4 one (mapped,
/// NAT64, 6to4) are judged by it.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let embedded = |hi: u16, lo: u16| {
                Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8)
            };
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] || s[..6] == [0; 6] {
                // NAT64, and IPv4-compatible (which includes :: and ::1)
                return !v6.is_loopback() && is_public_v4(embedded(s[6], s[7]));
            }
            if s[0] == 0x2002 {
                return is_public_v4(embedded(s[1], s[2])); // 6to4
            }
            !(v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link-local
                || (s[0] & 0xffc0) == 0xfec0 // site-local
                || (s[0] == 0x2001 && s[1] == 0xdb8)) // documentation
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(o[0] == 0 // "this network", including 0.0.0.0
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10, shared
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15, benchmarking
        || ip.is_documentation()
        || ip.is_multicast()
        || o[0] >= 240) // reserved, and broadcast
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
        assert!(HttpProxy::is_allowed("mixed.org", &proxy.policy.domains));
        assert!(HttpProxy::is_allowed("a.upper.com", &proxy.policy.domains));
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

    #[test]
    fn test_is_public() {
        for ip in [
            "93.184.216.34",
            "1.1.1.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "2002:7f00:1::",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }
}

//! HTTP/HTTPS proxy that only lets a domain allowlist through.
//!
//! It handles plain HTTP requests in absolute form (`GET http://host/path`)
//! and HTTPS tunnels (`CONNECT host:port`). Each target host is checked
//! against the allowlist, resolved once, checked against non-public
//! addresses (see [`is_public`]), and connected to by address. Then bytes
//! are relayed both ways until both sides are done, or neither has sent
//! anything for the idle timeout.

use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Notify};

/// Connection timeout for proxy connections
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a relayed connection may go with nothing sent either way. Not a
/// limit on how long it lasts: a download that keeps going keeps going.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Request line plus headers. The proxy runs in the host process, so a client
/// that never ends its headers mustn't be able to grow this without bound.
const MAX_HEADER_BYTES: u64 = 64 * 1024;

/// How long a client gets to send its request headers.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);

/// Request headers that only concern the hop between the client and the
/// proxy, or that the proxy sets itself. Also dropped: any header the
/// `Connection` header names.
const HOP_BY_HOP: [&str; 7] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authorization",
    "te",
    "upgrade",
    "host",
];

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
    idle_timeout: Duration,
}

/// The hosts the proxy refused, for one run: not on the allowlist, or
/// resolving only to addresses the policy refuses.
#[derive(Debug, Default)]
pub(crate) struct Blocked(Mutex<BTreeSet<String>>);

impl Blocked {
    fn record(&self, host: &str) {
        if let Ok(mut hosts) = self.0.lock() {
            hosts.insert(host.to_string());
        }
    }

    /// Sorted, each once.
    pub(crate) fn hosts(&self) -> Vec<String> {
        self.0
            .lock()
            .map(|hosts| hosts.iter().cloned().collect())
            .unwrap_or_default()
    }
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

/// What a request asks the proxy to do, once its target is parsed.
enum Request<'a> {
    /// `CONNECT host:port`: a tunnel.
    Connect { host: String, port: u16 },
    /// A plain HTTP request, to forward with `path` in place of the URL and
    /// `authority` as its `Host`.
    Http {
        host: String,
        port: u16,
        method: &'a str,
        authority: &'a str,
        path: String,
        version: &'a str,
    },
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
                // Hosts are lowercased and unbracketed before matching, so
                // patterns must be too.
                domains: allowed_domains
                    .into_iter()
                    .map(|d| {
                        d.trim_start_matches('[')
                            .trim_end_matches(']')
                            .to_lowercase()
                    })
                    .collect(),
                allow_private: false,
                idle_timeout: IDLE_TIMEOUT,
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
        let blocked = Arc::new(Blocked::default());
        Self::serve(listener, Arc::clone(&self.policy), blocked, stop).await;
        Ok(())
    }

    /// Run the proxy server without shutdown signal (for simpler use cases)
    pub async fn run_forever(&self) -> std::io::Result<()> {
        let (_tx, rx) = watch::channel(false);
        self.run(rx, None).await
    }

    /// What this proxy lets through.
    pub(crate) fn policy(&self) -> Arc<Policy> {
        Arc::clone(&self.policy)
    }

    /// Accepts and proxies connections on `listener` until `stop` completes,
    /// recording refused hosts in `blocked`. Connections still open then are
    /// cut: a run's listener stops when the run is over.
    pub(crate) async fn serve(
        listener: TcpListener,
        policy: Arc<Policy>,
        blocked: Arc<Blocked>,
        stop: impl std::future::Future<Output = ()>,
    ) {
        tokio::pin!(stop);
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let policy = Arc::clone(&policy);
                            let blocked = Arc::clone(&blocked);
                            connections.spawn(async move {
                                if let Err(e) = Self::handle_connection(stream, &policy, &blocked).await {
                                    tracing::debug!("Connection from {} error: {:?}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("Accept error: {:?}", e);
                        }
                    }
                }
                // Reap finished ones, so the set doesn't grow with them.
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
                _ = &mut stop => break,
            }
        }
        // Dropping `connections` aborts the ones still open.
    }

    async fn handle_connection(
        mut client: TcpStream,
        policy: &Policy,
        blocked: &Blocked,
    ) -> std::io::Result<()> {
        let mut reader = BufReader::new(&mut client);
        let head = match tokio::time::timeout(HEADER_TIMEOUT, Self::read_headers(&mut reader)).await
        {
            Ok(Ok(Some(head))) => head,
            Ok(Ok(None)) => {
                drop(reader);
                return Self::send_error(&mut client, 431, "Request Header Fields Too Large").await;
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                tracing::debug!("Timed out waiting for request headers");
                return Ok(());
            }
        };
        // What the client sent right after its headers, read along with
        // them: a request body, or the start of a TLS handshake. It goes to
        // the destination first. It used to be dropped with the reader.
        let early = reader.buffer().to_vec();
        drop(reader);

        let request = match Self::parse_request(&head) {
            Ok(request) => request,
            Err(reason) => return Self::send_error(&mut client, 400, reason).await,
        };
        let (host, port) = match &request {
            Request::Connect { host, port } | Request::Http { host, port, .. } => (host, *port),
        };
        tracing::debug!("Request for {host}:{port}");

        if !Self::is_allowed(host, &policy.domains) {
            tracing::info!("Blocked {} (not in whitelist)", host);
            blocked.record(host);
            return Self::send_error(&mut client, 403, "Domain not in whitelist").await;
        }
        let mut remote = match Self::connect(host, port, policy).await {
            Ok(remote) => remote,
            Err(e) => {
                if matches!(e, ConnectError::NotPublic) {
                    blocked.record(host);
                }
                return Self::refuse(&mut client, host, port, e).await;
            }
        };

        match &request {
            Request::Connect { .. } => {
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
            }
            Request::Http {
                method,
                authority,
                path,
                version,
                ..
            } => {
                let head = Self::forwarded_head(&head, method, path, version, authority);
                remote.write_all(head.as_bytes()).await?;
            }
        }
        Self::relay(client, remote, &early, policy.idle_timeout).await
    }

    /// Reads up to and including the blank line ending the headers, or to EOF.
    /// `None` if they run past `MAX_HEADER_BYTES`.
    async fn read_headers<R: AsyncBufRead + Unpin>(
        reader: &mut R,
    ) -> std::io::Result<Option<String>> {
        let mut all_headers = String::new();
        loop {
            let budget = MAX_HEADER_BYTES - all_headers.len() as u64;
            if budget == 0 {
                // A prior line landed exactly on the cap: take(0) reads 0
                // bytes same as real EOF, so this must be checked before
                // read_line, not inferred from its result.
                return Ok(None);
            }
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

    /// The request line's target, or why it can't be served.
    fn parse_request(head: &str) -> Result<Request<'_>, &'static str> {
        // Obsolete line folding (RFC 7230 §3.2.4): a continuation line is
        // part of whatever header preceded it, but `forwarded_head` strips
        // hop-by-hop headers line by line and would let a folded line
        // through under a kept header's name -- smuggling a client-chosen
        // Host or Proxy-Authorization past the strip. Refused outright,
        // the same as this parser already refuses anything else it won't
        // fully understand; no real client sends this today.
        if head
            .lines()
            .skip(1)
            .any(|line| line.starts_with([' ', '\t']))
        {
            return Err("Line folding not supported");
        }
        let mut parts = head.lines().next().unwrap_or("").split_whitespace();
        let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
            return Err("Bad Request");
        };
        let version = parts.next().unwrap_or("HTTP/1.1");

        if method.eq_ignore_ascii_case("CONNECT") {
            let (host, port) = parse_authority(target, 443).ok_or("Bad Request")?;
            return Ok(Request::Connect { host, port });
        }
        // Absolute form only: a request with just a path would have to be
        // routed by its Host header, which the client controls.
        let rest = target
            .get(..7)
            .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))
            .map(|_| &target[7..])
            .ok_or("Absolute URL required")?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..end];
        let (host, port) = parse_authority(authority, 80).ok_or("Bad Request")?;
        let path = match &rest[end..] {
            "" => "/".to_string(),
            p if p.starts_with('/') => p.to_string(),
            p => format!("/{p}"),
        };
        Ok(Request::Http {
            host,
            port,
            method,
            authority,
            path,
            version,
        })
    }

    /// The request head to send on: the path instead of the URL, `Host` set
    /// to the URL's (the destination that was checked, whatever the client
    /// put there), hop-by-hop headers dropped, and `Connection: close`. One
    /// request per connection: the server closes after answering it, so
    /// anything else the client sends on the same connection isn't served,
    /// and nothing needs the proxy to understand request bodies.
    fn forwarded_head(
        head: &str,
        method: &str,
        path: &str,
        version: &str,
        authority: &str,
    ) -> String {
        let headers: Vec<&str> = head
            .lines()
            .skip(1)
            .take_while(|line| !line.is_empty())
            .collect();
        let name = |line: &str| line.split(':').next().unwrap_or("").trim().to_lowercase();
        let named_by_connection: HashSet<String> = headers
            .iter()
            .filter(|line| name(line) == "connection")
            .flat_map(|line| {
                line.split_once(':')
                    .map(|(_, v)| v)
                    .unwrap_or("")
                    .split(',')
            })
            .map(|token| token.trim().to_lowercase())
            .collect();

        let mut out = format!("{method} {path} {version}\r\nHost: {authority}\r\n");
        let mut keep = true;
        for line in headers {
            // A line starting with whitespace continues the previous header.
            if !line.starts_with([' ', '\t']) {
                let name = name(line);
                keep = !HOP_BY_HOP.contains(&name.as_str()) && !named_by_connection.contains(&name);
            }
            if keep {
                out.push_str(line);
                out.push_str("\r\n");
            }
        }
        out.push_str("Connection: close\r\n\r\n");
        out
    }

    /// Sends `early` to `remote`, then copies both ways. When one side is
    /// done sending, the other is told (its write half is shut down) and the
    /// other direction carries on: a client may finish its request and still
    /// be waiting for the answer. Ends when both are done, either fails, or
    /// nothing has gone either way for `idle`.
    async fn relay(
        client: TcpStream,
        remote: TcpStream,
        early: &[u8],
        idle: Duration,
    ) -> std::io::Result<()> {
        let (client_read, client_write) = client.into_split();
        let (remote_read, mut remote_write) = remote.into_split();
        remote_write.write_all(early).await?;

        let activity = Notify::new();
        let pipe = |mut from: tokio::net::tcp::OwnedReadHalf,
                    mut to: tokio::net::tcp::OwnedWriteHalf| {
            let activity = &activity;
            async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    let n = from.read(&mut buf).await?;
                    if n == 0 {
                        return to.shutdown().await;
                    }
                    to.write_all(&buf[..n]).await?;
                    activity.notify_one();
                }
            }
        };
        let both = async {
            tokio::try_join!(
                pipe(client_read, remote_write),
                pipe(remote_read, client_write)
            )
        };
        let watchdog = async {
            while tokio::time::timeout(idle, activity.notified())
                .await
                .is_ok()
            {}
        };
        tokio::select! {
            result = both => result.map(|_| ()),
            _ = watchdog => {
                tracing::debug!("Closing a connection idle for {idle:?}");
                Ok(())
            }
        }
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
                tracing::debug!("Failed to connect to {host}:{port}: {e:?}");
                Self::send_error(client, 502, "Bad Gateway").await
            }
            ConnectError::TimedOut => {
                tracing::debug!("Connection timeout to {host}:{port}");
                Self::send_error(client, 504, "Gateway Timeout").await
            }
        }
    }

    /// Whether `host` (lowercased, no port or brackets) is on the allowlist.
    fn is_allowed(host: &str, allowed: &HashSet<String>) -> bool {
        if allowed.contains(host) {
            return true;
        }
        // "*.example.com": example.com itself, or anything ending in
        // ".example.com". Keeping the dot is what stops it matching
        // "evilexample.com".
        allowed.iter().any(|pattern| {
            pattern.strip_prefix('*').is_some_and(|dot_base| {
                dot_base.starts_with('.') && (host.ends_with(dot_base) || host == &dot_base[1..])
            })
        })
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

/// `host`, `host:port`, `[v6]` or `[v6]:port`, as the lowercased host
/// without brackets and the port (`default` if none). `None` for anything
/// else, including `user@host`: userinfo has no business in a proxy request,
/// and is an old way to make a URL look like it goes somewhere it doesn't.
fn parse_authority(authority: &str, default: u16) -> Option<(String, u16)> {
    if authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']')?;
            let port = match after {
                "" => None,
                p => Some(p.strip_prefix(':')?),
            };
            (host, port)
        }
        None => match authority.rsplit_once(':') {
            // More than one colon without brackets: a bare IPv6 address,
            // whose last group can't be told from a port.
            Some((host, _)) if host.contains(':') => return None,
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        None => default,
        Some(p) => p.parse().ok().filter(|&p| p != 0)?,
    };
    Some((host.to_ascii_lowercase(), port))
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
    use tokio::io::AsyncWriteExt;
    use tokio::sync::oneshot;

    fn allowed(domains: &[&str]) -> HashSet<String> {
        domains.iter().map(|d| d.to_string()).collect()
    }

    #[test]
    fn test_is_allowed_exact() {
        let allowed = allowed(&["example.com"]);
        assert!(HttpProxy::is_allowed("example.com", &allowed));
        assert!(!HttpProxy::is_allowed("other.com", &allowed));
    }

    #[test]
    fn test_is_allowed_wildcard() {
        let allowed = allowed(&["*.example.com"]);
        assert!(HttpProxy::is_allowed("sub.example.com", &allowed));
        assert!(HttpProxy::is_allowed("deep.sub.example.com", &allowed));
        assert!(HttpProxy::is_allowed("example.com", &allowed)); // Base domain also matches
        assert!(!HttpProxy::is_allowed("other.com", &allowed));
        // Only on a label boundary.
        assert!(!HttpProxy::is_allowed("evilexample.com", &allowed));
        assert!(!HttpProxy::is_allowed("example.com.evil.com", &allowed));
    }

    #[test]
    fn test_whitelist_entries_are_normalized() {
        let proxy = HttpProxy::new(
            vec!["Mixed.Org".into(), "*.Upper.COM".into(), "[::1]".into()],
            0,
        );
        assert!(HttpProxy::is_allowed("mixed.org", &proxy.policy.domains));
        assert!(HttpProxy::is_allowed("a.upper.com", &proxy.policy.domains));
        assert!(HttpProxy::is_allowed("::1", &proxy.policy.domains));
    }

    #[test]
    fn test_parse_authority() {
        let parsed = |a| parse_authority(a, 80);
        assert_eq!(parsed("Example.com"), Some(("example.com".into(), 80)));
        assert_eq!(
            parsed("example.com:8080"),
            Some(("example.com".into(), 8080))
        );
        assert_eq!(parsed("[::1]"), Some(("::1".into(), 80)));
        assert_eq!(parsed("[::1]:443"), Some(("::1".into(), 443)));
        for bad in [
            "",
            ":80",
            "::1",
            "[::1",
            "[::1]x",
            "a:b",
            "a:0",
            "a:99999",
            "user@a.com",
            "a.com:1@b.com",
        ] {
            assert_eq!(parsed(bad), None, "{bad}");
        }
    }

    #[test]
    fn test_forwarded_head() {
        let head = "POST http://a.com:81/x?q=1 HTTP/1.1\r\n\
                    Host: evil.example\r\n\
                    Connection: keep-alive, X-Secret\r\n\
                    Proxy-Authorization: Basic abc\r\n\
                    X-Secret: 1\r\n\
                    Keep-Alive: timeout=5\r\n\
                    Content-Length: 5\r\n\
                    X-Kept: a\r\n\
                    \r\n";
        let Ok(Request::Http {
            method,
            authority,
            path,
            version,
            ..
        }) = HttpProxy::parse_request(head)
        else {
            panic!("not parsed as HTTP");
        };
        assert_eq!(
            HttpProxy::forwarded_head(head, method, &path, version, authority),
            "POST /x?q=1 HTTP/1.1\r\nHost: a.com:81\r\nContent-Length: 5\r\n\
             X-Kept: a\r\nConnection: close\r\n\r\n"
        );
    }

    /// A continuation line inherits whatever a plain line-by-line stripper
    /// decided for the header it follows, with no look at its own content
    /// -- so a header that's supposed to be stripped could ride through
    /// folded under one that's kept. Refusing any folded request instead
    /// closes that off; verified it's refused for both a stripped and a
    /// kept header being the one folded under.
    #[test]
    fn test_line_folding_refused() {
        for head in [
            "GET http://a.com/ HTTP/1.1\r\nX-Kept: a\r\n Proxy-Authorization: x\r\n\r\n",
            "GET http://a.com/ HTTP/1.1\r\nX-Kept: a\r\n Host: evil.example\r\n\r\n",
        ] {
            assert!(matches!(
                HttpProxy::parse_request(head),
                Err("Line folding not supported")
            ));
        }
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

    /// A line landing exactly on the cap used to be indistinguishable from
    /// EOF (`take(0)` also reads 0 bytes), so it was accepted as complete
    /// instead of rejected -- dropping the real terminator and whatever the
    /// client sent after it.
    #[tokio::test]
    async fn test_header_line_exactly_at_the_cap_is_still_rejected() {
        let filler = "a".repeat(1024 * 64 - "X: \r\n".len());
        let mut input = format!("X: {filler}\r\n").into_bytes();
        input.extend_from_slice(b"Host: evil\r\n\r\nbody");
        assert_eq!(
            HttpProxy::read_headers(&mut &input[..]).await.unwrap(),
            None
        );
    }

    /// A proxy for `domains`, private destinations allowed (the test servers
    /// are on loopback). Stops when the sender is dropped.
    async fn proxy(
        domains: &[&str],
        allow_private: bool,
        idle_timeout: Duration,
    ) -> (SocketAddr, Arc<Blocked>, oneshot::Sender<()>) {
        let policy = Arc::new(Policy {
            domains: allowed(domains),
            allow_private,
            idle_timeout,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let blocked = Arc::new(Blocked::default());
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let stop = async move {
            let _ = stop_rx.await;
        };
        tokio::spawn(HttpProxy::serve(
            listener,
            policy,
            Arc::clone(&blocked),
            stop,
        ));
        (addr, blocked, stop_tx)
    }

    /// A server on loopback that hands each connection to `handle`.
    async fn upstream<F, Fut>(handle: F) -> u16
    where
        F: Fn(TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(handle(stream));
            }
        });
        port
    }

    /// Everything up to EOF, or what arrived within 5s.
    async fn read_all(stream: &mut TcpStream) -> String {
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Reads up to the end of a response head.
    async fn read_head(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        String::from_utf8(head).unwrap()
    }

    #[tokio::test]
    async fn test_http_request_body_reaches_the_server() {
        let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let port = upstream(move |mut s| {
            let seen_tx = seen_tx.clone();
            async move {
                // The request until the client's end of it (EOF, since the
                // proxy relays its half-close), then an answer.
                let request = read_all(&mut s).await;
                let _ = seen_tx.send(request);
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            }
        })
        .await;
        let (proxy, _, _stop) = proxy(&["localhost"], true, IDLE_TIMEOUT).await;

        // Content-Length and chunked, each sent in one write with its
        // headers, the way clients do.
        for body in [
            "Content-Length: 5\r\n\r\nHELLO",
            "Transfer-Encoding: chunked\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n",
        ] {
            let mut client = TcpStream::connect(proxy).await.unwrap();
            let request = format!(
                "POST http://localhost:{port}/up HTTP/1.1\r\nHost: evil.example\r\n\
                 Connection: keep-alive\r\n{body}"
            );
            client.write_all(request.as_bytes()).await.unwrap();
            client.shutdown().await.unwrap();

            let seen = seen_rx.recv().await.unwrap();
            let (seen_head, seen_body) = seen.split_once("\r\n\r\n").unwrap();
            assert!(seen_head.starts_with("POST /up HTTP/1.1\r\n"), "{seen}");
            assert!(
                seen_head.contains(&format!("\r\nHost: localhost:{port}\r\n")),
                "{seen}"
            );
            assert!(seen_head.contains("\r\nConnection: close"), "{seen}");
            assert!(!seen_head.contains("evil.example") && !seen_head.contains("keep-alive"));
            assert_eq!(seen_body, body.split_once("\r\n\r\n").unwrap().1);
            assert!(read_all(&mut client).await.ends_with("\r\n\r\nok"));
        }
    }

    #[tokio::test]
    async fn test_tunnel_keeps_early_data_and_survives_half_close() {
        let port = upstream(|mut s| async move {
            let got = read_all(&mut s).await;
            let _ = s.write_all(format!("got:{got}").as_bytes()).await;
        })
        .await;
        let (proxy, _, _stop) = proxy(&["localhost"], true, IDLE_TIMEOUT).await;

        let mut client = TcpStream::connect(proxy).await.unwrap();
        // CONNECT and the first bytes for the destination in one write.
        let request = format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\nEARLY");
        client.write_all(request.as_bytes()).await.unwrap();
        assert!(read_head(&mut client).await.starts_with("HTTP/1.1 200"));
        client.write_all(b"+LATER").await.unwrap();
        // Done sending; the answer still has to come back.
        client.shutdown().await.unwrap();
        assert_eq!(read_all(&mut client).await, "got:EARLY+LATER");
    }

    #[tokio::test]
    async fn test_idle_timeout_spares_active_connections() {
        let idle = Duration::from_millis(300);
        let trickle = upstream(|mut s| async move {
            for _ in 0..10 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if s.write_all(b".").await.is_err() {
                    return;
                }
            }
        })
        .await;
        let silent = upstream(|s| async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(s);
        })
        .await;
        let (proxy, _, _stop) = proxy(&["localhost"], true, idle).await;

        let mut active = TcpStream::connect(proxy).await.unwrap();
        active
            .write_all(format!("CONNECT localhost:{trickle} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        read_head(&mut active).await;
        // 1s in total, well past `idle`, but never idle that long.
        assert_eq!(read_all(&mut active).await, "..........");

        let mut quiet = TcpStream::connect(proxy).await.unwrap();
        quiet
            .write_all(format!("CONNECT localhost:{silent} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        read_head(&mut quiet).await;
        let start = std::time::Instant::now();
        assert_eq!(read_all(&mut quiet).await, "");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn test_stopping_cuts_open_connections() {
        let silent = upstream(|s| async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(s);
        })
        .await;
        let (proxy, _, stop) = proxy(&["localhost"], true, IDLE_TIMEOUT).await;

        let mut client = TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(format!("CONNECT localhost:{silent} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        read_head(&mut client).await;
        drop(stop);
        let start = std::time::Instant::now();
        assert_eq!(read_all(&mut client).await, "");
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn test_refusals_and_blocked_hosts() {
        let port = upstream(|_| async {}).await;
        // localhost is allowed by name, but not to loopback.
        let (proxy, blocked, _stop) = proxy(&["localhost"], false, IDLE_TIMEOUT).await;

        for (request, status) in [
            (
                "CONNECT evil.example:443 HTTP/1.1\r\n\r\n".to_string(),
                "403",
            ),
            (format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n"), "403"),
            (
                format!("GET http://user@localhost:{port}/ HTTP/1.1\r\n\r\n"),
                "400",
            ),
            (
                "GET /relative HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string(),
                "400",
            ),
            ("CONNECT ::1:443 HTTP/1.1\r\n\r\n".to_string(), "400"),
        ] {
            let mut client = TcpStream::connect(proxy).await.unwrap();
            client.write_all(request.as_bytes()).await.unwrap();
            let response = read_all(&mut client).await;
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status}")),
                "{request}: {response}"
            );
        }
        assert_eq!(blocked.hosts(), vec!["evil.example", "localhost"]);
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

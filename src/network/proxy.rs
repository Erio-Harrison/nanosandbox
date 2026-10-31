//! The `allow_network` proxy: HTTP (absolute-form requests and `CONNECT` tunnels) and SOCKS5
//! on one port, told apart by the first byte. Each destination is checked against the deny
//! and allow lists (see [`Rule`]), resolved once, checked for non-public addresses (see
//! [`is_public`]), and connected to by address. What the proxy didn't connect to, and why,
//! is recorded per run.

use crate::result::{NetworkRefusal, RefusalReason};
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore, watch};

/// Connection timeout for proxy connections
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Idle timeout for a relayed connection (not a lifetime limit).
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Request line plus headers cap: the proxy runs in the host process, so a client mustn't
/// grow this unbounded.
const MAX_HEADER_BYTES: u64 = 64 * 1024;

/// How long a client gets to send its request headers (or SOCKS5 handshake).
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest chunk-size line of a chunked request body (the size in hex, plus extensions).
const MAX_CHUNK_LINE: u64 = 1024;

/// Open connections per listener. The proxy runs in the host process: without a cap a sandboxed
/// program could use up its file descriptors. Past the cap, accepting waits for one to close.
const MAX_CONNECTIONS: usize = 256;

/// Pause after a failed `accept` (EMFILE and the like), so it doesn't spin.
const ACCEPT_RETRY: Duration = Duration::from_millis(10);

/// Hop-by-hop request headers and ones the proxy sets itself; also any header `Connection`
/// names.
const HOP_BY_HOP: [&str; 7] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authorization",
    "te",
    "upgrade",
    "host",
];

const SOCKS5_VERSION: u8 = 5;

/// What the proxy lets through.
#[derive(Clone, Debug)]
pub(crate) struct Policy {
    allow: Vec<Rule>,
    /// Checked first.
    deny: Vec<Rule>,
    /// Whether allowed names may lead to loopback, private, link-local (cloud metadata) or other
    /// non-public addresses. Off by default: the proxy connects from the host's network.
    allow_private: bool,
    /// Whether a tunnel's TLS handshake must name the host the tunnel was opened to.
    require_host_match: bool,
    idle_timeout: Duration,
}

/// One allow or deny entry: a host (`example.com`), `*.example.com` (it and its subdomains),
/// or an IP address, each with an optional `:port` (any port without one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rule {
    /// Lowercased, brackets stripped, a leading `*.` kept.
    pattern: String,
    port: Option<u16>,
    /// Deny entries: told to the program and recorded with the refusal.
    reason: Option<String>,
}

impl Rule {
    /// Parses an entry, or says why it can't work: the host must be a DNS name, `*.` and a name
    /// with at least two labels (`*.com` would allow a whole TLD), or an IP address (in brackets
    /// if it has a port); a path, scheme or other junk would never match.
    pub(crate) fn parse(entry: &str) -> Result<Rule, &'static str> {
        let (host, port) =
            split_port(entry).ok_or("not `host`, `host:port`, `*.host` or an IP address")?;
        let port = match port {
            None => None,
            Some(p) => Some(
                p.parse::<u16>()
                    .ok()
                    .filter(|&p| p != 0)
                    .ok_or("the port must be 1-65535")?,
            ),
        };
        let host =
            normalize_host(host).ok_or("not `host`, `host:port`, `*.host` or an IP address")?;
        if host.parse::<IpAddr>().is_err() {
            match host.strip_prefix("*.") {
                Some(base) if !is_dns_name(base) => return Err("not a domain name after `*.`"),
                Some(base) if !base.contains('.') => {
                    return Err("`*.` needs a name with at least two labels");
                }
                Some(_) => {}
                None if host.contains('*') => return Err("`*` only works as a leading `*.`"),
                None if !is_dns_name(&host) => return Err("not a domain name or IP address"),
                None => {}
            }
        }
        Ok(Rule {
            pattern: host,
            port,
            reason: None,
        })
    }

    pub(crate) fn with_reason(mut self, reason: Option<String>) -> Self {
        self.reason = reason;
        self
    }

    /// Whether `host` (lowercased, no brackets) on `port` is what this entry names.
    fn matches(&self, host: &str, port: u16) -> bool {
        if self.port.is_some_and(|p| p != port) {
            return false;
        }
        if self.pattern == host {
            return true;
        }
        // An IP literal, or anything else that isn't a DNS name (`::ffff:1.2.3.4%x.example.com`),
        // matches only exactly. "*.example.com" matches example.com and anything ending in
        // ".example.com"; the dot stops "evilexample.com".
        self.pattern.strip_prefix('*').is_some_and(|dot_base| {
            host.parse::<IpAddr>().is_err()
                && is_dns_name(host)
                && (host.ends_with(dot_base) || host == &dot_base[1..])
        })
    }
}

/// `host`, `host:port`, `[v6]`, `[v6]:port`, or a bare IPv6 address (no port) as host and port
/// text. `None` for an empty host or a bracket mismatch.
fn split_port(entry: &str) -> Option<(&str, Option<&str>)> {
    let (host, port) = match entry.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']')?;
            let port = match after {
                "" => None,
                p => Some(p.strip_prefix(':')?),
            };
            (host, port)
        }
        None => match entry.rsplit_once(':') {
            // More than one colon without brackets: a bare IPv6 address.
            Some((host, _)) if host.contains(':') => (entry, None),
            Some((host, port)) => (host, Some(port)),
            None => (entry, None),
        },
    };
    (!host.is_empty()).then_some((host, port))
}

impl Policy {
    /// Whether the policy lets a connection to `host:port` be tried.
    fn check(&self, host: &str, port: u16) -> Result<(), RefusalReason> {
        if let Some(rule) = self.deny.iter().find(|r| r.matches(host, port)) {
            return Err(RefusalReason::Denied(rule.reason.clone()));
        }
        if self.allow.iter().any(|r| r.matches(host, port)) {
            Ok(())
        } else {
            Err(RefusalReason::NotAllowed)
        }
    }
}

/// What the proxy didn't connect a run to, and how often it was asked.
#[derive(Debug, Default)]
pub(crate) struct Refusals(Mutex<BTreeMap<(String, u16, RefusalReason), u32>>);

impl Refusals {
    fn record(&self, host: &str, port: u16, reason: RefusalReason) {
        if let Ok(mut all) = self.0.lock() {
            *all.entry((host.to_string(), port, reason)).or_default() += 1;
        }
    }

    /// Sorted by host and port.
    pub(crate) fn list(&self) -> Vec<NetworkRefusal> {
        self.0
            .lock()
            .map(|all| {
                all.iter()
                    .map(|((host, port, reason), attempts)| NetworkRefusal {
                        host: host.clone(),
                        port: *port,
                        reason: reason.clone(),
                        attempts: *attempts,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// HTTP and SOCKS5 proxy server with a destination allowlist.
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

impl ConnectError {
    fn reason(&self) -> RefusalReason {
        match self {
            Self::NotPublic => RefusalReason::NonPublicAddress,
            Self::Failed(_) => RefusalReason::Unreachable,
            Self::TimedOut => RefusalReason::TimedOut,
        }
    }
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
        body: Body,
    },
}

/// How a request body is delimited (RFC 7230 3.3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Body {
    /// Neither header: no body.
    None,
    Length(u64),
    Chunked,
}

/// How much of what the client sends goes on to the server.
#[derive(Clone, Copy)]
enum Forward<'a> {
    /// A tunnel: everything.
    All,
    /// A tunnel under `require_host_match`: everything, once its first bytes are seen to be
    /// either not TLS or a ClientHello that doesn't name another host.
    IfHostMatches { host: &'a str, port: u16 },
    /// One request's body, then the server side is half-closed: a pipelined second request,
    /// with a `Host` of its own, never reaches the server.
    Body(Body),
}

/// Why a relay direction stopped before its stream ended.
enum Stop {
    Io(std::io::Error),
    /// The tunnel's TLS hello named another host (or couldn't be read): the whole connection
    /// is cut.
    Cut,
}

impl From<std::io::Error> for Stop {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// What a tunnel's first bytes say about it.
#[derive(Debug, PartialEq, Eq)]
enum Hello {
    NeedMore,
    NotTls,
    /// A TLS ClientHello, with its server name if it has one.
    Tls(Option<String>),
    /// TLS handshake records that don't hold a readable ClientHello.
    Malformed,
}

impl HttpProxy {
    /// Create a proxy for `allowed` entries (`host`, `host:port`, `*.host` or an IP address;
    /// entries that can't work are dropped, `ProxiedNetwork::setup` refuses them first)
    /// listening on `port` (0 for any).
    pub fn new(allowed: Vec<String>, port: u16) -> Self {
        Self {
            policy: Arc::new(Policy {
                allow: allowed.iter().filter_map(|e| Rule::parse(e).ok()).collect(),
                deny: Vec::new(),
                allow_private: false,
                require_host_match: false,
                idle_timeout: IDLE_TIMEOUT,
            }),
            listen_addr: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    /// Entries refused even if allowed, each with an optional reason for the program.
    pub fn deny(mut self, denied: Vec<(String, Option<String>)>) -> Self {
        Arc::make_mut(&mut self.policy).deny = denied
            .into_iter()
            .filter_map(|(e, reason)| Rule::parse(&e).ok().map(|r| r.with_reason(reason)))
            .collect();
        self
    }

    /// Let allowed domains lead to loopback, private, link-local and other
    /// non-public addresses too. Off by default.
    pub fn allow_private_destinations(mut self, allow: bool) -> Self {
        Arc::make_mut(&mut self.policy).allow_private = allow;
        self
    }

    /// Cut a tunnel whose TLS handshake names a host other than the one it was opened to.
    /// Off by default.
    pub fn require_host_match(mut self, require: bool) -> Self {
        Arc::make_mut(&mut self.policy).require_host_match = require;
        self
    }

    /// Get the listen address
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Run the proxy until the shutdown signal. If `bound` is given, the listen address (or bind
    /// error) is sent on it once the listener is up, before the accept loop starts.
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
        let refusals = Arc::new(Refusals::default());
        Self::serve(listener, Arc::clone(&self.policy), refusals, stop).await;
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
    /// recording what it didn't connect to in `refusals`. Connections still open then are
    /// cut: a run's listener stops when the run is over.
    pub(crate) async fn serve(
        listener: TcpListener,
        policy: Arc<Policy>,
        refusals: Arc<Refusals>,
        stop: impl std::future::Future<Output = ()>,
    ) {
        Self::serve_at_most(MAX_CONNECTIONS, listener, policy, refusals, stop).await
    }

    /// `serve` with at most `limit` connections open at once; the next is accepted when one
    /// closes.
    async fn serve_at_most(
        limit: usize,
        listener: TcpListener,
        policy: Arc<Policy>,
        refusals: Arc<Refusals>,
        stop: impl std::future::Future<Output = ()>,
    ) {
        tokio::pin!(stop);
        let mut connections = tokio::task::JoinSet::new();
        let slots = Arc::new(Semaphore::new(limit));
        loop {
            // A slot first, then a connection for it: nothing is accepted just to be dropped.
            let slot = tokio::select! {
                slot = Arc::clone(&slots).acquire_owned() => slot.expect("the semaphore is never closed"),
                Some(_) = connections.join_next(), if !connections.is_empty() => continue,
                _ = &mut stop => break,
            };
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let policy = Arc::clone(&policy);
                            let refusals = Arc::clone(&refusals);
                            connections.spawn(async move {
                                let _slot = slot;
                                if let Err(e) = Self::handle_connection(stream, &policy, &refusals).await {
                                    tracing::debug!("Connection from {} error: {:?}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("Accept error: {:?}", e);
                            tokio::time::sleep(ACCEPT_RETRY).await;
                        }
                    }
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
                _ = &mut stop => break,
            }
        }
        // Dropping `connections` aborts the ones still open.
    }

    async fn handle_connection(
        mut client: TcpStream,
        policy: &Policy,
        refusals: &Refusals,
    ) -> std::io::Result<()> {
        // A SOCKS5 client starts with its version byte; an HTTP request line starts with a method.
        let mut first = [0u8; 1];
        match tokio::time::timeout(HEADER_TIMEOUT, client.peek(&mut first)).await {
            Ok(Ok(1)) if first[0] == SOCKS5_VERSION => {
                return Self::handle_socks5(client, policy, refusals).await;
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()),
        }

        let mut reader = BufReader::new(&mut client);
        let head = match tokio::time::timeout(HEADER_TIMEOUT, Self::read_headers(&mut reader)).await
        {
            Ok(Ok(Some(head))) => head,
            Ok(Ok(None)) => {
                drop(reader);
                return Self::send_status(&mut client, 431, "Request Header Fields Too Large")
                    .await;
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                tracing::debug!("Timed out waiting for request headers");
                return Ok(());
            }
        };
        // Bytes the client sent right after its headers (request body or TLS handshake start);
        // forwarded to the destination first.
        let early = reader.buffer().to_vec();
        drop(reader);

        let request = match Self::parse_request(&head) {
            Ok(request) => request,
            Err(reason) => return Self::send_status(&mut client, 400, reason).await,
        };
        let (host, port) = match &request {
            Request::Connect { host, port } | Request::Http { host, port, .. } => (host, *port),
        };
        tracing::debug!("Request for {host}:{port}");

        if let Err(reason) = policy.check(host, port) {
            tracing::info!("Refused {host}:{port}: {}", reason.code());
            refusals.record(host, port, reason.clone());
            return Self::send_refusal(&mut client, 403, &reason, host, port).await;
        }
        let mut remote = match Self::connect(host, port, policy).await {
            Ok(remote) => remote,
            Err(e) => {
                let reason = e.reason();
                tracing::info!("Refused {host}:{port}: {} ({e})", reason.code());
                refusals.record(host, port, reason.clone());
                let status = match e {
                    ConnectError::NotPublic => 403,
                    ConnectError::Failed(_) => 502,
                    ConnectError::TimedOut => 504,
                };
                return Self::send_refusal(&mut client, status, &reason, host, port).await;
            }
        };

        let forward = match &request {
            Request::Connect { .. } => {
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                Self::tunnel_forward(policy, host, port)
            }
            Request::Http {
                method,
                authority,
                path,
                version,
                body,
                ..
            } => {
                let head = Self::forwarded_head(&head, method, path, version, authority);
                remote.write_all(head.as_bytes()).await?;
                Forward::Body(*body)
            }
        };
        Self::relay(client, remote, early, forward, policy, refusals).await
    }

    /// What a tunnel to `host:port` forwards: everything, or under `require_host_match` only
    /// once its first bytes are checked.
    fn tunnel_forward<'a>(policy: &Policy, host: &'a str, port: u16) -> Forward<'a> {
        if policy.require_host_match {
            Forward::IfHostMatches { host, port }
        } else {
            Forward::All
        }
    }

    /// A SOCKS5 client (RFC 1928): no authentication, `CONNECT` only, the destination by name
    /// or address. Refusals are reply 2 ("not allowed by ruleset"); a failed connection 5, a
    /// timeout 4.
    async fn handle_socks5(
        mut client: TcpStream,
        policy: &Policy,
        refusals: &Refusals,
    ) -> std::io::Result<()> {
        let handshake = async {
            let mut greeting = [0u8; 2];
            client.read_exact(&mut greeting).await?;
            let mut methods = vec![0u8; greeting[1] as usize];
            client.read_exact(&mut methods).await?;
            if !methods.contains(&0) {
                client.write_all(&[SOCKS5_VERSION, 0xff]).await?;
                return Ok(None);
            }
            client.write_all(&[SOCKS5_VERSION, 0]).await?;

            let mut request = [0u8; 4];
            client.read_exact(&mut request).await?;
            let [version, command, _, address_type] = request;
            if version != SOCKS5_VERSION {
                return Ok(None);
            }
            let host = match address_type {
                1 => {
                    let mut ip = [0u8; 4];
                    client.read_exact(&mut ip).await?;
                    Ipv4Addr::from(ip).to_string()
                }
                4 => {
                    let mut ip = [0u8; 16];
                    client.read_exact(&mut ip).await?;
                    Ipv6Addr::from(ip).to_string()
                }
                3 => {
                    let mut len = [0u8; 1];
                    client.read_exact(&mut len).await?;
                    let mut name = vec![0u8; len[0] as usize];
                    client.read_exact(&mut name).await?;
                    // Arbitrary bytes otherwise, and they'd end up in logs and the result.
                    match std::str::from_utf8(&name).ok().and_then(normalize_host) {
                        Some(host) if is_dns_name(&host) || host.parse::<IpAddr>().is_ok() => host,
                        _ => {
                            tracing::debug!(
                                "SOCKS5 request with an invalid destination name ({} bytes)",
                                name.len()
                            );
                            Self::socks5_reply(&mut client, 1).await?;
                            return Ok(None);
                        }
                    }
                }
                _ => {
                    Self::socks5_reply(&mut client, 8).await?;
                    return Ok(None);
                }
            };
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            Ok::<_, std::io::Error>(Some((command, host, u16::from_be_bytes(port))))
        };
        let Some((command, host, port)) = tokio::time::timeout(HEADER_TIMEOUT, handshake)
            .await
            .unwrap_or(Ok(None))?
        else {
            return Ok(());
        };
        if command != 1 {
            return Self::socks5_reply(&mut client, 7).await;
        }
        tracing::debug!("SOCKS5 request for {host}:{port}");

        if let Err(reason) = policy.check(&host, port) {
            tracing::info!("Refused {host}:{port}: {}", reason.code());
            refusals.record(&host, port, reason);
            return Self::socks5_reply(&mut client, 2).await;
        }
        let remote = match Self::connect(&host, port, policy).await {
            Ok(remote) => remote,
            Err(e) => {
                let reason = e.reason();
                tracing::info!("Refused {host}:{port}: {} ({e})", reason.code());
                refusals.record(&host, port, reason);
                let code = match e {
                    ConnectError::NotPublic => 2,
                    ConnectError::Failed(_) => 5,
                    ConnectError::TimedOut => 4,
                };
                return Self::socks5_reply(&mut client, code).await;
            }
        };
        Self::socks5_reply(&mut client, 0).await?;
        let forward = Self::tunnel_forward(policy, &host, port);
        Self::relay(client, remote, Vec::new(), forward, policy, refusals).await
    }

    /// `code` 0 is success; the bound address is reported as unspecified.
    async fn socks5_reply(client: &mut TcpStream, code: u8) -> std::io::Result<()> {
        client
            .write_all(&[SOCKS5_VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
    }

    /// Reads the start of a tunnel into `held` until it is plainly not TLS, or holds a whole
    /// TLS ClientHello. Why the tunnel must be cut, if it must: the hello names another host
    /// than `host`, or is TLS that can't be read (malformed, over `MAX_HEADER_BYTES`, or cut
    /// off). Nothing is forwarded meanwhile, so there is no window to slip a hello through
    /// unchecked; a client that never speaks is the idle timeout's business.
    async fn hello_mismatch<R: AsyncRead + Unpin>(
        client: &mut R,
        held: &mut Vec<u8>,
        host: &str,
    ) -> std::io::Result<Option<String>> {
        loop {
            match client_hello_sni(held) {
                Hello::NeedMore if (held.len() as u64) < MAX_HEADER_BYTES => {}
                Hello::NeedMore => return Ok(Some("TLS hello too long to check".into())),
                Hello::Malformed => return Ok(Some("TLS hello can't be read".into())),
                Hello::NotTls => return Ok(None),
                Hello::Tls(Some(name)) if name != host => {
                    return Ok(Some(format!("TLS hello names {name}")));
                }
                Hello::Tls(_) => return Ok(None),
            }
            let mut buf = [0u8; 4096];
            match client.read(&mut buf).await? {
                // Half-closed before saying anything: nothing to check. Mid-hello: can't check.
                0 if held.is_empty() => return Ok(None),
                0 => return Ok(Some("TLS hello cut off".into())),
                n => held.extend_from_slice(&buf[..n]),
            }
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
            if budget == 0 {
                // Checked before read_line: a line landing exactly on the cap makes take(0) read 0 bytes,
                // same as EOF.
                return Ok(None);
            }
            let mut line = String::new();
            let n = (&mut *reader).take(budget).read_line(&mut line).await?;
            all_headers.push_str(&line);
            if n == 0 || line == "\r\n" || line == "\n" {
                return Ok(Some(all_headers));
            }
            if !line.ends_with('\n') {
                let within = (all_headers.len() as u64) < MAX_HEADER_BYTES;
                return Ok(within.then_some(all_headers));
            }
        }
    }

    /// The request line's target, or why it can't be served.
    fn parse_request(head: &str) -> Result<Request<'_>, &'static str> {
        // Obsolete line folding (RFC 7230 3.2.4) is refused: `forwarded_head` strips hop-by-hop
        // headers line by line, so a folded line could smuggle Host or Proxy-Authorization past it.
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
        // Absolute form only: routing by Host would trust a client-controlled header.
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
            body: Self::request_body(head)?,
        })
    }

    /// How the request's body is delimited, from its headers (RFC 7230 3.3.3). Refused when
    /// it's ambiguous: both headers, more than one `Content-Length`, or one that isn't a
    /// decimal, or a `Transfer-Encoding` not ending in `chunked`.
    fn request_body(head: &str) -> Result<Body, &'static str> {
        let mut length = None;
        let mut encoding = None;
        for line in head.lines().skip(1).take_while(|line| !line.is_empty()) {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            if name.trim().eq_ignore_ascii_case("content-length") {
                let valid = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
                let parsed = valid.then(|| value.parse::<u64>().ok()).flatten();
                if length.is_some() || parsed.is_none() {
                    return Err("Bad Content-Length");
                }
                length = parsed;
            } else if name.trim().eq_ignore_ascii_case("transfer-encoding") {
                let last = value.rsplit(',').next().unwrap_or("").trim();
                if encoding.is_some() || !last.eq_ignore_ascii_case("chunked") {
                    return Err("Unsupported Transfer-Encoding");
                }
                encoding = Some(Body::Chunked);
            }
        }
        match (length, encoding) {
            (Some(_), Some(_)) => Err("Content-Length with Transfer-Encoding"),
            (Some(n), None) => Ok(Body::Length(n)),
            (None, Some(chunked)) => Ok(chunked),
            (None, None) => Ok(Body::None),
        }
    }

    /// The request head to send on: path instead of URL, `Host` set to the checked URL's,
    /// hop-by-hop headers dropped, `Connection: close`. One request per connection: the body
    /// is forwarded by its framing and anything after it isn't (see `Forward::Body`).
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

    /// Copies both ways: `early` and then what the client sends, as far as `forward` says, to
    /// the server; everything the server sends, from the start, to the client. A finished side
    /// is half-closed and the other direction carries on. Ends when both are done, either
    /// fails, the tunnel is cut (recorded as `HostMismatch`), or nothing moves for the policy's
    /// idle timeout.
    async fn relay(
        client: TcpStream,
        remote: TcpStream,
        early: Vec<u8>,
        forward: Forward<'_>,
        policy: &Policy,
        refusals: &Refusals,
    ) -> std::io::Result<()> {
        let idle = policy.idle_timeout;
        let (client_read, mut client_write) = client.into_split();
        let (mut remote_read, remote_write) = remote.into_split();
        let activity = Notify::new();

        let upstream = Self::forward_client(
            client_read,
            remote_write,
            early,
            forward,
            &activity,
            refusals,
        );
        let downstream = async {
            Self::pipe(&mut remote_read, &mut client_write, &activity).await?;
            client_write.shutdown().await?;
            Ok::<_, Stop>(())
        };
        let both = async { tokio::try_join!(upstream, downstream) };
        let watchdog = async {
            while tokio::time::timeout(idle, activity.notified())
                .await
                .is_ok()
            {}
        };
        tokio::select! {
            result = both => match result {
                Ok(_) | Err(Stop::Cut) => Ok(()),
                Err(Stop::Io(e)) => Err(e),
            },
            _ = watchdog => {
                tracing::debug!("Closing a connection idle for {idle:?}");
                Ok(())
            }
        }
    }

    /// The client-to-server direction: `held` (what came with the request) and then the
    /// client's bytes, as far as `forward` says, then a half-close. Under `IfHostMatches`
    /// nothing goes out until the first bytes are checked.
    async fn forward_client(
        mut client: tokio::net::tcp::OwnedReadHalf,
        mut remote: tokio::net::tcp::OwnedWriteHalf,
        mut held: Vec<u8>,
        forward: Forward<'_>,
        activity: &Notify,
        refusals: &Refusals,
    ) -> Result<(), Stop> {
        if let Forward::IfHostMatches { host, port } = forward
            && let Some(why) = Self::hello_mismatch(&mut client, &mut held, host).await?
        {
            tracing::info!("Cut tunnel to {host}:{port}: its {why}");
            refusals.record(host, port, RefusalReason::HostMismatch);
            return Err(Stop::Cut);
        }
        let mut source = std::io::Cursor::new(held).chain(client);
        match forward {
            Forward::All | Forward::IfHostMatches { .. } => {
                Self::pipe(&mut source, &mut remote, activity).await?;
            }
            Forward::Body(Body::None) => {}
            Forward::Body(Body::Length(n)) => {
                Self::pipe(&mut (&mut source).take(n), &mut remote, activity).await?;
            }
            Forward::Body(Body::Chunked) => {
                Self::forward_chunked(&mut BufReader::new(&mut source), &mut remote, activity)
                    .await?;
            }
        }
        remote.shutdown().await?;
        Ok(())
    }

    /// Copies `from` to `to` until `from` ends, noting each move on `activity`.
    async fn pipe<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        from: &mut R,
        to: &mut W,
        activity: &Notify,
    ) -> std::io::Result<()> {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = from.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            to.write_all(&buf[..n]).await?;
            activity.notify_one();
        }
    }

    /// Copies one chunked body (RFC 7230 4.1): each chunk by its declared size, through the
    /// last (empty) chunk and the trailer section's blank line. Framing that doesn't parse is
    /// an error (the head already went out, so the connection is dropped).
    async fn forward_chunked<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        from: &mut R,
        to: &mut W,
        activity: &Notify,
    ) -> std::io::Result<()> {
        let bad = || std::io::Error::new(std::io::ErrorKind::InvalidData, "bad chunked body");
        loop {
            let mut line = String::new();
            (&mut *from)
                .take(MAX_CHUNK_LINE)
                .read_line(&mut line)
                .await?;
            if !line.ends_with('\n') {
                return Err(bad());
            }
            // `size[;extensions]`
            let size = line.trim_end().split(';').next().unwrap_or("").trim();
            let size = u64::from_str_radix(size, 16).map_err(|_| bad())?;
            to.write_all(line.as_bytes()).await?;
            activity.notify_one();
            if size == 0 {
                break;
            }
            Self::pipe(&mut (&mut *from).take(size), to, activity).await?;
            let mut crlf = [0u8; 2];
            from.read_exact(&mut crlf).await?;
            if crlf != *b"\r\n" {
                return Err(bad());
            }
            to.write_all(&crlf).await?;
        }
        let mut budget = MAX_HEADER_BYTES;
        loop {
            let mut line = String::new();
            let n = (&mut *from).take(budget).read_line(&mut line).await? as u64;
            if !line.ends_with('\n') {
                return Err(bad());
            }
            budget -= n;
            to.write_all(line.as_bytes()).await?;
            if line == "\r\n" || line == "\n" {
                return Ok(());
            }
        }
    }

    /// Resolves `host` once and connects to one of the allowed addresses by address, so the name
    /// can't re-resolve elsewhere (DNS rebinding).
    async fn connect(host: &str, port: u16, policy: &Policy) -> Result<TcpStream, ConnectError> {
        let attempt = async {
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
                .await
                .map_err(ConnectError::Failed)?
                .collect();
            let usable: Vec<&SocketAddr> = resolved
                .iter()
                .filter(|a| policy.allow_private || (is_public(a.ip()) && !is_own_address(a.ip())))
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

    /// A refusal the program can act on: the reason's code in `X-Proxy-Error`, and a line
    /// saying what was refused and why.
    async fn send_refusal(
        client: &mut TcpStream,
        status: u16,
        reason: &RefusalReason,
        host: &str,
        port: u16,
    ) -> std::io::Result<()> {
        let phrase = match status {
            403 => "Forbidden",
            502 => "Bad Gateway",
            _ => "Gateway Timeout",
        };
        let body = format!("nanosandbox: {}\n", describe(reason, host, port));
        let response = format!(
            "HTTP/1.1 {status} {phrase}\r\nX-Proxy-Error: {}\r\nContent-Type: text/plain\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            reason.code(),
            body.len(),
        );
        client.write_all(response.as_bytes()).await
    }

    async fn send_status(client: &mut TcpStream, code: u16, msg: &str) -> std::io::Result<()> {
        let body = format!("nanosandbox proxy: {code} {msg}\n");
        let response = format!(
            "HTTP/1.1 {code} {msg}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len(),
        );
        client.write_all(response.as_bytes()).await
    }
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPublic => f.write_str("resolves only to non-public addresses"),
            Self::Failed(e) => write!(f, "{e}"),
            Self::TimedOut => f.write_str("connect timed out"),
        }
    }
}

/// One line for the program about a refusal.
fn describe(reason: &RefusalReason, host: &str, port: u16) -> String {
    let what = format!("{host}:{port}");
    match reason {
        RefusalReason::NotAllowed => format!("{what} is not on the network allowlist"),
        RefusalReason::Denied(Some(why)) => format!("{what} is denied: {why}"),
        RefusalReason::Denied(None) => format!("{what} is on the network deny list"),
        RefusalReason::NonPublicAddress => {
            format!("{what} resolves only to a loopback, private or other non-public address")
        }
        RefusalReason::HostMismatch => {
            format!("the TLS handshake to {what} named another host")
        }
        RefusalReason::Unreachable => format!("could not connect to {what}"),
        RefusalReason::TimedOut => format!("connecting to {what} timed out"),
    }
}

/// The server name in the TLS ClientHello that `buf` starts with. The hello may span several
/// handshake records (type 0x16): their bodies are joined until the handshake message's
/// declared length is in; `NeedMore` until then. Records that don't add up to a ClientHello
/// are `Malformed`, so a hello the proxy can't read is never relayed on trust.
fn client_hello_sni(buf: &[u8]) -> Hello {
    match buf.first() {
        None => return Hello::NeedMore,
        Some(0x16) => {}
        Some(_) => return Hello::NotTls,
    }
    let mut handshake = Vec::new();
    let mut at = 0usize;
    loop {
        // Enough of the handshake header to know its length, and then the whole message.
        if handshake.len() >= 4 {
            let declared = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]);
            if handshake.len() >= 4 + declared as usize {
                return parse_client_hello(&handshake[..4 + declared as usize]);
            }
        }
        let Some(header) = buf.get(at..at + 5) else {
            return Hello::NeedMore;
        };
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        // Every record a handshake fragment (RFC 8446 5.1 also forbids empty ones).
        if header[0] != 0x16 || record_len == 0 {
            return Hello::Malformed;
        }
        let Some(body) = buf.get(at + 5..at + 5 + record_len) else {
            return Hello::NeedMore;
        };
        handshake.extend_from_slice(body);
        at += 5 + record_len;
    }
}

/// The `server_name` extension's host name in a complete handshake message, normalized, if
/// the message is a ClientHello that parses.
fn parse_client_hello(message: &[u8]) -> Hello {
    fn parse(message: &[u8]) -> Option<Option<String>> {
        let at = std::cell::Cell::new(0usize);
        let take = |n: usize| -> Option<&[u8]> {
            let slice = message.get(at.get()..at.get() + n)?;
            at.set(at.get() + n);
            Some(slice)
        };
        let u8_at = |b: &[u8]| b[0] as usize;
        let u16_at = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]) as usize;

        if u8_at(take(1)?) != 1 {
            return None; // not a ClientHello
        }
        take(3)?; // handshake length
        take(2)?; // legacy version
        take(32)?; // random
        let n = u8_at(take(1)?);
        take(n)?; // session id
        let n = u16_at(take(2)?);
        take(n)?; // cipher suites
        let n = u8_at(take(1)?);
        take(n)?; // compression methods
        if at.get() == message.len() {
            return Some(None); // no extensions at all
        }
        let extensions_len = u16_at(take(2)?);
        let extensions = take(extensions_len)?;

        let mut at = 0usize;
        while at + 4 <= extensions.len() {
            let kind = u16_at(&extensions[at..]);
            let len = u16_at(&extensions[at + 2..]);
            let data = extensions.get(at + 4..at + 4 + len)?;
            at += 4 + len;
            if kind != 0 {
                continue;
            }
            // ServerNameList: length, then entries of type (0 = host_name), length, name.
            let list_len = u16_at(data.get(..2)?);
            let list = data.get(2..2 + list_len)?;
            let mut p = 0usize;
            while p + 3 <= list.len() {
                let name_type = list[p];
                let name_len = u16_at(&list[p + 1..]);
                let name = list.get(p + 3..p + 3 + name_len)?;
                if name_type == 0 {
                    return Some(normalize_host(std::str::from_utf8(name).ok()?));
                }
                p += 3 + name_len;
            }
            return Some(None);
        }
        Some(None)
    }
    match parse(message) {
        Some(sni) => Hello::Tls(sni),
        None => Hello::Malformed,
    }
}

/// `host`, `host:port`, `[v6]` or `[v6]:port` as normalized host and port (`default` if none).
/// `None` for anything else, including `user@host` (userinfo can disguise the destination).
fn parse_authority(authority: &str, default: u16) -> Option<(String, u16)> {
    if authority.contains('@') {
        return None;
    }
    let (host, port) = split_port(authority)?;
    if host.contains(':') && !authority.starts_with('[') {
        // A bare IPv6 address: its last group can't be told from a port.
        return None;
    }
    let port = match port {
        None => default,
        Some(p) => p.parse().ok().filter(|&p| p != 0)?,
    };
    Some((normalize_host(host)?, port))
}

/// `host` as rules, refusals and matching see it: lowercased, one trailing dot (a fully
/// qualified `example.com.`) dropped. `None` if nothing is left.
fn normalize_host(host: &str) -> Option<String> {
    let host = host.strip_suffix('.').unwrap_or(host);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Letters, digits, `-` and `_` in dot-separated labels, none empty.
fn is_dns_name(host: &str) -> bool {
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// This machine's own interface addresses: a service bound to all interfaces answers on them
/// just as on loopback, so they count as non-public. Enumerated only on Unix; elsewhere this is
/// always false (loopback and the private ranges are still caught by `is_public`).
fn is_own_address(ip: IpAddr) -> bool {
    #[cfg(unix)]
    if let Ok(addrs) = nix::ifaddrs::getifaddrs() {
        return addrs.filter_map(|a| a.address).any(|a| {
            a.as_sockaddr_in().map(|s| IpAddr::V4(s.ip())) == Some(ip)
                || a.as_sockaddr_in6().map(|s| IpAddr::V6(s.ip())) == Some(ip)
        });
    }
    let _ = ip;
    false
}

/// Whether `ip` is on the public internet (not loopback, private, link-local, CGNAT,
/// multicast, reserved...). IPv6 addresses embedding IPv4 are judged by it.
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
        || o == [168, 63, 129, 16] // Azure's platform endpoint (metadata, agent)
        || o[0] >= 240) // reserved, and broadcast
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::oneshot;

    fn make_policy(allow: &[&str], deny: &[(&str, Option<&str>)]) -> Policy {
        Policy {
            allow: allow.iter().map(|e| Rule::parse(e).unwrap()).collect(),
            deny: deny
                .iter()
                .map(|(e, why)| Rule::parse(e).unwrap().with_reason(why.map(String::from)))
                .collect(),
            allow_private: false,
            require_host_match: false,
            idle_timeout: IDLE_TIMEOUT,
        }
    }

    #[test]
    fn test_rules_match_exactly() {
        let policy = make_policy(&["example.com"], &[]);
        assert_eq!(policy.check("example.com", 443), Ok(()));
        assert_eq!(policy.check("example.com", 22), Ok(()));
        assert_eq!(
            policy.check("other.com", 443),
            Err(RefusalReason::NotAllowed)
        );
    }

    #[test]
    fn test_wildcard_rules() {
        let policy = make_policy(&["*.example.com"], &[]);
        for host in ["sub.example.com", "deep.sub.example.com", "example.com"] {
            assert_eq!(policy.check(host, 443), Ok(()), "{host}");
        }
        for host in [
            "other.com",
            // Only on a label boundary.
            "evilexample.com",
            "example.com.evil.com",
            // Not a DNS name: an IPv6 literal with a zone that happens to end in the base.
            "::ffff:1.2.3.4%x.example.com",
            "1.2.3.4.example.com%x",
        ] {
            assert_eq!(
                policy.check(host, 443),
                Err(RefusalReason::NotAllowed),
                "{host}"
            );
        }
    }

    #[test]
    fn test_port_rules() {
        let policy = make_policy(
            &[
                "api.example.com:443",
                "*.wild.org:8443",
                "[::1]:9000",
                "1.2.3.4",
            ],
            &[],
        );
        assert_eq!(policy.check("api.example.com", 443), Ok(()));
        assert_eq!(
            policy.check("api.example.com", 80),
            Err(RefusalReason::NotAllowed)
        );
        assert_eq!(policy.check("a.wild.org", 8443), Ok(()));
        assert_eq!(policy.check("wild.org", 8443), Ok(()));
        assert_eq!(
            policy.check("a.wild.org", 443),
            Err(RefusalReason::NotAllowed)
        );
        assert_eq!(policy.check("::1", 9000), Ok(()));
        assert_eq!(policy.check("::1", 9001), Err(RefusalReason::NotAllowed));
        assert_eq!(policy.check("1.2.3.4", 1), Ok(()));
    }

    #[test]
    fn test_deny_is_checked_first_and_carries_its_reason() {
        let policy = make_policy(
            &["*.github.com", "example.com"],
            &[
                ("github.com:22", Some("SSH is blocked; use an https remote")),
                ("example.com", None),
            ],
        );
        assert_eq!(policy.check("github.com", 443), Ok(()));
        assert_eq!(
            policy.check("github.com", 22),
            Err(RefusalReason::Denied(Some(
                "SSH is blocked; use an https remote".into()
            )))
        );
        assert_eq!(
            policy.check("example.com", 443),
            Err(RefusalReason::Denied(None))
        );
    }

    #[test]
    fn test_entries_that_cannot_work_are_refused() {
        for ok in [
            "example.com",
            "*.example.com",
            "*.co.uk",
            "localhost",
            "127.0.0.1",
            "::1",
            "[::1]",
            "[::1]:443",
            // An IPv6 address: a port needs brackets.
            "::1:443",
            "Example.COM",
            "example.com:443",
            "*.example.com:8443",
            "1.2.3.4:80",
        ] {
            assert_eq!(Rule::parse(ok).map(|_| ()), Ok(()), "{ok}");
        }
        for bad in [
            "",
            "*",
            "*.com",
            "*.",
            "example.*",
            "a.*.example.com",
            "example.com:0",
            "example.com:99999",
            "example.com:x",
            "example.com:",
            "[::1]:",
            "[::1",
            "https://example.com",
            "example.com/path",
            "exa mple.com",
            ":443",
        ] {
            assert!(Rule::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn test_own_and_platform_addresses_are_not_public() {
        // getifaddrs is unix-only; elsewhere own-address isn't enumerated (loopback and the
        // other non-public ranges are still refused by is_public).
        #[cfg(unix)]
        assert!(is_own_address("127.0.0.1".parse().unwrap()));
        assert!(!is_public("168.63.129.16".parse().unwrap()));
        assert!(is_public("168.63.129.17".parse().unwrap()));
    }

    #[test]
    fn test_entries_are_normalized() {
        let proxy = HttpProxy::new(
            vec!["Mixed.Org".into(), "*.Upper.COM:443".into(), "[::1]".into()],
            0,
        );
        assert_eq!(proxy.policy.check("mixed.org", 80), Ok(()));
        assert_eq!(proxy.policy.check("a.upper.com", 443), Ok(()));
        assert_eq!(proxy.policy.check("::1", 80), Ok(()));
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

    /// Folded lines inherit a line-by-line stripper's decision for the header above them, so a
    /// stripped header could ride through under a kept one; such requests are refused.
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

        let long = vec![b'a'; 1024 * 1024];
        assert_eq!(HttpProxy::read_headers(&mut &long[..]).await.unwrap(), None);
        let many = b"X: y\r\n".repeat(100_000);
        assert_eq!(HttpProxy::read_headers(&mut &many[..]).await.unwrap(), None);
    }

    /// A line landing exactly on the cap used to read as EOF (`take(0)`) and be accepted as
    /// complete.
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

    /// A TLS ClientHello record naming `sni` (or none), as a client would send it.
    fn client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(name) = sni {
            let mut list = vec![0u8]; // host_name
            list.extend_from_slice(&(name.len() as u16).to_be_bytes());
            list.extend_from_slice(name.as_bytes());
            let mut data = (list.len() as u16).to_be_bytes().to_vec();
            data.extend_from_slice(&list);
            extensions.extend_from_slice(&[0, 0]);
            extensions.extend_from_slice(&(data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&data);
        }
        // Another extension after, to be skipped.
        extensions.extend_from_slice(&[0, 0x2b, 0, 3, 2, 3, 4]);
        let mut body = vec![3, 3]; // legacy version
        body.extend_from_slice(&[7u8; 32]); // random
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[1, 0]); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![1]; // ClientHello
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        let mut record = vec![0x16, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// `hello`, one record, re-framed as handshake records of at most `piece` bytes each.
    fn split_records(hello: &[u8], piece: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in hello[5..].chunks(piece) {
            out.extend_from_slice(&[0x16, 3, 1]);
            out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }

    #[test]
    fn test_client_hello_sni() {
        let hello = client_hello(Some("Example.COM."));
        let named = Hello::Tls(Some("example.com".into()));
        assert_eq!(client_hello_sni(&hello), named);
        assert_eq!(client_hello_sni(&hello[..hello.len() - 1]), Hello::NeedMore);
        assert_eq!(client_hello_sni(&hello[..3]), Hello::NeedMore);
        assert_eq!(client_hello_sni(&[]), Hello::NeedMore);
        assert_eq!(client_hello_sni(b"SSH-2.0-x"), Hello::NotTls);
        assert_eq!(client_hello_sni(&client_hello(None)), Hello::Tls(None));

        // Split over several records: the same hello, once all of it is in.
        for piece in [1, 7, 40, 1000] {
            let split = split_records(&hello, piece);
            assert_eq!(client_hello_sni(&split), named, "piece {piece}");
            assert_eq!(
                client_hello_sni(&split[..split.len() - 1]),
                Hello::NeedMore,
                "piece {piece}"
            );
        }
        // A continuation that isn't a handshake record, or is empty.
        let mut split = split_records(&hello, 7);
        split[5 + 7] = 0x17;
        assert_eq!(client_hello_sni(&split), Hello::Malformed);
        assert_eq!(
            client_hello_sni(&[0x16, 3, 1, 0, 0, 0x16, 3, 1, 0, 1, 1]),
            Hello::Malformed
        );
        // Garbage inside a well-framed record: unreadable, not "no name".
        let mut junk = vec![0x16, 3, 1, 0, 4];
        junk.extend_from_slice(&[1, 0, 0, 0]);
        assert_eq!(client_hello_sni(&junk), Hello::Malformed);
        let mut not_hello = hello.clone();
        not_hello[5] = 2; // ServerHello
        assert_eq!(client_hello_sni(&not_hello), Hello::Malformed);
    }

    #[test]
    fn test_request_body_framing() {
        let body = |headers: &str| {
            HttpProxy::request_body(&format!("GET http://a/ HTTP/1.1\r\n{headers}\r\n"))
        };
        assert_eq!(body(""), Ok(Body::None));
        assert_eq!(body("content-length: 12\r\n"), Ok(Body::Length(12)));
        assert_eq!(body("Transfer-Encoding: chunked\r\n"), Ok(Body::Chunked));
        assert_eq!(
            body("Transfer-Encoding: gzip, Chunked\r\n"),
            Ok(Body::Chunked)
        );
        for bad in [
            "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
            "Content-Length: 5\r\nContent-Length: 5\r\n",
            "Content-Length: 5, 5\r\n",
            "Content-Length: -1\r\n",
            "Content-Length: 0x10\r\n",
            "Content-Length:\r\n",
            "Content-Length: 99999999999999999999999\r\n",
            "Transfer-Encoding: gzip\r\n",
            "Transfer-Encoding: chunked, gzip\r\n",
        ] {
            assert!(body(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn test_trailing_dot_is_dropped() {
        assert_eq!(
            Rule::parse("Example.com."),
            Ok(Rule {
                pattern: "example.com".into(),
                port: None,
                reason: None,
            })
        );
        assert_eq!(
            Rule::parse("*.example.com.:443").map(|r| (r.pattern, r.port)),
            Ok(("*.example.com".into(), Some(443)))
        );
        assert!(Rule::parse(".").is_err());
        assert!(Rule::parse("example..").is_err());
        let policy = make_policy(&["example.com", "*.wild.org"], &[]);
        assert_eq!(
            parse_authority("Example.COM.", 80).unwrap().0,
            "example.com"
        );
        assert_eq!(parse_authority(".", 80), None);
        for authority in ["example.com.", "example.com.:443", "a.wild.org."] {
            let (host, port) = parse_authority(authority, 443).unwrap();
            assert_eq!(policy.check(&host, port), Ok(()), "{authority}");
        }
    }

    /// A proxy for `domains`, private destinations allowed (the test servers
    /// are on loopback). Stops when the sender is dropped.
    async fn proxy(
        domains: &[&str],
        allow_private: bool,
        idle_timeout: Duration,
    ) -> (SocketAddr, Arc<Refusals>, oneshot::Sender<()>) {
        let mut policy = make_policy(domains, &[]);
        policy.allow_private = allow_private;
        policy.idle_timeout = idle_timeout;
        proxy_with(policy).await
    }

    async fn proxy_with(policy: Policy) -> (SocketAddr, Arc<Refusals>, oneshot::Sender<()>) {
        proxy_limited(policy, MAX_CONNECTIONS).await
    }

    async fn proxy_limited(
        policy: Policy,
        limit: usize,
    ) -> (SocketAddr, Arc<Refusals>, oneshot::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let refusals = Arc::new(Refusals::default());
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let stop = async move {
            let _ = stop_rx.await;
        };
        tokio::spawn(HttpProxy::serve_at_most(
            limit,
            listener,
            Arc::new(policy),
            Arc::clone(&refusals),
            stop,
        ));
        (addr, refusals, stop_tx)
    }

    /// A policy allowing localhost on loopback, with `require_host_match` if asked.
    fn localhost_policy(require_host_match: bool) -> Policy {
        let mut p = make_policy(&["localhost"], &[]);
        p.allow_private = true;
        p.require_host_match = require_host_match;
        p
    }

    /// A tunnel through `proxy` to `localhost:port`, past the `200`.
    async fn connect_tunnel(proxy: SocketAddr, port: u16) -> TcpStream {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        assert!(read_head(&mut client).await.starts_with("HTTP/1.1 200"));
        client
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

    /// An echo server that reports what it got.
    async fn echo_upstream() -> u16 {
        upstream(|mut s| async move {
            let got = read_all(&mut s).await;
            let _ = s.write_all(format!("got:{got}").as_bytes()).await;
        })
        .await
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
                let request = read_all(&mut s).await;
                let _ = seen_tx.send(request);
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            }
        })
        .await;
        let (proxy, _, _stop) = proxy(&["localhost"], true, IDLE_TIMEOUT).await;

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
        let port = echo_upstream().await;
        let (proxy, _, _stop) = proxy(&["localhost"], true, IDLE_TIMEOUT).await;

        let mut client = TcpStream::connect(proxy).await.unwrap();
        let request = format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\nEARLY");
        client.write_all(request.as_bytes()).await.unwrap();
        assert!(read_head(&mut client).await.starts_with("HTTP/1.1 200"));
        client.write_all(b"+LATER").await.unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(read_all(&mut client).await, "got:EARLY+LATER");
    }

    /// SOCKS5 greeting and CONNECT request for `host:port`; the reply's status byte and the
    /// stream, ready for the tunnel.
    async fn socks5_connect(proxy: SocketAddr, host: &str, port: u16) -> (u8, TcpStream) {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        let mut request = vec![5, 1, 0, 3, host.len() as u8];
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 5);
        (reply[1], client)
    }

    #[tokio::test]
    async fn test_socks5_tunnels_and_refuses_by_the_same_policy() {
        let port = echo_upstream().await;
        let policy = {
            let mut p = make_policy(&["localhost"], &[("localhost:1", Some("port one"))]);
            p.allow_private = true;
            p
        };
        let (proxy, refusals, _stop) = proxy_with(policy).await;

        let (status, mut client) = socks5_connect(proxy, "LocalHost", port).await;
        assert_eq!(status, 0);
        client.write_all(b"hi").await.unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(read_all(&mut client).await, "got:hi");

        let (status, _) = socks5_connect(proxy, "evil.example", 443).await;
        assert_eq!(status, 2);
        let (status, _) = socks5_connect(proxy, "localhost", 1).await;
        assert_eq!(status, 2);
        // An IPv4 address, by address type 1.
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        client.read_exact(&mut [0u8; 2]).await.unwrap();
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 2);
        // UDP ASSOCIATE isn't offered.
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        client.read_exact(&mut [0u8; 2]).await.unwrap();
        client
            .write_all(&[5, 3, 0, 3, 1, b'a', 0, 80])
            .await
            .unwrap();
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 7);

        let listed: Vec<(String, u16, RefusalReason, u32)> = refusals
            .list()
            .into_iter()
            .map(|r| (r.host, r.port, r.reason, r.attempts))
            .collect();
        assert_eq!(
            listed,
            vec![
                ("127.0.0.1".into(), 80, RefusalReason::NotAllowed, 1),
                ("evil.example".into(), 443, RefusalReason::NotAllowed, 1),
                (
                    "localhost".into(),
                    1,
                    RefusalReason::Denied(Some("port one".into())),
                    1
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_host_match_cuts_a_tunnel_whose_handshake_names_another_host() {
        let port = echo_upstream().await;
        let policy = {
            let mut p = make_policy(&["localhost"], &[]);
            p.allow_private = true;
            p.require_host_match = true;
            p
        };
        let (proxy, refusals, _stop) = proxy_with(policy).await;

        let tunnel = |hello: Vec<u8>| async move {
            let mut client = TcpStream::connect(proxy).await.unwrap();
            client
                .write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n").as_bytes())
                .await
                .unwrap();
            assert!(read_head(&mut client).await.starts_with("HTTP/1.1 200"));
            // In two pieces: the second arrives after the proxy started looking.
            client.write_all(&hello[..4]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            client.write_all(&hello[4..]).await.unwrap();
            client.shutdown().await.unwrap();
            read_all(&mut client).await
        };
        let hello = client_hello(Some("localhost"));
        assert_eq!(
            tunnel(hello.clone()).await.len(),
            "got:".len() + hello.len()
        );
        // No name, or not TLS at all: nothing to check.
        assert!(tunnel(client_hello(None)).await.starts_with("got:"));
        assert_eq!(
            tunnel(b"SSH-2.0-client".to_vec()).await,
            "got:SSH-2.0-client"
        );
        assert!(refusals.list().is_empty());

        assert_eq!(tunnel(client_hello(Some("other.example"))).await, "");
        let (status, mut client) = socks5_connect(proxy, "localhost", port).await;
        assert_eq!(status, 0);
        client
            .write_all(&client_hello(Some("other.example")))
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(read_all(&mut client).await, "");
        let listed = refusals.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            (listed[0].reason.clone(), listed[0].attempts),
            (RefusalReason::HostMismatch, 2)
        );
    }

    /// A ClientHello spread over several TLS records is still read, so splitting it isn't a way
    /// past the check; one that can't be read is cut, not trusted.
    #[tokio::test]
    async fn test_host_match_reads_a_hello_split_over_records() {
        let port = echo_upstream().await;
        let (proxy, refusals, _stop) = proxy_with(localhost_policy(true)).await;

        let tunnel = |bytes: Vec<u8>| async move {
            let mut client = connect_tunnel(proxy, port).await;
            client.write_all(&bytes).await.unwrap();
            client.shutdown().await.unwrap();
            read_all(&mut client).await
        };
        let ok = split_records(&client_hello(Some("localhost")), 11);
        assert_eq!(tunnel(ok.clone()).await.len(), "got:".len() + ok.len());
        assert!(refusals.list().is_empty());

        assert_eq!(
            tunnel(split_records(&client_hello(Some("other.example")), 11)).await,
            ""
        );
        // A handshake record whose contents aren't a ClientHello.
        assert_eq!(tunnel(vec![0x16, 3, 1, 0, 4, 1, 0, 0, 0]).await, "");
        // A hello that stops short.
        let short = client_hello(Some("localhost"));
        assert_eq!(tunnel(short[..short.len() / 2].to_vec()).await, "");
        let listed = refusals.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            (listed[0].reason.clone(), listed[0].attempts),
            (RefusalReason::HostMismatch, 3)
        );
    }

    /// Nothing the client sends is forwarded until it's checked, however long it waits.
    #[tokio::test]
    async fn test_host_match_waits_for_the_hello() {
        let port = echo_upstream().await;
        let (proxy, refusals, _stop) = proxy_with(localhost_policy(true)).await;

        let mut client = connect_tunnel(proxy, port).await;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        client
            .write_all(&client_hello(Some("other.example")))
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(read_all(&mut client).await, "");
        assert_eq!(refusals.list().len(), 1);
    }

    /// The server's bytes flow from the start, so a protocol where it speaks first works, and
    /// the client's plainly-not-TLS bytes follow unchecked.
    #[tokio::test]
    async fn test_host_match_lets_the_server_speak_first() {
        let banner_first = upstream(|mut s| async move {
            s.write_all(b"220 hello\r\n").await.unwrap();
            let got = read_all(&mut s).await;
            let _ = s.write_all(format!("got:{got}").as_bytes()).await;
        })
        .await;
        let (proxy, refusals, _stop) = proxy_with(localhost_policy(true)).await;

        let mut client = connect_tunnel(proxy, banner_first).await;
        let mut banner = [0u8; 11];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut banner))
            .await
            .expect("banner before the client speaks")
            .unwrap();
        assert_eq!(&banner, b"220 hello\r\n");
        client.write_all(b"EHLO me\r\n").await.unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(read_all(&mut client).await, "got:EHLO me\r\n");
        assert!(refusals.list().is_empty());
    }

    /// Only the first request on a connection reaches the server: the second has a `Host` of
    /// its own that was never checked.
    #[tokio::test]
    async fn test_pipelined_request_does_not_reach_the_server() {
        let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let port = upstream(move |mut s| {
            let seen_tx = seen_tx.clone();
            async move {
                let request = read_all(&mut s).await;
                let _ = seen_tx.send(request);
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            }
        })
        .await;
        let (proxy, _, _stop) = proxy(&["localhost"], true, IDLE_TIMEOUT).await;

        for (first, second) in [
            ("", ""),
            ("Content-Length: 5\r\n\r\nHELLO", ""),
            (
                "Transfer-Encoding: chunked\r\n\r\n5\r\nHELLO\r\n0\r\nX-T: 1\r\n\r\n",
                "",
            ),
            // The second's body isn't mistaken for the first's trailer or next chunk.
            (
                "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                "Content-Length: 3\r\n\r\nabc",
            ),
        ] {
            let mut client = TcpStream::connect(proxy).await.unwrap();
            let first = match first {
                "" => "\r\n".to_string(),
                f => f.to_string(),
            };
            let second = match second {
                "" => "\r\n".to_string(),
                s => s.to_string(),
            };
            let pipelined = format!(
                "POST http://localhost:{port}/first HTTP/1.1\r\n{first}\
                 POST http://localhost:{port}/second HTTP/1.1\r\nHost: other.example\r\n{second}"
            );
            client.write_all(pipelined.as_bytes()).await.unwrap();
            // Not half-closed: the server must still get the whole first request.
            let seen = tokio::time::timeout(Duration::from_secs(5), seen_rx.recv())
                .await
                .expect("the server got the first request")
                .unwrap();
            assert!(seen.starts_with("POST /first HTTP/1.1\r\n"), "{seen}");
            assert!(
                !seen.contains("second") && !seen.contains("other.example"),
                "{seen}"
            );
            let (seen_head, seen_body) = seen.split_once("\r\n\r\n").unwrap();
            let expected_body = first.split_once("\r\n\r\n").map_or("", |(_, b)| b);
            assert_eq!(seen_body, expected_body, "{seen_head}");
            assert!(read_all(&mut client).await.ends_with("\r\n\r\nok"));
        }
    }

    #[tokio::test]
    async fn test_ambiguous_body_framing_is_refused() {
        let (proxy, _, _stop) = proxy(&["localhost"], true, IDLE_TIMEOUT).await;
        for headers in [
            "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
            "Content-Length: 5\r\nContent-Length: 6\r\n",
            "Content-Length: five\r\n",
        ] {
            let mut client = TcpStream::connect(proxy).await.unwrap();
            client
                .write_all(format!("POST http://localhost:1/ HTTP/1.1\r\n{headers}\r\n").as_bytes())
                .await
                .unwrap();
            let response = read_all(&mut client).await;
            assert!(
                response.starts_with("HTTP/1.1 400"),
                "{headers}: {response}"
            );
        }
    }

    /// Past the cap the next connection waits for a slot; it isn't dropped.
    #[tokio::test]
    async fn test_connections_past_the_cap_wait() {
        let port = echo_upstream().await;
        let (proxy, _, _stop) = proxy_limited(localhost_policy(false), 1).await;

        let first = connect_tunnel(proxy, port).await;
        let mut second = TcpStream::connect(proxy).await.unwrap();
        second
            .write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut byte = [0u8];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), second.read(&mut byte))
                .await
                .is_err(),
            "accepted past the cap"
        );
        drop(first);
        assert!(read_head(&mut second).await.starts_with("HTTP/1.1 200"));
    }

    /// A destination name that isn't one is refused outright, and not recorded: there is
    /// nothing trustworthy to record.
    #[tokio::test]
    async fn test_socks5_rejects_an_invalid_name_without_recording_it() {
        let (proxy, refusals, _stop) = proxy_with(localhost_policy(false)).await;
        for name in ["local\nhost", "a b", "", ".", "ex!ample", "lo\u{e9}calhost"] {
            let (status, _) = socks5_connect(proxy, name, 80).await;
            assert_eq!(status, 1, "{name:?}");
        }
        assert!(refusals.list().is_empty());
        // Valid names and IP literals still work (and are refused by policy, not form).
        for name in ["other.example.", "1.2.3.4", "::1"] {
            let (status, _) = socks5_connect(proxy, name, 80).await;
            assert_eq!(status, 2, "{name:?}");
        }
        let hosts: Vec<String> = refusals.list().into_iter().map(|r| r.host).collect();
        assert_eq!(hosts, ["1.2.3.4", "::1", "other.example"]);
    }

    /// A fully qualified name (`host.`) is the host, allowed and recorded as such.
    #[tokio::test]
    async fn test_fqdn_matches_and_is_recorded_without_the_dot() {
        let port = echo_upstream().await;
        let (proxy, refusals, _stop) = proxy_with(localhost_policy(false)).await;

        let mut client = TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(format!("CONNECT localhost.:{port} HTTP/1.1\r\n\r\nhi").as_bytes())
            .await
            .unwrap();
        assert!(read_head(&mut client).await.starts_with("HTTP/1.1 200"));
        client.shutdown().await.unwrap();
        assert_eq!(read_all(&mut client).await, "got:hi");

        let mut client = TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(b"CONNECT Other.Example.:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let response = read_all(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(response.contains("other.example:443 is not"), "{response}");
        let listed = refusals.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            (listed[0].host.as_str(), listed[0].port),
            ("other.example", 443)
        );
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
    async fn test_refusals_say_why_and_are_listed() {
        let port = upstream(|_| async {}).await;
        // A port nothing listens on.
        let closed = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        // localhost is allowed by name, but not to loopback; closed.test is, for the failure.
        let policy = {
            let mut p = make_policy(
                &["localhost", "127.0.0.1"],
                &[("localhost:1", Some("no port one"))],
            );
            p.deny.push(Rule::parse("localhost:2").unwrap());
            p
        };
        let (proxy, refusals, _stop) = proxy_with(policy).await;

        for (request, status, code, line) in [
            (
                "CONNECT evil.example:443 HTTP/1.1\r\n\r\n".to_string(),
                "403",
                "not-allowed",
                "evil.example:443 is not on the network allowlist",
            ),
            (
                format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n"),
                "403",
                "non-public-address",
                "non-public address",
            ),
            (
                "CONNECT localhost:1 HTTP/1.1\r\n\r\n".to_string(),
                "403",
                "denied",
                "localhost:1 is denied: no port one",
            ),
            (
                "GET http://localhost:2/ HTTP/1.1\r\n\r\n".to_string(),
                "403",
                "denied",
                "localhost:2 is on the network deny list",
            ),
            (
                format!("GET http://user@localhost:{port}/ HTTP/1.1\r\n\r\n"),
                "400",
                "",
                "",
            ),
            (
                "GET /relative HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string(),
                "400",
                "",
                "",
            ),
            (
                "CONNECT ::1:443 HTTP/1.1\r\n\r\n".to_string(),
                "400",
                "",
                "",
            ),
        ] {
            let mut client = TcpStream::connect(proxy).await.unwrap();
            client.write_all(request.as_bytes()).await.unwrap();
            let response = read_all(&mut client).await;
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status}")),
                "{request}: {response}"
            );
            if !code.is_empty() {
                assert!(
                    response.contains(&format!("\r\nX-Proxy-Error: {code}\r\n")),
                    "{request}: {response}"
                );
                assert!(response.contains(line), "{request}: {response}");
            }
        }
        let listed: Vec<(String, u16, &'static str, u32)> = refusals
            .list()
            .into_iter()
            .map(|r| (r.host, r.port, r.reason.code(), r.attempts))
            .collect();
        assert_eq!(
            listed,
            vec![
                ("evil.example".into(), 443, "not-allowed", 1),
                ("localhost".into(), 1, "denied", 1),
                ("localhost".into(), 2, "denied", 1),
                ("localhost".into(), port, "non-public-address", 1),
            ]
        );
        assert_eq!(
            NetworkRefusal::blocked_hosts(&refusals.list()),
            vec!["evil.example", "localhost"]
        );

        // A connection failure is a 502 and listed too, but isn't a blocked host.
        let policy = {
            let mut p = make_policy(&["127.0.0.1"], &[]);
            p.allow_private = true;
            p
        };
        let (proxy, refusals, _stop) = proxy_with(policy).await;
        for _ in 0..2 {
            let mut client = TcpStream::connect(proxy).await.unwrap();
            client
                .write_all(format!("CONNECT 127.0.0.1:{closed} HTTP/1.1\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let response = read_all(&mut client).await;
            assert!(response.starts_with("HTTP/1.1 502"), "{response}");
            assert!(
                response.contains("X-Proxy-Error: unreachable\r\n"),
                "{response}"
            );
        }
        let listed = refusals.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            (listed[0].port, listed[0].reason.clone(), listed[0].attempts),
            (closed, RefusalReason::Unreachable, 2)
        );
        assert!(NetworkRefusal::blocked_hosts(&listed).is_empty());
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

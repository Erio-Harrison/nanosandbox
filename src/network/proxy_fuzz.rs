//! Randomized checks of the proxy's parsers against properties and an independent reader.
//! Seeded, so a failure reproduces; `NANOSANDBOX_FUZZ_ITERS` raises the iteration count.

use super::tests::{echo_upstream, localhost_policy, proxy_limited};
use super::*;

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
    fn pick_ref<'a, T: ?Sized>(&mut self, items: &[&'a T]) -> &'a T {
        items[self.below(items.len())]
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
    fn some(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max);
        self.bytes(n)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn iterations(default: usize) -> usize {
    std::env::var("NANOSANDBOX_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---- TLS ClientHello ----

fn sni_ext(entries: &[(u8, &str)]) -> Vec<u8> {
    let mut list = Vec::new();
    for (kind, name) in entries {
        list.push(*kind);
        list.extend_from_slice(&(name.len() as u16).to_be_bytes());
        list.extend_from_slice(name.as_bytes());
    }
    let mut data = (list.len() as u16).to_be_bytes().to_vec();
    data.extend_from_slice(&list);
    extension(0, &data)
}

fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// A ClientHello handshake message with the given extensions.
fn hello_message(rng: &mut Rng, extensions: &[Vec<u8>]) -> Vec<u8> {
    let extensions: Vec<u8> = extensions.concat();
    let mut body = vec![3, 3];
    body.extend_from_slice(&rng.bytes(32));
    let sid = rng.below(33);
    body.push(sid as u8);
    body.extend_from_slice(&rng.bytes(sid));
    let ciphers = 1 + rng.below(8);
    body.extend_from_slice(&((ciphers * 2) as u16).to_be_bytes());
    body.extend_from_slice(&rng.bytes(ciphers * 2));
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut message = vec![1];
    message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    message.extend_from_slice(&body);
    message
}

fn records(message: &[u8], piece: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in message.chunks(piece) {
        out.extend_from_slice(&[0x16, 3, 1]);
        out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<usize> {
        Some(self.take(1)?[0] as usize)
    }
    fn u16(&mut self) -> Option<usize> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]) as usize)
    }
    fn prefixed16(&mut self) -> Option<Reader<'a>> {
        let n = self.u16()?;
        Some(Reader(self.take(n)?))
    }
}

/// What a strict server (OpenSSL-like: every length exact, no duplicates) takes from `message`
/// (one whole ClientHello handshake message): `None` if it would reject it, else the name.
fn strict_sni(message: &[u8]) -> Option<Option<String>> {
    let mut r = Reader(message);
    if r.u8()? != 1 {
        return None;
    }
    let declared = {
        let b = r.take(3)?;
        u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize
    };
    if declared != r.0.len() {
        return None;
    }
    r.take(2)?;
    r.take(32)?;
    let sid = r.u8()?;
    if sid > 32 {
        return None;
    }
    r.take(sid)?;
    let ciphers = r.prefixed16()?;
    if ciphers.0.is_empty() || ciphers.0.len() % 2 != 0 {
        return None;
    }
    let compression = r.u8()?;
    if compression == 0 {
        return None;
    }
    r.take(compression)?;
    if r.0.is_empty() {
        return Some(None);
    }
    let mut extensions = r.prefixed16()?;
    if !r.0.is_empty() {
        return None;
    }
    let mut seen = std::collections::HashSet::new();
    let mut name = None;
    while !extensions.0.is_empty() {
        let kind = extensions.u16()?;
        let mut data = extensions.prefixed16()?;
        if !seen.insert(kind) {
            return None;
        }
        if kind != 0 {
            continue;
        }
        let mut list = data.prefixed16()?;
        if !data.0.is_empty() || list.0.is_empty() {
            return None;
        }
        let mut host = None;
        while !list.0.is_empty() {
            let name_type = list.u8()?;
            let n = list.u16()?;
            let bytes = list.take(n)?;
            if name_type == 0 {
                if host.is_some() || bytes.is_empty() {
                    return None;
                }
                host = Some(String::from_utf8(bytes.to_vec()).ok()?);
            } else {
                return None;
            }
        }
        name = host;
    }
    Some(name.and_then(|n| normalize_host(&n)))
}

/// `strict_sni` over the handshake message the records in `buf` carry, if they carry one.
fn strict_view(buf: &[u8]) -> Option<Option<String>> {
    let mut handshake = Vec::new();
    let mut at = 0;
    loop {
        if handshake.len() >= 4 {
            let declared =
                u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
            if handshake.len() >= 4 + declared {
                return strict_sni(&handshake[..4 + declared]);
            }
        }
        let header = buf.get(at..at + 5)?;
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if header[0] != 0x16 || len == 0 {
            return None;
        }
        handshake.extend_from_slice(buf.get(at + 5..at + 5 + len)?);
        at += 5 + len;
    }
}

fn mutate(rng: &mut Rng, buf: &mut Vec<u8>) {
    for _ in 0..1 + rng.below(3) {
        if buf.is_empty() {
            return;
        }
        let at = rng.below(buf.len());
        match rng.below(7) {
            0 => buf[at] ^= 1 << rng.below(8),
            1 => buf[at] = *rng.pick(&[0, 1, 0xff, 0x16, 0x7f]),
            2 => {
                let end = (at + 1 + rng.below(6)).min(buf.len());
                buf.drain(at..end);
            }
            3 => {
                let extra = rng.some(6);
                buf.splice(at..at, extra);
            }
            4 => buf.truncate(at),
            5 => {
                // A length field nudged by one.
                if at + 1 < buf.len() {
                    let v = u16::from_be_bytes([buf[at], buf[at + 1]]);
                    let v = if rng.chance(50) {
                        v.wrapping_add(1)
                    } else {
                        v.wrapping_sub(1)
                    };
                    buf[at..at + 2].copy_from_slice(&v.to_be_bytes());
                }
            }
            _ => {
                let end = (at + 1 + rng.below(8)).min(buf.len());
                let copy = buf[at..end].to_vec();
                let to = rng.below(buf.len());
                buf.splice(to..to, copy);
            }
        }
    }
}

const NAMES: [&str; 5] = [
    "example.com",
    "Example.COM.",
    "a.b.c.example.org",
    "x",
    "evil.test",
];

fn random_hello(rng: &mut Rng) -> (Vec<u8>, Option<String>) {
    let name = rng.chance(85).then(|| *rng.pick(&NAMES));
    let mut exts: Vec<Vec<u8>> = (0..rng.below(4))
        .map(|_| extension(1 + rng.below(60) as u16, &rng.some(20)))
        .collect();
    if let Some(name) = name {
        let at = rng.below(exts.len() + 1);
        exts.insert(at, sni_ext(&[(0, name)]));
    }
    let message = hello_message(rng, &exts);
    (message, name.and_then(normalize_host))
}

#[test]
fn test_client_hello_fragmentation_never_changes_the_name() {
    let mut rng = Rng::new(1);
    for _ in 0..iterations(1500) {
        let (message, expect) = random_hello(&mut rng);
        let want = Hello::Tls(expect);
        let piece = [1, 2, 3, 4, 5, 6, 7, 13, 64, message.len()][rng.below(10)].max(1);
        let wire = records(&message, piece);
        assert_eq!(
            client_hello_sni(&wire),
            want,
            "piece {piece}: {}",
            hex(&wire)
        );
        let mut padded = wire.clone();
        padded.extend_from_slice(&rng.some(40));
        assert_eq!(client_hello_sni(&padded), want, "padded: {}", hex(&padded));
        for cut in 0..wire.len() {
            assert_eq!(
                client_hello_sni(&wire[..cut]),
                Hello::NeedMore,
                "cut {cut} of piece {piece}: {}",
                hex(&wire)
            );
        }
    }
}

/// Whatever the proxy reads out of damaged bytes must not differ from what a strict server
/// reads out of them: it may refuse or wait, never name a different host.
#[test]
fn test_client_hello_damage_never_hides_the_name_a_strict_server_sees() {
    let mut rng = Rng::new(2);
    let mut violations = Vec::new();
    for _ in 0..iterations(60_000) {
        let (message, _) = random_hello(&mut rng);
        let piece = [message.len(), 1, 3, 17, 50][rng.below(5)].max(1);
        let mut wire = records(&message, piece);
        mutate(&mut rng, &mut wire);
        let proxy = client_hello_sni(&wire);
        if let Some(Some(seen)) = strict_view(&wire) {
            let ok = match &proxy {
                Hello::Tls(Some(name)) => *name == seen,
                Hello::NeedMore | Hello::Malformed => true,
                Hello::Tls(None) | Hello::NotTls => false,
            };
            if !ok {
                violations.push(format!(
                    "server sees {seen}, proxy {proxy:?}: {}",
                    hex(&wire)
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "{} cases, first:\n{}",
        violations.len(),
        violations[..violations.len().min(5)].join("\n")
    );
}

#[test]
fn test_client_hello_random_bytes_do_not_panic() {
    let mut rng = Rng::new(3);
    for _ in 0..iterations(100_000) {
        let n = rng.below(120);
        let mut buf = rng.bytes(n);
        if rng.chance(80) && !buf.is_empty() {
            buf[0] = 0x16;
            if buf.len() > 4 && rng.chance(70) {
                buf[3] = 0;
                buf[4] = (n as u8).saturating_sub(5);
            }
        }
        let _ = client_hello_sni(&buf);
    }
}

/// A hello that names two hosts is read differently by different servers; relaying it on the
/// first name would trust a reading the server may not share.
#[test]
fn test_client_hello_with_two_names_is_not_read_as_one() {
    let mut rng = Rng::new(4);
    let two_entries = sni_ext(&[(0, "allowed.test"), (0, "other.test")]);
    let two_extensions = [
        sni_ext(&[(0, "allowed.test")]),
        sni_ext(&[(0, "other.test")]),
    ]
    .concat();
    for (label, exts) in [
        ("two host_name entries", vec![two_entries]),
        ("two server_name extensions", vec![two_extensions]),
    ] {
        let wire = records(&hello_message(&mut rng, &exts), 1 << 14);
        let got = client_hello_sni(&wire);
        assert!(
            matches!(got, Hello::Malformed),
            "{label} is read as {got:?}"
        );
    }
}

// ---- HTTP ----

const METHODS: [&str; 7] = [
    "GET", "POST", "get", "PUT", "CONNECT", "G\u{0}T", "GET\u{b}",
];
const TARGETS: [&str; 26] = [
    "http://é.test/",
    "http://ignore-all-previous-instructions.test:81/",
    "http://a.test\u{200b}/",
    "http://a$b.test/",
    "http://a.test/",
    "http://a.test",
    "HTTP://A.TEST:8080/x?y#z",
    "http://a.test?x=1",
    "http://a.test#frag",
    "http://a.test@b.test/",
    "http://a.test\\@b.test/",
    "http://[::1]:80/",
    "http://[::1/",
    "http://a.test:80:81/",
    "http://:80/",
    "http:///",
    "http://a.test./",
    "http://a.test../",
    "http://a.test:0/",
    "http://a.test:99999/",
    "http://a.test\u{a0}b.test/",
    "http://a.test/%0d%0aHost:%20b.test",
    "/relative",
    "a.test:443",
    "a.test:",
    "[::1]:443",
];
const HEADER_NAMES: [&str; 14] = [
    "Host",
    "host",
    "HOST",
    "Connection",
    "Content-Length",
    "Transfer-Encoding",
    "Proxy-Authorization",
    "Keep-Alive",
    "TE",
    "Upgrade",
    "X-Real-Ip",
    "Content-Type",
    "Cookie",
    "Proxy-Connection",
];
const JUNK_NAME_SUFFIX: [&str; 9] = ["", "", "", " ", "\t", "\u{b}", "\u{c}", "\u{a0}", "\u{0}"];
const VALUES: [&str; 12] = [
    "b.test",
    "close",
    "keep-alive",
    "5",
    "0",
    "chunked",
    "gzip, chunked",
    "x\rHost: evil.test",
    "x\r",
    "Content-Length",
    "a, close",
    "\u{0}",
];

fn http_head(rng: &mut Rng) -> String {
    let mut head = format!(
        "{} {}{} {}\r\n",
        rng.pick(&METHODS),
        rng.pick(&TARGETS),
        if rng.chance(10) { "\r" } else { "" },
        rng.pick(&["HTTP/1.1", "HTTP/1.0", "", "HTTP/1.1 x"])
    );
    for _ in 0..rng.below(7) {
        if rng.chance(8) {
            head.push_str(&format!(" {}\r\n", rng.pick(&VALUES)));
            continue;
        }
        let mut name = rng.pick(&HEADER_NAMES).to_string();
        if rng.chance(15) {
            let at = rng.below(name.len());
            name.insert_str(at, rng.pick_ref(&JUNK_NAME_SUFFIX));
        }
        name.push_str(rng.pick_ref(&JUNK_NAME_SUFFIX));
        let sep = if rng.chance(90) { ":" } else { "" };
        head.push_str(&format!("{name}{sep} {}\r\n", rng.pick(&VALUES)));
    }
    head.push_str("\r\n");
    head
}

#[test]
fn test_http_rewriting_keeps_one_host_and_clean_lines() {
    let mut rng = Rng::new(5);
    let mut violations = Vec::new();
    let mut served = 0;
    for _ in 0..iterations(100_000) {
        let head = http_head(&mut rng);
        let Ok(request) = HttpProxy::parse_request(&head) else {
            continue;
        };
        let Request::Http {
            host,
            port,
            method,
            authority,
            path,
            version,
            body,
        } = request
        else {
            continue;
        };
        served += 1;
        let out = HttpProxy::forwarded_head(&head, method, &path, version, authority);
        let mut fail = |why: &str| violations.push(format!("{why}\nin {head:?}\nout {out:?}"));

        let Some(wire) = out.strip_suffix("\r\n\r\n") else {
            fail("no blank line at the end");
            continue;
        };
        if wire.contains('\0') || wire.replace("\r\n", "").contains(['\r', '\n']) {
            fail("a bare CR/LF or NUL reaches the server");
        }
        let lines: Vec<&str> = wire.split("\r\n").collect();
        let hosts = lines[1..]
            .iter()
            .filter(|l| {
                l.split(':')
                    .next()
                    .unwrap_or("")
                    .eq_ignore_ascii_case("host")
            })
            .count();
        if hosts != 1 || lines.get(1) != Some(&format!("Host: {authority}").as_str()) {
            fail("the Host header isn't the checked authority, once");
        }
        if lines[1..].iter().any(|l| l.starts_with([' ', '\t'])) {
            fail("a folded line is forwarded");
        }
        if parse_authority(authority, 80) != Some((host.clone(), port)) {
            fail("the authority and the checked host disagree");
        }
        if HttpProxy::request_body(&out) != Ok(body) {
            fail("the forwarded head frames its body differently");
        }
    }
    assert!(served > 1000, "only {served} requests got through to check");
    assert!(
        violations.is_empty(),
        "{} cases, first:\n{}",
        violations.len(),
        violations[..violations.len().min(4)].join("\n---\n")
    );
}

#[test]
fn test_authority_and_rules_only_let_names_and_addresses_through() {
    let mut rng = Rng::new(6);
    let alphabet: Vec<char> = "ab.-_:[]@%\\/ \t0129xX*\u{0}é".chars().collect();
    let policy = {
        let mut p = Policy {
            allow: ["*.a.test", "a.test", "1.2.3.4", "[::1]:443", "b.test:80"]
                .iter()
                .map(|e| Rule::parse(e).unwrap())
                .collect(),
            deny: vec![Rule::parse("bad.a.test").unwrap()],
            allow_private: false,
            require_host_match: false,
            idle_timeout: IDLE_TIMEOUT,
        };
        p.allow_private = false;
        p
    };
    for _ in 0..iterations(200_000) {
        let n = 1 + rng.below(14);
        let mut text: String = (0..n).map(|_| *rng.pick(&alphabet)).collect();
        if rng.chance(30) {
            let head: String = text.chars().take(3).collect();
            text = format!("{head}.a.test{}", rng.pick(&["", ".", ":80", ":0"]));
        }
        let default = *rng.pick(&[80u16, 443]);
        if let Some((host, port)) = parse_authority(&text, default) {
            assert!(!host.is_empty() && port != 0, "{text:?}");
            assert_eq!(host, host.to_ascii_lowercase(), "{text:?}");
            assert!(!host.contains('@'), "{text:?} -> {host:?}");
            if policy.check(&host, port).is_ok() {
                assert!(
                    is_dns_name(&host) || host.parse::<IpAddr>().is_ok(),
                    "{text:?} was allowed as {host:?}"
                );
                assert!(
                    !host.starts_with("bad.a.test"),
                    "denied name allowed: {text:?}"
                );
            }
        }
        let _ = Rule::parse(&text);
    }
}

// ---- live proxy ----

use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

static PANICS: AtomicUsize = AtomicUsize::new(0);

/// Counts panics anywhere in the process: a connection task's panic is otherwise swallowed
/// by the accept loop.
fn count_panics() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // The proxy's own (this file's assertions are other tests' business).
            if info
                .location()
                .is_some_and(|l| l.file().ends_with("proxy.rs"))
            {
                PANICS.fetch_add(1, Ordering::SeqCst);
            }
            previous(info);
        }));
    });
}

/// Sends `chunks`, then half-closes (or drops), and says whether the proxy then closed its
/// side within the time allowed.
async fn send(proxy: SocketAddr, chunks: Vec<Vec<u8>>, half_close: bool) -> Result<(), String> {
    let Ok(mut client) = TcpStream::connect(proxy).await else {
        return Err("connect refused".into());
    };
    for chunk in &chunks {
        if client.write_all(chunk).await.is_err() {
            break; // the proxy hung up on it already
        }
        tokio::task::yield_now().await;
    }
    if !half_close {
        return Ok(());
    }
    let _ = client.shutdown().await;
    let mut sink = Vec::new();
    match tokio::time::timeout(Duration::from_secs(8), client.read_to_end(&mut sink)).await {
        Ok(_) => Ok(()),
        Err(_) => Err(format!(
            "the proxy kept the connection open after the client's EOF; sent {:?}",
            chunks
                .concat()
                .iter()
                .take(120)
                .map(|&b| b as char)
                .collect::<String>()
        )),
    }
}

fn split_randomly(rng: &mut Rng, bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let n = 1 + rng
            .below(bytes.len() - at)
            .min(if rng.chance(70) { 7 } else { 4096 });
        out.push(bytes[at..at + n].to_vec());
        at += n;
    }
    out
}

fn socks5_bytes(rng: &mut Rng, upstream: u16) -> Vec<u8> {
    let mut out = vec![5];
    let methods = if rng.chance(90) { vec![0] } else { rng.some(4) };
    out.push(methods.len() as u8);
    out.extend_from_slice(&methods);
    if rng.chance(90) {
        out.extend_from_slice(&[5, *rng.pick(&[1u8, 1, 1, 2, 3, 0]), 0]);
        match rng.below(4) {
            0 => {
                out.push(1);
                out.extend_from_slice(&[127, 0, 0, 1]);
                out.extend_from_slice(&upstream.to_be_bytes());
            }
            1 => {
                out.push(3);
                let name =
                    *rng.pick(&["localhost", "a.test", "LOCALHOST.", "x y", "é", "", "a..b"]);
                out.push(name.len() as u8);
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(&upstream.to_be_bytes());
            }
            2 => {
                out.push(4);
                out.extend_from_slice(&rng.bytes(16));
                out.extend_from_slice(&rng.bytes(2));
            }
            _ => out.extend_from_slice(&rng.some(30)),
        }
    }
    out.extend_from_slice(&rng.some(40));
    out
}

fn storm_payload(rng: &mut Rng, upstream: u16) -> Vec<u8> {
    match rng.below(6) {
        0 | 1 => {
            let mut head = http_head(rng).replace("a.test", &format!("localhost:{upstream}"));
            if rng.chance(30) {
                head.push_str(&String::from_utf8_lossy(&rng.some(60)));
            }
            let mut bytes = head.into_bytes();
            if rng.chance(30) {
                mutate(rng, &mut bytes);
            }
            bytes
        }
        2 => rng.some(200),
        3 => socks5_bytes(rng, upstream),
        4 => {
            let mut bytes = format!("CONNECT localhost:{upstream} HTTP/1.1\r\n\r\n").into_bytes();
            let (message, _) = random_hello(rng);
            let mut hello = records(&message, 1 + rng.below(60));
            if rng.chance(50) {
                mutate(rng, &mut hello);
            }
            bytes.extend_from_slice(&hello);
            bytes
        }
        _ => {
            let mut bytes = format!(
                "POST http://localhost:{upstream}/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .into_bytes();
            for _ in 0..rng.below(4) {
                bytes.extend_from_slice(
                    format!(
                        "{}{}\r\n",
                        rng.pick(&[
                            "5",
                            "0",
                            "+5",
                            "ff",
                            "",
                            "x",
                            "5;e=1",
                            "-1",
                            "ffffffffffffffffff"
                        ]),
                        rng.pick(&["", " ", "\r"])
                    )
                    .as_bytes(),
                );
                bytes.extend_from_slice(&rng.some(8));
                bytes.extend_from_slice(rng.pick_ref(&[&b"\r\n"[..], &b"\n"[..], &b""[..]]));
            }
            bytes
        }
    }
}

/// Garbage, in every shape the proxy parses, from many clients at once: nothing panics, every
/// connection ends when its client does, no connection slot is lost, and nothing a client made
/// up reaches the refusal record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_storm_of_malformed_clients_leaves_the_proxy_whole() {
    count_panics();
    let panics_before = PANICS.load(Ordering::SeqCst);
    let upstream_port = echo_upstream().await;
    let mut failures = Vec::new();
    for require_host_match in [false, true] {
        let mut policy = localhost_policy(require_host_match);
        policy.allow.push(Rule::parse("*.a.test").unwrap());
        policy.idle_timeout = Duration::from_secs(10);
        const SLOTS: usize = 16;
        let (proxy, refusals, _stop) = proxy_limited(policy, SLOTS).await;
        let mut rng = Rng::new(7 + require_host_match as u64);

        let mut tasks = tokio::task::JoinSet::new();
        let total = iterations(1500);
        let mut sent = 0;
        while sent < total {
            while tasks.len() < 64 && sent < total {
                let payload = storm_payload(&mut rng, upstream_port);
                let chunks = split_randomly(&mut rng, &payload);
                let half_close = rng.chance(85);
                tasks.spawn(send(proxy, chunks, half_close));
                sent += 1;
            }
            if let Some(done) = tasks.join_next().await
                && let Err(why) = done.unwrap()
            {
                failures.push(why);
            }
        }
        while let Some(done) = tasks.join_next().await {
            if let Err(why) = done.unwrap() {
                failures.push(why);
            }
        }

        // Every slot is free again: SLOTS clients, all at once, are each served.
        let mut served = tokio::task::JoinSet::new();
        for _ in 0..SLOTS {
            served.spawn(async move {
                let mut client = TcpStream::connect(proxy).await.unwrap();
                client
                    .write_all(
                        format!("GET http://localhost:{upstream_port}/ HTTP/1.1\r\n\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
                client.shutdown().await.unwrap();
                let mut got = Vec::new();
                tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut got))
                    .await
                    .map(|_| String::from_utf8_lossy(&got).starts_with("got:GET /"))
                    .unwrap_or(false)
            });
        }
        let mut ok = 0;
        while let Some(done) = served.join_next().await {
            ok += done.unwrap() as usize;
        }
        if ok != SLOTS {
            failures.push(format!("only {ok} of {SLOTS} clients were served after the storm (require_host_match {require_host_match})"));
        }

        assert!(!refusals.list().is_empty(), "the storm refused nothing");
        for r in refusals.list() {
            if !(is_dns_name(&r.host) || r.host.parse::<IpAddr>().is_ok()) {
                failures.push(format!("the refusal record holds {:?}", r.host));
            }
        }
    }
    let panics = PANICS.load(Ordering::SeqCst) - panics_before;
    assert_eq!(panics, 0, "connection tasks panicked");
    failures.dedup();
    assert!(
        failures.is_empty(),
        "{} problems, first:\n{}",
        failures.len(),
        failures[..failures.len().min(6)].join("\n")
    );
}

/// A server that records what each connection sends until its EOF, then answers and closes.
async fn recording_upstream() -> (u16, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut got = Vec::new();
                let _ = tokio::time::timeout(Duration::from_secs(8), stream.read_to_end(&mut got))
                    .await;
                let _ = tx.send(got);
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            });
        }
    });
    (port, rx)
}

/// A framed body and its wire form: what the proxy has to forward, byte for byte.
fn framed_body(rng: &mut Rng) -> (Vec<u8>, String) {
    if rng.chance(40) {
        let body = if rng.chance(50) {
            b"GET http://localhost/SMUGGLED HTTP/1.1\r\nHost: evil.test\r\n\r\n".to_vec()
        } else {
            rng.some(300)
        };
        return (body.clone(), format!("Content-Length: {}\r\n", body.len()));
    }
    let mut wire = Vec::new();
    for _ in 0..rng.below(5) {
        let chunk = rng.some(120);
        let ext = *rng.pick(&["", ";name=value", " ;x", ";a=\"b\""]);
        let size = if rng.chance(30) {
            format!("{:X}", chunk.len())
        } else {
            format!("{:x}", chunk.len())
        };
        if chunk.is_empty() {
            continue; // an empty chunk would end the body early
        }
        wire.extend_from_slice(format!("{size}{ext}\r\n").as_bytes());
        wire.extend_from_slice(&chunk);
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(format!("0{}\r\n", rng.pick(&["", ";done"])).as_bytes());
    for _ in 0..rng.below(3) {
        wire.extend_from_slice(b"X-Trailer: v\r\n");
    }
    wire.extend_from_slice(b"\r\n");
    (wire, "Transfer-Encoding: chunked\r\n".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_only_the_framed_body_is_forwarded_and_never_a_pipelined_request() {
    let (port, mut recorded) = recording_upstream().await;
    let (proxy, _, _stop) = proxy_limited(localhost_policy(false), 8).await;
    let mut rng = Rng::new(9);
    for i in 0..iterations(400) {
        let (body, framing) = framed_body(&mut rng);
        let head = format!("POST http://localhost:{port}/p HTTP/1.1\r\nX-N: {i}\r\n{framing}\r\n");
        let second =
            format!("GET http://localhost:{port}/SMUGGLED HTTP/1.1\r\nHost: evil.test\r\n\r\n");
        let mut wire = head.clone().into_bytes();
        wire.extend_from_slice(&body);
        wire.extend_from_slice(second.as_bytes());

        let mut client = TcpStream::connect(proxy).await.unwrap();
        for chunk in split_randomly(&mut rng, &wire) {
            // The proxy may be done with the request (and closed) before the rest is sent.
            if client.write_all(&chunk).await.is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let _ = client.shutdown().await;
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut response))
            .await
            .unwrap_or_else(|_| panic!("no end to the response, iteration {i}"))
            .ok();

        let got = tokio::time::timeout(Duration::from_secs(10), recorded.recv())
            .await
            .expect("the upstream saw nothing")
            .unwrap();
        let mut expect = HttpProxy::forwarded_head(
            &head,
            "POST",
            "/p",
            "HTTP/1.1",
            &format!("localhost:{port}"),
        )
        .into_bytes();
        expect.extend_from_slice(&body);
        assert_eq!(
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&expect),
            "iteration {i}, client sent {:?}",
            String::from_utf8_lossy(&wire)
        );
    }
}

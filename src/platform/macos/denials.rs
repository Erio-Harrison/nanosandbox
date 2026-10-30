//! What Seatbelt refused a run, from the unified log (`report_denials`).
//!
//! The kernel logs every denial as `Sandbox: NAME(PID) deny(1) OPERATION PATH`, readable
//! without privileges through `log stream`. One stream runs per `Sandbox` for as long as it
//! lives; each run knows the pids of its process tree (the wait loop follows forks with
//! kqueue's `NOTE_FORK` and lists the children) and takes the file events from those pids in
//! its window. Other sandboxed processes on the machine log denials too, so a pid is the only
//! safe key.
//!
//! The stream delivers in order but late (30-50 ms, more under load), and a fresh one can
//! take a while before it delivers at all. So the log probes itself: it provokes a denial it
//! can recognise (`sandbox-exec` reading a file of its own that its profile forbids) and
//! waits for that event. Once at start, to know the stream is live; and once at the end of
//! each run, as a barrier: when the probe's event has arrived, so has everything the run
//! caused before it.

use crate::result::DeniedPath;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long to wait for a probe's event before giving up on the stream (then the run's
/// events are taken as they are).
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// How many probes a fresh stream gets to prove itself live.
const START_PROBES: u32 = 3;

/// Events older than this are dropped unclaimed.
const KEEP: Duration = Duration::from_secs(60);

/// Paths every process trips over, which say nothing about the policy.
const NOISE: &[&str] = &["/dev/dtracehelper"];

/// The Seatbelt file and exec operations as the kernel names them in a report. Only these are
/// taken, so a process whose name spells out a fake operation can't pass it off as one.
const OPERATIONS: &[&str] = &[
    "file-read-data",
    "file-read-metadata",
    "file-read-xattr",
    "file-write-data",
    "file-write-create",
    "file-write-unlink",
    "file-write-mode",
    "file-write-owner",
    "file-write-flags",
    "file-write-acl",
    "file-write-xattr",
    "file-write-times",
    "file-write-setugid",
    "file-write-finderinfo",
    "file-write-unmount",
    "file-ioctl",
    "file-link",
    "file-clone",
    "file-mknod",
    "file-mount",
    "file-unmount",
    "file-revoke",
    "file-search",
    "file-issue-extension",
    "file-map-executable",
    "file-test-existence",
    "process-exec",
    "process-exec-interpreter",
];

/// A `Sandbox:` log line, kept as text: its process name and path are the command's to
/// choose, so where the name ends and the pid begins is only known once the run's pids are.
#[derive(Debug, Clone)]
struct Event {
    at: SystemTime,
    /// After `Sandbox: `, JSON escapes undone.
    message: String,
}

#[derive(Default)]
struct State {
    events: Vec<Event>,
    /// Probe processes in flight, by pid.
    probe_pids: Vec<i32>,
    /// Probe paths whose events have arrived.
    probes_seen: Vec<String>,
}

/// `NAME(PID) deny(N) OPERATION PATH` read against `pids`: the first split at a `) deny(` that
/// yields one of them and a known file operation. A process can put `) deny(` in its own name
/// or in a path, which can garble the path reported for it, but not make the event belong to
/// no pid; a made-up operation name isn't taken, so the real split is the one found.
fn resolve(message: &str, pids: &[i32]) -> Option<(i32, String, String)> {
    let mut from = 0;
    while let Some(k) = message[from..].find(") deny(") {
        let k = from + k;
        from = k + 1;
        let Some(open) = message[..k].rfind('(') else {
            continue;
        };
        let Ok(pid) = message[open + 1..k].parse::<i32>() else {
            continue;
        };
        if !pids.contains(&pid) {
            continue;
        }
        let Some((_, tail)) = message[k + ") deny(".len()..].split_once(") ") else {
            continue;
        };
        let Some((operation, path)) = tail.split_once(' ') else {
            continue;
        };
        if !OPERATIONS.contains(&operation) {
            continue;
        }
        if NOISE.contains(&path) {
            return None;
        }
        return Some((pid, operation.to_string(), path.to_string()));
    }
    None
}

/// The stream and what it has delivered.
pub(crate) struct DenialLog {
    state: Arc<Mutex<State>>,
    child: Mutex<Child>,
    /// This log's own directory of probe files.
    probe_dir: PathBuf,
    /// Held while alive; a sweep removes the directory once it can take the lock.
    _lease: Option<std::fs::File>,
    probes: std::sync::atomic::AtomicU64,
    arrived: std::sync::Condvar,
}

impl std::fmt::Debug for DenialLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DenialLog")
    }
}

/// One run's claim on the log: taken at launch, settled at the end.
pub(crate) struct RunDenials {
    log: Arc<DenialLog>,
    start: SystemTime,
    pids: Vec<i32>,
}

impl DenialLog {
    /// Starts the stream and waits for it to be live.
    pub(crate) fn start() -> std::io::Result<Arc<Self>> {
        let mut child = Command::new("/usr/bin/log")
            .args([
                "stream",
                "--style",
                "ndjson",
                "--predicate",
                "sender == \"Sandbox\"",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdout = child.stdout.take().expect("piped");
        let mut reader = BufReader::new(stdout);
        // The first line is the filter banner; events follow.
        let mut banner = String::new();
        if reader.read_line(&mut banner)? == 0 {
            let _ = child.kill();
            return Err(std::io::Error::other("log stream ended before it started"));
        }
        // Named and leased like a private temp dir, so the sweep removes it if this process
        // dies without dropping the log (see private_tmp.rs).
        let probe_dir = std::env::temp_dir().join(format!(
            "{}denials-{}-{:x}",
            crate::platform::private_tmp::PREFIX,
            std::process::id(),
            rand_u64()
        ));
        std::fs::create_dir_all(&probe_dir)?;
        let probe_dir = probe_dir.canonicalize()?;
        let lease = crate::platform::private_tmp::take_lease(&probe_dir)?;
        let log = Arc::new(Self {
            state: Arc::new(Mutex::new(State::default())),
            child: Mutex::new(child),
            probe_dir,
            _lease: lease,
            probes: std::sync::atomic::AtomicU64::new(0),
            arrived: std::sync::Condvar::new(),
        });
        let sink = Arc::downgrade(&log);
        std::thread::Builder::new()
            .name("nanosandbox-denials".into())
            .spawn(move || {
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    let Some(log) = sink.upgrade() else { break };
                    if let Some(event) = parse_line(&line) {
                        log.deliver(event);
                    }
                }
            })?;
        // Live? A fresh stream can sit silent for a while; a probe's event proves it.
        if !(0..START_PROBES).any(|_| log.probe().is_ok()) {
            return Err(std::io::Error::other(
                "`log stream` isn't delivering sandbox denials",
            ));
        }
        Ok(log)
    }

    fn deliver(&self, event: Event) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((pid, _, path)) = resolve(&event.message, &state.probe_pids)
            && path.starts_with(self.probe_dir.to_string_lossy().as_ref())
        {
            state.probe_pids.retain(|p| *p != pid);
            state.probes_seen.push(path);
            drop(state);
            self.arrived.notify_all();
            return;
        }
        let cutoff = SystemTime::now().checked_sub(KEEP).unwrap_or(UNIX_EPOCH);
        state.events.retain(|e| e.at >= cutoff);
        state.events.push(event);
    }

    /// Provokes a denial on a probe file of this log's own and waits for its event: when it
    /// has arrived, so has every earlier one. Fails if it doesn't arrive in `PROBE_TIMEOUT`.
    fn probe(&self) -> Result<(), ()> {
        let n = self
            .probes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let path = self.probe_dir.join(format!("probe-{n}"));
        std::fs::write(&path, b"").map_err(|_| ())?;
        let path_str = path.to_string_lossy().into_owned();
        let profile = format!(
            "(version 1)(allow default)(deny file-read* (literal \"{}\"))",
            path_str.replace('\\', "\\\\").replace('"', "\\\"")
        );
        let child = Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &profile, "/bin/cat", &path_str])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = child else {
            let _ = std::fs::remove_file(&path);
            return Err(());
        };
        // The probe's event is told from a command's by this pid; a command would have to
        // name itself after a pid not yet assigned to spoof it.
        let pid = child.id() as i32;
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.probe_pids.push(pid);
        }
        let _ = child.wait();
        let _ = std::fs::remove_file(&path);
        let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(i) = state.probes_seen.iter().position(|p| *p == path_str) {
                state.probes_seen.remove(i);
                return Ok(());
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                state.probe_pids.retain(|p| *p != pid);
                return Err(());
            }
            state = self
                .arrived
                .wait_timeout(state, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// A run starts now.
    pub(crate) fn begin(self: &Arc<Self>) -> RunDenials {
        RunDenials {
            log: Arc::clone(self),
            start: SystemTime::now(),
            pids: Vec::new(),
        }
    }
}

impl Drop for DenialLog {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.probe_dir);
    }
}

fn rand_u64() -> u64 {
    let mut bytes = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut bytes);
    }
    u64::from_ne_bytes(bytes) ^ (std::process::id() as u64)
}

impl RunDenials {
    /// A process of the run's tree, for attributing its denials; true if new.
    pub(crate) fn saw(&mut self, pid: i32) -> bool {
        if self.pids.contains(&pid) {
            return false;
        }
        self.pids.push(pid);
        true
    }

    /// The run's file denials, once the log has caught up (a probe after the run is the
    /// barrier): events in the run's window from the pids of its tree.
    pub(crate) fn finish(mut self, first_pid: i32) -> Vec<DeniedPath> {
        self.saw(first_pid);
        let ended = SystemTime::now();
        if self.log.probe().is_err() {
            tracing::warn!("the denial log fell behind; this run's denied_paths may be short");
        }
        let mut state = self.log.state.lock().unwrap_or_else(|e| e.into_inner());
        let window = |e: &Event| e.at >= self.start && e.at <= ended + Duration::from_secs(1);
        let mine = |e: &Event| window(e) && resolve(&e.message, &self.pids).is_some();
        let (taken, kept): (Vec<Event>, Vec<Event>) = std::mem::take(&mut state.events)
            .into_iter()
            .partition(mine);
        state.events = kept;
        drop(state);
        summarize(
            taken
                .iter()
                .filter_map(|e| resolve(&e.message, &self.pids))
                .map(|(_, operation, path)| (operation, path))
                .collect(),
        )
    }
}

/// Each path and operation once, with how often, sorted.
fn summarize(events: Vec<(String, String)>) -> Vec<DeniedPath> {
    let mut out: Vec<DeniedPath> = Vec::new();
    for (operation, path) in events {
        match out
            .iter_mut()
            .find(|d| d.path.as_os_str() == path.as_str() && d.operation == operation)
        {
            Some(d) => d.count += 1,
            None => out.push(DeniedPath {
                path: PathBuf::from(path),
                operation,
                count: 1,
            }),
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path).then(a.operation.cmp(&b.operation)));
    out
}

/// One ndjson line of `log stream`, if it's a sandbox denial (whose pid is settled later).
fn parse_line(line: &str) -> Option<Event> {
    let at = parse_log_time(json_field(line, "timestamp")?)?;
    let message = json_field(line, "eventMessage")?.strip_prefix("Sandbox: ")?;
    if !message.contains(") deny(") {
        return None;
    }
    Some(Event {
        at,
        message: unescape(message),
    })
}

/// The raw value of a string field in one line of JSON (escapes left in place).
fn json_field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("\"{name}\":\"");
    let start = line.find(&key)? + key.len();
    let rest = &line[start..];
    let mut end = 0;
    let bytes = rest.as_bytes();
    while end < bytes.len() {
        match bytes[end] {
            b'\\' => end += 2,
            b'"' => return Some(&rest[..end]),
            _ => end += 1,
        }
    }
    None
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(other) => out.push(other),
                None => break,
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// `2026-10-30 15:04:38.366959+1100` as a point in time.
fn parse_log_time(s: &str) -> Option<SystemTime> {
    let (date, rest) = s.split_once(' ')?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    let sign_at = rest.rfind(['+', '-'])?;
    let (clock, zone) = rest.split_at(sign_at);
    let mut hms = clock.split(':');
    let hour: i64 = hms.next()?.parse().ok()?;
    let minute: i64 = hms.next()?.parse().ok()?;
    let sec_frac = hms.next()?;
    let (sec, frac) = sec_frac.split_once('.').unwrap_or((sec_frac, "0"));
    let second: i64 = sec.parse().ok()?;
    let micros: u64 = format!("{frac:0<6}").get(..6)?.parse().ok()?;
    let zone_sign = if zone.starts_with('-') { -1 } else { 1 };
    let zone_digits = &zone[1..];
    let zone_minutes: i64 = zone_digits.get(..2)?.parse::<i64>().ok()? * 60
        + zone_digits.get(2..4)?.parse::<i64>().ok()?;
    // Days from civil (Howard Hinnant's algorithm).
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let local = days * 86_400 + hour * 3600 + minute * 60 + second;
    let utc = local - zone_sign * zone_minutes * 60;
    let utc = u64::try_from(utc).ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(utc) + Duration::from_micros(micros))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line_and_resolve() {
        let line = r#"{"traceID":1,"timestamp":"2026-10-30 15:04:38.366959+1100","eventMessage":"Sandbox: cat(56242) deny(1) file-read-data \/Users\/h\/.ssh\/known hosts","processID":0}"#;
        let e = parse_line(line).unwrap();
        assert_eq!(
            e.at.duration_since(UNIX_EPOCH).unwrap().as_micros(),
            1_793_333_078_366_959
        );
        assert_eq!(
            resolve(&e.message, &[56242]),
            Some((
                56242,
                "file-read-data".into(),
                "/Users/h/.ssh/known hosts".into()
            ))
        );
        assert_eq!(resolve(&e.message, &[1]), None);
        for noise in [
            "sh(1) deny(1) sysctl-read kern.bootargs",
            "sh(1) deny(1) mach-lookup com.apple.logd",
            "sh(1) deny(1) file-write-data /dev/dtracehelper",
        ] {
            assert_eq!(resolve(noise, &[1]), None, "{noise}");
        }
        assert!(
            parse_line(
                r#"{"timestamp":"2026-10-30 15:04:38.366959+1100","eventMessage":"something else"}"#
            )
            .is_none()
        );
    }

    /// A process named to look like a log line can't make its denial vanish: the split that
    /// names one of the run's pids is the one taken.
    #[test]
    fn test_resolve_is_not_fooled_by_the_process_name() {
        let own = &[85739];
        assert_eq!(
            resolve("a(1) deny(1) x(85739) deny(1) file-read-data /c", own),
            Some((85739, "file-read-data".into(), "/c".into()))
        );
        assert_eq!(
            resolve("q) deny(9(85739) deny(1) file-read-data /c", own),
            Some((85739, "file-read-data".into(), "/c".into()))
        );
        // Its own pid in its name garbles the path, but the event is still its.
        let r = resolve(
            "x(85739) deny(1) file-read-data /fake(85739) deny(1) file-read-data /c",
            own,
        )
        .unwrap();
        assert_eq!(r.0, 85739);
        assert!(r.2.ends_with("/c"));
        // A made-up operation in the name isn't one: the real split is taken, and an event
        // that isn't a file operation stays filtered.
        assert_eq!(
            resolve(
                "x(85739) deny(1) file-a b(85739) deny(1) file-read-data /c",
                own
            ),
            Some((85739, "file-read-data".into(), "/c".into()))
        );
        assert_eq!(
            resolve(
                "x(85739) deny(1) file-a b(85739) deny(1) sysctl-read kern.x",
                own
            ),
            None
        );
        assert_eq!(
            resolve(
                "x(85739) deny(1) file-a b(85739) deny(1) file-write-data /dev/dtracehelper",
                own
            ),
            None
        );
        // A path containing the pattern keeps the first, correct split.
        assert_eq!(
            resolve(
                "cat(85739) deny(1) file-read-data /ws/x(85739) deny(1) y /z",
                own
            ),
            Some((
                85739,
                "file-read-data".into(),
                "/ws/x(85739) deny(1) y /z".into()
            ))
        );
    }

    #[test]
    fn test_parse_log_time_handles_zones_and_leap_days() {
        let t = |s: &str| {
            parse_log_time(s)
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        };
        assert_eq!(t("1970-01-01 00:00:00.000000+0000"), 0);
        assert_eq!(t("1970-01-01 01:00:00+0100"), 0);
        assert_eq!(t("2024-02-29 12:00:00.5-0530"), 1_709_227_800);
        assert_eq!(t("2026-10-30 15:04:38.366959+1100"), 1_793_333_078);
    }

    #[test]
    fn test_summarize_counts_and_sorts() {
        let ev = |op: &str, path: &str| (op.to_string(), path.to_string());
        let out = summarize(vec![
            ev("file-read-data", "/b"),
            ev("file-read-data", "/a"),
            ev("file-read-data", "/b"),
            ev("file-write-create", "/a"),
        ]);
        let shown: Vec<(String, &str, u32)> = out
            .iter()
            .map(|d| (d.path.display().to_string(), d.operation.as_str(), d.count))
            .collect();
        assert_eq!(
            shown,
            vec![
                ("/a".into(), "file-read-data", 1),
                ("/a".into(), "file-write-create", 1),
                ("/b".into(), "file-read-data", 2),
            ]
        );
    }
}

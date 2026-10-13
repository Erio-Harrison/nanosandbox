//! `--audit-dir`: what each server did, kept so that tampering shows.
//!
//! The directory holds one file per server run, `session-<ms>-<pid>.jsonl`,
//! and a small `ledger.jsonl` that lists the sessions. Both are hash chains:
//! each line is `{"seq", "prev", "<body>", "hash"}`, where `hash` is the
//! SHA-256 of `seq`, `prev` (the line before's hash) and the body's JSON, so
//! changing, removing or reordering a line breaks the chain from there on.
//!
//! A session file starts with the server's own start, then for each command
//! a `run_start`, written *before* the command runs (and refusing it if it
//! can't be written), and a `run_end` after. A `run_start` with no `run_end`
//! is a command that was running when the server died. A clean shutdown
//! ends the file with `session_end`; without it the session is *unsealed*.
//!
//! The ledger says a session opened, then that it closed (with its record
//! count and last hash), or was removed by `--audit-cleanup`. So a session
//! file that vanishes, or is cut short after it was sealed, is seen.
//!
//! What it can't show: lines cut off the end of a session that was never
//! sealed, the ledger's own tail cut off, or everything replaced by a new
//! chain. The directory is as safe as where it lives: commands can neither
//! write nor read it (see `Config::build`), but whoever runs the server can.
//! Keep a copy of the ledger's head somewhere else to close that.
//!
//! Nothing here ever deletes anything except `--audit-cleanup`, on request.

use nanosandbox::audit::{AuditEnd, AuditSink, AuditStart};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// The `prev` of a chain's first line.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const LEDGER: &str = "ledger.jsonl";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn digest(seq: u64, prev: &str, body: &str) -> String {
    let mut h = Sha256::new();
    h.update(format!("{seq}\n{prev}\n{body}"));
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn lock(file: &File, wait: bool) -> bool {
    let op = libc::LOCK_EX | if wait { 0 } else { libc::LOCK_NB };
    unsafe { libc::flock(file.as_raw_fd(), op) == 0 }
}

/// Reads a whole chain, calling `each` on every body, and returns how many
/// lines there are and the last hash. `key` is the name of the body field.
fn read_chain(
    path: &Path,
    key: &str,
    mut each: impl FnMut(u64, &Value),
) -> Result<(u64, String), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut head = GENESIS.to_string();
    let mut records = 0;
    for (i, line) in text.split_inclusive('\n').enumerate() {
        let bad = |what: &str| format!("{}: line {}: {what}", path.display(), i + 1);
        let Some(line) = line.strip_suffix('\n') else {
            return Err(bad("incomplete (no newline): cut off, or being written to"));
        };
        let v: Value = serde_json::from_str(line).map_err(|e| bad(&format!("not JSON: {e}")))?;
        let seq = v["seq"].as_u64().ok_or_else(|| bad("no seq"))?;
        if seq != records {
            return Err(bad(&format!(
                "seq is {seq}, expected {records}: a line is missing or moved"
            )));
        }
        let prev = v["prev"].as_str().ok_or_else(|| bad("no prev"))?;
        if prev != head {
            return Err(bad("does not follow the line before it"));
        }
        let hash = v["hash"].as_str().ok_or_else(|| bad("no hash"))?;
        if hash != digest(seq, prev, &v[key].to_string()) {
            return Err(bad("its content does not match its hash: it was changed"));
        }
        each(records, &v[key]);
        head = hash.to_string();
        records += 1;
    }
    Ok((records, head))
}

fn line_for(seq: u64, prev: &str, key: &str, body: &Value) -> (String, String) {
    let hash = digest(seq, prev, &body.to_string());
    let mut line = json!({"seq": seq, "prev": prev, "hash": hash});
    line[key] = body.clone();
    (format!("{line}\n"), hash)
}

fn private_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("{}: {e}", dir.display()))
}

// ---- the ledger ----------------------------------------------------------

/// The ledger, held (locked) for as long as this exists. Servers each hold it
/// only for the moment it takes to add a line.
struct Ledger {
    file: File,
    seq: u64,
    head: String,
    entries: Vec<Value>,
}

impl Ledger {
    fn open(dir: &Path) -> Result<Self, String> {
        let path = dir.join(LEDGER);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if !lock(&file, true) {
            return Err(format!("{}: could not lock it", path.display()));
        }
        let mut entries = Vec::new();
        let (seq, head) = read_chain(&path, "entry", |_, v| entries.push(v.clone()))?;
        Ok(Self {
            file,
            seq,
            head,
            entries,
        })
    }

    fn append(&mut self, entry: Value) -> Result<(), String> {
        let (line, hash) = line_for(self.seq, &self.head, "entry", &entry);
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.sync_data())
            .map_err(|e| format!("ledger: {e}"))?;
        self.seq += 1;
        self.head = hash;
        self.entries.push(entry);
        Ok(())
    }
}

// ---- a session -------------------------------------------------------------

pub struct Session {
    name: String,
    inner: Mutex<Inner>,
    closed: AtomicBool,
    dir: PathBuf,
}

struct Inner {
    /// Held locked for the server's life: whether a session is still running
    /// is whether its lock can be taken.
    file: File,
    seq: u64,
    head: String,
    runs: u64,
    /// Why no more can be written; once set, nothing runs.
    failed: Option<String>,
}

impl Session {
    /// Starts a session in `dir`: its own file, and a line in the ledger.
    /// Reads only the ledger, which stays small however long the history.
    pub fn open(dir: &Path) -> Result<Self, String> {
        private_dir(dir)?;
        let mut ledger = Ledger::open(dir)?;
        let (name, path, file) = (0..100)
            .find_map(|n| {
                let name = format!("session-{}-{}-{n}.jsonl", now_ms(), std::process::id());
                let path = dir.join(&name);
                OpenOptions::new()
                    .create_new(true)
                    .append(true)
                    .mode(0o600)
                    .open(&path)
                    .ok()
                    .map(|f| (name, path, f))
            })
            .ok_or("could not create a session file")?;
        if !lock(&file, false) {
            return Err(format!("{}: could not lock it", path.display()));
        }
        let mut inner = Inner {
            file,
            seq: 0,
            head: GENESIS.to_string(),
            runs: 0,
            failed: None,
        };
        let start = json!({
            "kind": "session_start",
            "ts_ms": now_ms(),
            "pid": std::process::id(),
            "version": env!("CARGO_PKG_VERSION"),
        });
        Self::write(&mut inner, &start).map_err(|e| format!("{}: {e}", path.display()))?;
        ledger.append(json!({
            "kind": "open", "session": name, "ts_ms": now_ms(),
        }))?;
        Ok(Self {
            name,
            inner: Mutex::new(inner),
            closed: AtomicBool::new(false),
            dir: dir.to_path_buf(),
        })
    }

    fn write(inner: &mut Inner, record: &Value) -> std::io::Result<()> {
        let (line, hash) = line_for(inner.seq, &inner.head, "record", record);
        inner.file.write_all(line.as_bytes())?;
        inner.file.sync_data()?;
        inner.seq += 1;
        inner.head = hash;
        Ok(())
    }

    /// Seals the session on a clean shutdown: `session_end` in its file, and
    /// its length and last hash in the ledger. Once only.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.failed.is_some() {
            return; // what's there is what there is: left unsealed
        }
        let end = json!({"kind": "session_end", "ts_ms": now_ms(), "runs": inner.runs});
        if let Err(e) = Self::write(&mut inner, &end) {
            eprintln!("nanosandbox-mcp: audit: could not seal {}: {e}", self.name);
            return;
        }
        let sealed = Ledger::open(&self.dir).and_then(|mut l| {
            l.append(json!({
                "kind": "close", "session": self.name, "ts_ms": now_ms(),
                "records": inner.seq, "head": inner.head,
            }))
        });
        if let Err(e) = sealed {
            eprintln!("nanosandbox-mcp: audit: could not record the close: {e}");
        }
    }

    fn fail(inner: &mut Inner, e: std::io::Error) -> String {
        let why = format!("the audit log could not be written: {e}");
        eprintln!("nanosandbox-mcp: audit: {why}");
        inner.failed = Some(why.clone());
        why
    }
}

impl AuditSink for Session {
    fn begin(&self, start: &AuditStart) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(why) = &inner.failed {
            return Err(why.clone());
        }
        let record = json!({"kind": "run_start", "start": start});
        Self::write(&mut inner, &record).map_err(|e| Self::fail(&mut inner, e))?;
        inner.runs += 1;
        Ok(())
    }

    fn end(&self, end: &AuditEnd) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.failed.is_some() {
            return;
        }
        let record = json!({"kind": "run_end", "end": end});
        if let Err(e) = Self::write(&mut inner, &record) {
            Self::fail(&mut inner, e);
        }
    }
}

// ---- reading it back -------------------------------------------------------

/// What `--audit-verify` found.
#[derive(Debug, Default)]
pub struct Report {
    pub sessions: u64,
    pub sealed: u64,
    pub runs: u64,
    pub ledger_head: String,
    /// Not integrity failures, but worth knowing: a session that was never
    /// sealed, a command that never ended, one that is still running.
    pub notes: Vec<String>,
    /// The chain is broken, or what the ledger says isn't what's there.
    pub errors: Vec<String>,
}

struct Seen {
    records: u64,
    head: String,
    runs: u64,
    unfinished: u64,
    sealed_in_file: bool,
}

fn read_session(path: &Path) -> Result<Seen, String> {
    let (mut runs, mut open_runs, mut sealed) = (0, 0u64, false);
    let mut first = true;
    let mut shape_error = None;
    let (records, head) = read_chain(path, "record", |_, r| {
        if std::mem::take(&mut first) && r["kind"] != "session_start" {
            shape_error = Some("does not begin with session_start".to_string());
        }
        match r["kind"].as_str() {
            Some("run_start") => {
                runs += 1;
                open_runs += 1;
            }
            Some("run_end") => open_runs = open_runs.saturating_sub(1),
            Some("session_end") => sealed = true,
            _ => {}
        }
    })?;
    if let Some(e) = shape_error {
        return Err(format!("{}: {e}", path.display()));
    }
    Ok(Seen {
        records,
        head,
        runs,
        unfinished: open_runs,
        sealed_in_file: sealed,
    })
}

fn is_running(path: &Path) -> bool {
    OpenOptions::new()
        .read(true)
        .open(path)
        .map(|f| !lock(&f, false))
        .unwrap_or(false)
}

/// Checks the ledger, and every session in it against the ledger.
pub fn verify(dir: &Path) -> Report {
    let mut report = Report::default();
    let mut entries = Vec::new();
    match read_chain(&dir.join(LEDGER), "entry", |_, v| entries.push(v.clone())) {
        Ok((_, head)) => report.ledger_head = head,
        Err(e) => {
            report.errors.push(e);
            return report;
        }
    }
    // Per session: closed (records, head), removed.
    let mut closed: BTreeMap<String, (u64, String)> = BTreeMap::new();
    let mut removed: Vec<String> = Vec::new();
    let mut opened: Vec<String> = Vec::new();
    for e in &entries {
        let session = e["session"].as_str().unwrap_or("").to_string();
        match e["kind"].as_str() {
            Some("open") => opened.push(session),
            Some("close") => {
                closed.insert(
                    session,
                    (
                        e["records"].as_u64().unwrap_or(0),
                        e["head"].as_str().unwrap_or("").to_string(),
                    ),
                );
            }
            Some("removed") => removed.push(session),
            _ => {}
        }
    }
    for name in &opened {
        if removed.contains(name) {
            continue;
        }
        report.sessions += 1;
        let path = dir.join(name);
        if !path.exists() {
            report.errors.push(format!(
                "{name}: in the ledger, but the file is gone (and not removed by --audit-cleanup)"
            ));
            continue;
        }
        let seen = match read_session(&path) {
            Ok(s) => s,
            Err(e) => {
                report.errors.push(e);
                continue;
            }
        };
        report.runs += seen.runs;
        match closed.get(name) {
            Some((records, head)) => {
                report.sealed += 1;
                if *records != seen.records || *head != seen.head {
                    report.errors.push(format!(
                        "{name}: sealed with {records} records, but the file holds {} (cut short, or changed after)",
                        seen.records
                    ));
                }
                if !seen.sealed_in_file {
                    report
                        .errors
                        .push(format!("{name}: the ledger says it closed, the file doesn't"));
                }
            }
            None if is_running(&path) => report.notes.push(format!("{name}: still running")),
            None => report.notes.push(format!(
                "{name}: unsealed: the server died or was killed ({} commands started, {} with no end)",
                seen.runs, seen.unfinished
            )),
        }
        if seen.unfinished > 0 && closed.contains_key(name) {
            report.notes.push(format!(
                "{name}: {} commands started and never ended (still running when it shut down)",
                seen.unfinished
            ));
        }
    }
    // Files the ledger doesn't know of.
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("session-") && name.ends_with(".jsonl") && !opened.contains(&name) {
                report
                    .errors
                    .push(format!("{name}: not in the ledger (not made by a server)"));
            }
        }
    }
    report
}

/// What `--audit-cleanup` is to remove: all of the filters given have to
/// hold. A running session is never touched, nor one that doesn't verify:
/// that would remove the evidence of tampering.
#[derive(Debug, Default, Clone)]
pub struct CleanupPlan {
    pub keep: Option<usize>,
    pub older_than_days: Option<u64>,
    pub max_total_bytes: Option<u64>,
    pub dry_run: bool,
}

#[derive(Debug)]
pub struct Removal {
    pub session: String,
    pub bytes: u64,
}

/// Removes old sessions, oldest first, and says so in the ledger (the
/// session's record count and last hash stay there).
pub fn cleanup(dir: &Path, plan: &CleanupPlan) -> Result<Vec<Removal>, String> {
    if plan.keep.is_none() && plan.older_than_days.is_none() && plan.max_total_bytes.is_none() {
        return Err("--audit-cleanup needs --keep, --older-than or --max-total-size".into());
    }
    let mut ledger = Ledger::open(dir)?;
    let removed: Vec<String> = ledger
        .entries
        .iter()
        .filter(|e| e["kind"] == "removed")
        .filter_map(|e| e["session"].as_str().map(String::from))
        .collect();
    // (name, opened at, bytes), oldest first, of the sessions that can go.
    struct Candidate {
        name: String,
        opened: u64,
        bytes: u64,
        records: u64,
        head: String,
    }
    let mut all: Vec<Candidate> = Vec::new();
    let mut untouchable_bytes = 0u64;
    for e in ledger.entries.iter().filter(|e| e["kind"] == "open") {
        let name = e["session"].as_str().unwrap_or("").to_string();
        if removed.contains(&name) {
            continue;
        }
        let path = dir.join(&name);
        let bytes = std::fs::metadata(&path).map_or(0, |m| m.len());
        let opened = e["ts_ms"].as_u64().unwrap_or(0);
        if !path.exists() || is_running(&path) {
            untouchable_bytes += bytes;
            continue;
        }
        match read_session(&path) {
            Ok(seen) => all.push(Candidate {
                name,
                opened,
                bytes,
                records: seen.records,
                head: seen.head,
            }),
            Err(_) => untouchable_bytes += bytes,
        }
    }
    all.sort_by_key(|c| c.opened);
    let total: u64 = all.iter().map(|c| c.bytes).sum::<u64>() + untouchable_bytes;
    let now = now_ms();
    let newest_kept = plan.keep.map_or(0, |k| all.len().saturating_sub(k));
    let mut doomed: Vec<&Candidate> = Vec::new();
    let mut remaining = total;
    for (i, c) in all.iter().enumerate() {
        if plan.keep.is_some() && i >= newest_kept {
            continue;
        }
        if let Some(days) = plan.older_than_days
            && now.saturating_sub(c.opened) <= days * 86_400_000
        {
            continue;
        }
        if let Some(budget) = plan.max_total_bytes
            && remaining <= budget
        {
            continue;
        }
        remaining = remaining.saturating_sub(c.bytes);
        doomed.push(c);
    }
    let mut out = Vec::new();
    for c in doomed {
        if !plan.dry_run {
            ledger.append(json!({
                "kind": "removed", "session": c.name, "ts_ms": now_ms(),
                "records": c.records, "head": c.head,
            }))?;
            std::fs::remove_file(dir.join(&c.name)).map_err(|e| format!("{}: {e}", c.name))?;
        }
        out.push(Removal {
            session: c.name.clone(),
            bytes: c.bytes,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosandbox::Sandbox;
    use std::sync::Arc;

    fn sandbox(session: &Arc<Session>) -> Sandbox {
        Sandbox::builder()
            .working_dir("/")
            .audit(session.clone())
            .build()
            .unwrap()
    }

    /// A session with `n` commands run, sealed or not.
    fn session_in(dir: &Path, n: usize, seal: bool) -> String {
        let session = Arc::new(Session::open(dir).unwrap());
        let sb = sandbox(&session);
        for i in 0..n {
            sb.run("echo", &[&i.to_string()]).unwrap();
        }
        let name = session.name.clone();
        if seal {
            session.close();
        }
        name
    }

    fn lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }

    fn write(path: &Path, lines: &[String]) {
        std::fs::write(path, lines.join("\n") + "\n").unwrap();
    }

    #[test]
    fn a_session_records_each_command_twice_and_is_sealed_on_close() {
        let dir = tempfile::tempdir().unwrap();
        let name = session_in(dir.path(), 2, true);
        let kinds: Vec<String> = lines(&dir.path().join(&name))
            .iter()
            .map(|l| serde_json::from_str::<Value>(l).unwrap()["record"]["kind"].to_string())
            .collect();
        assert_eq!(
            kinds,
            [
                "\"session_start\"",
                "\"run_start\"",
                "\"run_end\"",
                "\"run_start\"",
                "\"run_end\"",
                "\"session_end\""
            ]
        );
        let r = verify(dir.path());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!((r.sessions, r.sealed, r.runs), (1, 1, 2));
        assert!(r.notes.is_empty(), "{:?}", r.notes);
    }

    #[test]
    fn a_session_that_died_is_unsealed_and_a_running_one_is_said_to_run() {
        let dir = tempfile::tempdir().unwrap();
        let dead = session_in(dir.path(), 1, false); // dropped: its lock is gone
        let alive = Arc::new(Session::open(dir.path()).unwrap());
        let r = verify(dir.path());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!((r.sessions, r.sealed), (2, 0));
        assert!(
            r.notes
                .iter()
                .any(|n| n.starts_with(&dead) && n.contains("unsealed")),
            "{:?}",
            r.notes
        );
        assert!(
            r.notes
                .iter()
                .any(|n| n.starts_with(&alive.name) && n.contains("still running")),
            "{:?}",
            r.notes
        );
    }

    /// A command that began and never ended is in the record.
    #[test]
    fn a_command_that_never_ended_is_shown() {
        let dir = tempfile::tempdir().unwrap();
        let session = Arc::new(Session::open(dir.path()).unwrap());
        let sb = sandbox(&session);
        sb.run("echo", &["done"]).unwrap();
        // Begun, then the host died: only the start was written.
        let start = serde_json::to_value(nanosandbox_start()).unwrap();
        let mut inner = session.inner.lock().unwrap();
        Session::write(&mut inner, &json!({"kind": "run_start", "start": start})).unwrap();
        drop(inner);
        let name = session.name.clone();
        drop(sb);
        drop(session);
        let r = verify(dir.path());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(
            r.notes
                .iter()
                .any(|n| n.starts_with(&name) && n.contains("2 commands started, 1 with no end")),
            "{:?}",
            r.notes
        );
    }

    fn nanosandbox_start() -> Value {
        json!({"command": "sleep", "args": ["60"], "run": 99})
    }

    #[test]
    fn changing_removing_or_reordering_a_line_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let name = session_in(dir.path(), 3, true);
        let path = dir.path().join(&name);
        let original = lines(&path);

        let mut changed = original.clone();
        changed[1] = changed[1].replace("echo", "ech0");
        write(&path, &changed);
        let r = verify(dir.path());
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains("line 2") && e.contains("changed")),
            "{:?}",
            r.errors
        );

        let mut removed = original.clone();
        removed.remove(1);
        write(&path, &removed);
        assert!(
            verify(dir.path())
                .errors
                .iter()
                .any(|e| e.contains("line 2") && e.contains("missing")),
        );

        let mut swapped = original.clone();
        swapped.swap(1, 2);
        write(&path, &swapped);
        assert!(!verify(dir.path()).errors.is_empty());

        // Cut short after it was sealed: the ledger knows how long it was.
        write(&path, &original[..4]);
        let r = verify(dir.path());
        assert!(
            r.errors.iter().any(|e| e.contains("sealed with 8 records")),
            "{:?}",
            r.errors
        );
    }

    #[test]
    fn a_session_file_that_vanishes_or_appears_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let name = session_in(dir.path(), 1, true);
        std::fs::copy(
            dir.path().join(&name),
            dir.path().join("session-1-1-0.jsonl"),
        )
        .unwrap();
        let r = verify(dir.path());
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains("session-1-1-0.jsonl: not in the ledger")),
            "{:?}",
            r.errors
        );
        std::fs::remove_file(dir.path().join("session-1-1-0.jsonl")).unwrap();
        std::fs::remove_file(dir.path().join(&name)).unwrap();
        let r = verify(dir.path());
        assert!(
            r.errors
                .iter()
                .any(|e| e.contains(&name) && e.contains("file is gone")),
            "{:?}",
            r.errors
        );
    }

    #[test]
    fn a_changed_ledger_is_found_and_stops_a_new_session() {
        let dir = tempfile::tempdir().unwrap();
        session_in(dir.path(), 1, true);
        let ledger = dir.path().join(LEDGER);
        let mut l = lines(&ledger);
        l[0] = l[0].replace("open", "opem");
        write(&ledger, &l);
        assert!(!verify(dir.path()).errors.is_empty());
        assert!(Session::open(dir.path()).is_err());
    }

    /// Two agents on one machine, one directory.
    #[test]
    fn several_servers_can_share_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let a = Arc::new(Session::open(dir.path()).unwrap());
        let b = Arc::new(Session::open(dir.path()).unwrap());
        let (sa, sb) = (sandbox(&a), sandbox(&b));
        sa.run("echo", &["a"]).unwrap();
        sb.run("echo", &["b"]).unwrap();
        a.close();
        b.close();
        let r = verify(dir.path());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!((r.sessions, r.sealed, r.runs), (2, 2, 2));
    }

    /// If the record can't be written, nothing runs, and keeps not running.
    #[test]
    fn once_the_log_cannot_be_written_no_command_runs() {
        let dir = tempfile::tempdir().unwrap();
        let session = Arc::new(Session::open(dir.path()).unwrap());
        // A handle that can't be written to stands in for a full disk.
        let path = dir.path().join(&session.name);
        session.inner.lock().unwrap().file = File::open(path).unwrap();
        let sb = sandbox(&session);
        let err = sb.run("echo", &["x"]).unwrap_err();
        assert!(err.to_string().contains("could not be written"), "{err}");
        let again = sb.run("echo", &["y"]).unwrap_err();
        assert!(
            again.to_string().contains("could not be written"),
            "{again}"
        );
    }

    fn names(removed: &[Removal]) -> Vec<String> {
        removed.iter().map(|r| r.session.clone()).collect()
    }

    #[test]
    fn cleanup_removes_the_oldest_and_says_so_in_the_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let made: Vec<String> = (0..3)
            .map(|_| {
                std::thread::sleep(std::time::Duration::from_millis(5));
                session_in(dir.path(), 1, true)
            })
            .collect();
        let plan = CleanupPlan {
            keep: Some(1),
            dry_run: true,
            ..Default::default()
        };
        let would = cleanup(dir.path(), &plan).unwrap();
        assert_eq!(names(&would), made[..2]);
        assert!(made.iter().all(|n| dir.path().join(n).exists()), "dry run");

        let gone = cleanup(
            dir.path(),
            &CleanupPlan {
                keep: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(names(&gone), made[..2]);
        assert!(!dir.path().join(&made[0]).exists() && dir.path().join(&made[2]).exists());
        let r = verify(dir.path());
        assert!(
            r.errors.is_empty(),
            "removal is in the ledger: {:?}",
            r.errors
        );
        assert_eq!(r.sessions, 1);
    }

    #[test]
    fn cleanup_leaves_a_running_session_and_one_that_does_not_verify() {
        let dir = tempfile::tempdir().unwrap();
        let running = Arc::new(Session::open(dir.path()).unwrap());
        let tampered = session_in(dir.path(), 2, true);
        let path = dir.path().join(&tampered);
        let mut l = lines(&path);
        l[1] = l[1].replace("echo", "ech0");
        write(&path, &l);
        let old = session_in(dir.path(), 1, true);
        let gone = cleanup(
            dir.path(),
            &CleanupPlan {
                keep: Some(0),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(names(&gone), [old]);
        assert!(dir.path().join(&running.name).exists() && path.exists());
    }

    #[test]
    fn cleanup_by_age_and_by_size() {
        let dir = tempfile::tempdir().unwrap();
        session_in(dir.path(), 1, true);
        let none = cleanup(
            dir.path(),
            &CleanupPlan {
                older_than_days: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(none.is_empty(), "nothing is a day old");
        let big = cleanup(
            dir.path(),
            &CleanupPlan {
                max_total_bytes: Some(10),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(big.len(), 1);
        assert!(
            cleanup(dir.path(), &CleanupPlan::default()).is_err(),
            "a plan needs a filter"
        );
    }

    #[test]
    fn the_files_are_private_to_their_owner() {
        let dir = tempfile::tempdir().unwrap();
        let name = session_in(dir.path(), 1, true);
        for f in [name.as_str(), LEDGER] {
            let mode = std::fs::metadata(dir.path().join(f))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "{f}: {mode:o}");
        }
    }
}

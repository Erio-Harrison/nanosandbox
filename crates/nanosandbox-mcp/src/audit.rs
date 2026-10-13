//! `--audit-dir`: what each server did, kept so that tampering shows.
//!
//! The directory holds one file per server run, `session-<ms>-<pid>-<n>.jsonl`.
//! Each line is `{"seq", "prev", "record", "hash"}`, where `hash` is the SHA-256
//! of `seq`, `prev` (the line before's hash) and the record's JSON, so
//! changing, removing or reordering a line breaks the chain from there on.
//!
//! A file starts with `session_start`, then for each command a `run_start`,
//! written *before* the command runs (and refusing it if it can't be
//! written), and a `run_end` after. A `run_start` with no `run_end` is a
//! command that was running when the server died. A clean shutdown ends the
//! file with `session_end`; without it the session is *unsealed*.
//!
//! Servers don't share a file, so any number can record into one directory
//! and none waits on another. Starting a server reads nothing of the history.
//!
//! What it can't show: a session cut short or removed by whoever has the
//! files (a cut-short sealed session just reads as unsealed), or a chain
//! replaced by a new one. The directory is as safe as where it lives:
//! commands can neither write nor read it (see `Config::build`), but whoever
//! runs the server can. Keep a copy of a session's last hash elsewhere to
//! close that.
//!
//! Old sessions are removed by [`prune`]: at every start, by age and total
//! size (see [`Retention`]), and on request by `--audit-cleanup`.

use nanosandbox::audit::{AuditEnd, AuditSink, AuditStart};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

/// The `prev` of a chain's first line.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// How long a session is kept, by default.
pub const DEFAULT_KEEP_DAYS: u64 = 30;
/// How much a directory of sessions may hold, by default.
pub const DEFAULT_MAX_BYTES: u64 = 1 << 30;

/// A session written to this recently is left alone by the automatic
/// removal, whatever its age or the directory's size: it may be a server
/// that has made its file and not yet locked it.
const GRACE: Duration = Duration::from_secs(300);

/// What starting a server keeps. `None`: no limit of that kind.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Retention {
    pub keep_days: Option<u64>,
    pub max_bytes: Option<u64>,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            keep_days: Some(DEFAULT_KEEP_DAYS),
            max_bytes: Some(DEFAULT_MAX_BYTES),
        }
    }
}

impl Retention {
    pub fn describe(&self) -> String {
        let days = self
            .keep_days
            .map_or("no age limit".to_string(), |d| format!("{d} days"));
        let size = self
            .max_bytes
            .map_or("no size limit".to_string(), |b| format!("{} MB", b >> 20));
        format!("keeping {days} / {size}")
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn digest(seq: u64, prev: &str, body: &str) -> String {
    let mut h = Sha256::new();
    h.update(format!("{seq}\n{prev}\n{body}"));
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn lock(file: &File) -> bool {
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

/// Reads a whole chain, calling `each` on every record, and returns how many
/// lines there are and the last hash.
fn read_chain(path: &Path, mut each: impl FnMut(&Value)) -> Result<(u64, String), String> {
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
        if hash != digest(seq, prev, &v["record"].to_string()) {
            return Err(bad("its content does not match its hash: it was changed"));
        }
        each(&v["record"]);
        head = hash.to_string();
        records += 1;
    }
    Ok((records, head))
}

fn line_for(seq: u64, prev: &str, record: &Value) -> (String, String) {
    let hash = digest(seq, prev, &record.to_string());
    let line = json!({"seq": seq, "prev": prev, "record": record, "hash": hash});
    (format!("{line}\n"), hash)
}

// ---- a session -------------------------------------------------------------

pub struct Session {
    name: String,
    inner: Mutex<Inner>,
    closed: AtomicBool,
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
    /// Starts a session in `dir`, and then removes old ones as `retention`
    /// says. A failure to remove is said, not fatal: a full or odd directory
    /// shouldn't keep the server from starting.
    pub fn open(dir: &Path, retention: &Retention) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
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
            .ok_or_else(|| format!("{}: could not create a session file", dir.display()))?;
        if !lock(&file) {
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
        remove_old(dir, &name, retention);
        Ok(Self {
            name,
            inner: Mutex::new(inner),
            closed: AtomicBool::new(false),
        })
    }

    fn write(inner: &mut Inner, record: &Value) -> std::io::Result<()> {
        let (line, hash) = line_for(inner.seq, &inner.head, record);
        inner.file.write_all(line.as_bytes())?;
        inner.file.sync_data()?;
        inner.seq += 1;
        inner.head = hash;
        Ok(())
    }

    /// Seals the session on a clean shutdown. Once only.
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
        }
    }

    fn fail(inner: &mut Inner, e: std::io::Error) -> String {
        let why = format!(
            "the audit record could not be written ({e}); commands are refused until the \
             server is restarted. Free space or fix the --audit-dir, or run without it"
        );
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
    /// Not integrity failures, but worth knowing: a session that was never
    /// sealed, a command that never ended, one that is still running.
    pub notes: Vec<String>,
    /// A chain is broken.
    pub errors: Vec<String>,
}

struct Seen {
    runs: u64,
    unfinished: u64,
    sealed: bool,
}

fn read_session(path: &Path) -> Result<Seen, String> {
    let (mut runs, mut open_runs, mut sealed) = (0, 0u64, false);
    let mut first = true;
    let mut shape_error = None;
    read_chain(path, |r| {
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
        runs,
        unfinished: open_runs,
        sealed,
    })
}

fn is_running(path: &Path) -> bool {
    OpenOptions::new()
        .read(true)
        .open(path)
        .map(|f| !lock(&f))
        .unwrap_or(false)
}

/// The sessions in `dir`, or the one file `path` names.
fn session_paths(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    let mut v: Vec<PathBuf> = std::fs::read_dir(path)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| is_session_name(p))
        .collect();
    v.sort();
    v
}

fn is_session_name(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("session-") && n.ends_with(".jsonl"))
}

/// Checks the chain of every session in `path` (a directory, or one file).
pub fn verify(path: &Path) -> Report {
    let mut report = Report::default();
    if !path.exists() {
        report
            .errors
            .push(format!("{}: no such file or directory", path.display()));
        return report;
    }
    for file in session_paths(path) {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        report.sessions += 1;
        let seen = match read_session(&file) {
            Ok(s) => s,
            Err(e) => {
                report.errors.push(e);
                continue;
            }
        };
        report.runs += seen.runs;
        if seen.sealed {
            report.sealed += 1;
            if seen.unfinished > 0 {
                report.notes.push(format!(
                    "{name}: {} commands started and never ended (still running when it shut down)",
                    seen.unfinished
                ));
            }
        } else if is_running(&file) {
            report.notes.push(format!("{name}: still running"));
        } else {
            report.notes.push(format!(
                "{name}: unsealed: the server died or was killed, or the file was cut short \
                 ({} commands started, {} with no end)",
                seen.runs, seen.unfinished
            ));
        }
    }
    report
}

// ---- removing old sessions -------------------------------------------------

/// What to remove. All of the filters given have to hold for a session to go.
#[derive(Debug, Default, Clone)]
pub struct Plan {
    /// Keep this many of the newest sessions, whatever else.
    pub keep: Option<usize>,
    /// Only sessions last written to more than this many days ago.
    pub older_than_days: Option<u64>,
    /// Oldest first, until the directory holds no more than this.
    pub max_total_bytes: Option<u64>,
    /// Leave sessions written to within this long alone.
    pub grace: Duration,
    /// Read each session and leave one that doesn't verify: it may be the
    /// evidence of tampering. Costs reading it.
    pub verify_first: bool,
    pub dry_run: bool,
    /// A session never to remove: the caller's own.
    pub protect: Option<String>,
}

#[derive(Debug)]
pub struct Removal {
    pub session: String,
    pub bytes: u64,
}

#[derive(Debug, Default)]
pub struct Pruned {
    pub removed: Vec<Removal>,
    /// Left because they don't verify.
    pub unverified: Vec<String>,
}

struct Found {
    path: PathBuf,
    name: String,
    bytes: u64,
    modified: SystemTime,
}

/// Removes sessions from `dir` as `plan` says, oldest first. Never one that
/// is still running, nor the plan's `protect`. Only looks at names, sizes
/// and times, plus each file's contents if `verify_first`.
pub fn prune(dir: &Path, plan: &Plan) -> Result<Pruned, String> {
    // With no filter every condition holds, and everything would go.
    if plan.keep.is_none() && plan.older_than_days.is_none() && plan.max_total_bytes.is_none() {
        return Err("--audit-cleanup needs --keep, --older-than or --max-total-size".into());
    }
    let mut all: Vec<Found> = session_paths(dir)
        .into_iter()
        .filter_map(|path| {
            let meta = std::fs::metadata(&path).ok()?;
            Some(Found {
                name: path.file_name()?.to_string_lossy().into_owned(),
                bytes: meta.len(),
                modified: meta.modified().ok()?,
                path,
            })
        })
        .collect();
    all.sort_by_key(|f| f.modified);
    let now = SystemTime::now();
    let total: u64 = all.iter().map(|f| f.bytes).sum();
    let newest_kept = plan.keep.map_or(0, |k| all.len().saturating_sub(k));
    let mut remaining = total;
    let mut out = Pruned::default();
    for (i, f) in all.iter().enumerate() {
        let age = now.duration_since(f.modified).unwrap_or_default();
        if plan.keep.is_some() && i >= newest_kept {
            continue;
        }
        if plan.protect.as_deref() == Some(f.name.as_str()) || age < plan.grace {
            continue;
        }
        if let Some(days) = plan.older_than_days
            && age <= Duration::from_secs(days * 86_400)
        {
            continue;
        }
        if let Some(budget) = plan.max_total_bytes
            && remaining <= budget
        {
            continue;
        }
        if is_running(&f.path) {
            continue;
        }
        if plan.verify_first && read_session(&f.path).is_err() {
            out.unverified.push(f.name.clone());
            continue;
        }
        if !plan.dry_run {
            match std::fs::remove_file(&f.path) {
                Ok(()) => {}
                // Another server starting at the same time got there first.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{}: {e}", f.path.display())),
            }
        }
        remaining = remaining.saturating_sub(f.bytes);
        out.removed.push(Removal {
            session: f.name.clone(),
            bytes: f.bytes,
        });
    }
    Ok(out)
}

/// What starting a server does: removes what `retention` says is too old,
/// then, if the directory is still too big, the oldest. Never its own
/// session, a running one, or one written to in the last few minutes. Reads
/// no session, so it costs the same however much history there is.
fn remove_old(dir: &Path, own: &str, retention: &Retention) {
    let passes = [
        Plan {
            older_than_days: retention.keep_days,
            ..Plan::default()
        },
        Plan {
            max_total_bytes: retention.max_bytes,
            ..Plan::default()
        },
    ];
    let mut removed = 0;
    let mut bytes = 0;
    for plan in passes {
        if plan.older_than_days.is_none() && plan.max_total_bytes.is_none() {
            continue;
        }
        let plan = Plan {
            grace: GRACE,
            protect: Some(own.to_string()),
            ..plan
        };
        match prune(dir, &plan) {
            Ok(p) => {
                removed += p.removed.len();
                bytes += p.removed.iter().map(|r| r.bytes).sum::<u64>();
            }
            Err(e) => {
                eprintln!("nanosandbox-mcp: audit: could not remove old sessions: {e}");
                return;
            }
        }
    }
    if removed > 0 {
        eprintln!(
            "nanosandbox-mcp: audit: removed {removed} old sessions ({} MB)",
            bytes >> 20
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosandbox::Sandbox;
    use std::sync::Arc;

    const DAY: u64 = 86_400;

    fn open(dir: &Path) -> Arc<Session> {
        Arc::new(Session::open(dir, &Retention::default()).unwrap())
    }

    fn sandbox(session: &Arc<Session>) -> Sandbox {
        Sandbox::builder()
            .working_dir("/")
            .audit(session.clone())
            .build()
            .unwrap()
    }

    /// A session with `n` commands run, sealed or not, its file name.
    fn session_in(dir: &Path, n: usize, seal: bool) -> String {
        let session = open(dir);
        let sb = sandbox(&session);
        for i in 0..n {
            sb.run("echo", &[&i.to_string()]).unwrap();
        }
        let name = session.name.clone();
        if seal {
            session.close();
        }
        drop(sb);
        drop(session);
        wait_dead(&dir.join(&name));
        name
    }

    /// Waits for a dropped session's lock to go. Tests run on threads of one
    /// process, and another test's sandbox, between clone and exec, holds
    /// copies of every descriptor the process has, this lock among them. Not
    /// something a real server has: only its own children could.
    fn wait_dead(path: &Path) {
        let start = std::time::Instant::now();
        while is_running(path) {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "{} is still locked",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Makes a file look last written `secs` ago.
    fn age(path: &Path, secs: u64) {
        let when = SystemTime::now() - Duration::from_secs(secs);
        OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(when)
            .unwrap();
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

    fn sessions(dir: &Path) -> Vec<String> {
        session_paths(dir)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    // ---- recording and checking ----

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
    fn a_session_can_be_checked_by_itself() {
        let dir = tempfile::tempdir().unwrap();
        let name = session_in(dir.path(), 1, true);
        let r = verify(&dir.path().join(&name));
        assert_eq!((r.sessions, r.errors.len()), (1, 0));
        assert!(!verify(&dir.path().join("nope")).errors.is_empty());
    }

    #[test]
    fn a_session_that_died_is_unsealed_and_a_running_one_is_said_to_run() {
        let dir = tempfile::tempdir().unwrap();
        let dead = session_in(dir.path(), 1, false); // dropped: its lock is gone
        let alive = open(dir.path());
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
        let session = open(dir.path());
        let sb = sandbox(&session);
        sb.run("echo", &["done"]).unwrap();
        // Begun, then the host died: only the start was written.
        let start = json!({"command": "sleep", "args": ["60"], "run": 99});
        let mut inner = session.inner.lock().unwrap();
        Session::write(&mut inner, &json!({"kind": "run_start", "start": start})).unwrap();
        drop(inner);
        let name = session.name.clone();
        drop(sb);
        drop(session);
        wait_dead(&dir.path().join(&name));
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

    #[test]
    fn changing_removing_or_reordering_a_line_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let name = session_in(dir.path(), 3, true);
        let path = dir.path().join(&name);
        let original = lines(&path);

        let mut changed = original.clone();
        changed[1] = changed[1].replace("echo", "ech0");
        write(&path, &changed);
        assert!(
            verify(dir.path())
                .errors
                .iter()
                .any(|e| e.contains("line 2") && e.contains("changed"))
        );

        let mut removed = original.clone();
        removed.remove(1);
        write(&path, &removed);
        assert!(
            verify(dir.path())
                .errors
                .iter()
                .any(|e| e.contains("line 2") && e.contains("missing"))
        );

        let mut swapped = original.clone();
        swapped.swap(1, 2);
        write(&path, &swapped);
        assert!(!verify(dir.path()).errors.is_empty());

        // Cut short, a session just reads as one that was never sealed: with
        // no one else keeping count, that is all there is to see.
        write(&path, &original[..4]);
        let r = verify(dir.path());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(
            r.notes.iter().any(|n| n.contains("unsealed")),
            "{:?}",
            r.notes
        );
    }

    /// Two agents on one machine, one directory.
    #[test]
    fn several_servers_can_share_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (open(dir.path()), open(dir.path()));
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
        let session = open(dir.path());
        // A handle that can't be written to stands in for a full disk.
        let path = dir.path().join(&session.name);
        session.inner.lock().unwrap().file = File::open(path).unwrap();
        let sb = sandbox(&session);
        let err = sb.run("echo", &["x"]).unwrap_err();
        assert!(err.to_string().contains("could not be written"), "{err}");
        assert!(
            err.to_string().contains("restarted"),
            "says what to do: {err}"
        );
        let again = sb.run("echo", &["y"]).unwrap_err();
        assert!(
            again.to_string().contains("could not be written"),
            "{again}"
        );
    }

    #[test]
    fn the_files_are_private_to_their_owner() {
        let dir = tempfile::tempdir().unwrap();
        let name = session_in(dir.path(), 1, true);
        let mode = std::fs::metadata(dir.path().join(&name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
    }

    // ---- what starting a server removes ----

    #[test]
    fn starting_a_server_removes_sessions_past_the_age_limit_and_keeps_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let old = session_in(dir.path(), 1, true);
        let recent = session_in(dir.path(), 1, true);
        age(&dir.path().join(&old), 40 * DAY);
        age(&dir.path().join(&recent), 5 * DAY);

        let own = open(dir.path());
        let left = sessions(dir.path());
        assert!(!left.contains(&old), "{left:?}");
        assert!(
            left.contains(&recent) && left.contains(&own.name),
            "{left:?}"
        );
    }

    #[test]
    fn a_session_still_running_stays_however_old_it_looks() {
        let dir = tempfile::tempdir().unwrap();
        let running = open(dir.path());
        age(&dir.path().join(&running.name), 400 * DAY);
        let _new = open(dir.path());
        assert!(sessions(dir.path()).contains(&running.name));
    }

    #[test]
    fn a_session_written_to_a_moment_ago_is_left_alone_whatever_the_limits() {
        let dir = tempfile::tempdir().unwrap();
        let fresh = session_in(dir.path(), 1, false);
        let tight = Retention {
            keep_days: Some(0),
            max_bytes: Some(1),
        };
        let _own = Session::open(dir.path(), &tight).unwrap();
        assert!(
            sessions(dir.path()).contains(&fresh),
            "within the grace period"
        );
    }

    #[test]
    fn the_size_limit_removes_the_oldest_first_and_stops_when_under() {
        let dir = tempfile::tempdir().unwrap();
        let names: Vec<String> = (0..4)
            .map(|i| {
                let n = session_in(dir.path(), 3, true);
                age(&dir.path().join(&n), (4 - i) * 3600); // 4h, 3h, 2h, 1h ago
                n
            })
            .collect();
        let size = |n: &String| std::fs::metadata(dir.path().join(n)).unwrap().len();
        // Room for the two newest and the new session's own file, not more.
        let budget = size(&names[2]) + size(&names[3]) + 2000;
        let r = Retention {
            keep_days: None,
            max_bytes: Some(budget),
        };
        let own = Session::open(dir.path(), &r).unwrap();
        let left = sessions(dir.path());
        assert!(
            !left.contains(&names[0]) && !left.contains(&names[1]),
            "{left:?}"
        );
        assert!(
            left.contains(&names[2]) && left.contains(&names[3]),
            "{left:?}"
        );
        assert!(left.contains(&own.name));
    }

    #[test]
    fn no_limit_means_nothing_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let old = session_in(dir.path(), 1, true);
        age(&dir.path().join(&old), 900 * DAY);
        let none = Retention {
            keep_days: None,
            max_bytes: None,
        };
        let _own = Session::open(dir.path(), &none).unwrap();
        assert!(sessions(dir.path()).contains(&old));
    }

    /// Starting costs the same however much history there is: it reads none.
    #[test]
    fn starting_a_server_reads_no_old_session() {
        let dir = tempfile::tempdir().unwrap();
        let junk = dir.path().join("session-1-1-0.jsonl");
        std::fs::write(&junk, "this is not a chain\n").unwrap();
        age(&junk, DAY); // a day old, within the limits: kept, and not read
        let _own = open(dir.path());
        assert!(junk.exists());
    }

    #[test]
    fn what_is_not_a_session_is_never_touched() {
        let dir = tempfile::tempdir().unwrap();
        for f in [
            "ledger.jsonl",
            "notes.txt",
            "session-x.txt",
            "session-1.jsonl.bak",
        ] {
            let p = dir.path().join(f);
            std::fs::write(&p, "mine").unwrap();
            age(&p, 900 * DAY);
        }
        let _own = open(dir.path());
        let r = prune(
            dir.path(),
            &Plan {
                keep: Some(0),
                ..Plan::default()
            },
        )
        .unwrap();
        assert_eq!(r.removed.len(), 0);
        for f in [
            "ledger.jsonl",
            "notes.txt",
            "session-x.txt",
            "session-1.jsonl.bak",
        ] {
            assert!(dir.path().join(f).exists(), "{f}");
        }
    }

    // ---- removing on request ----

    fn removed(p: &Pruned) -> Vec<String> {
        p.removed.iter().map(|r| r.session.clone()).collect()
    }

    #[test]
    fn cleanup_removes_the_oldest_and_a_dry_run_removes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let made: Vec<String> = (0..3u64)
            .map(|i| {
                let n = session_in(dir.path(), 1, true);
                age(&dir.path().join(&n), (3 - i) * 3600);
                n
            })
            .collect();
        let keep_one = Plan {
            keep: Some(1),
            dry_run: true,
            verify_first: true,
            ..Plan::default()
        };
        assert_eq!(removed(&prune(dir.path(), &keep_one).unwrap()), made[..2]);
        assert_eq!(sessions(dir.path()).len(), 3, "dry run");

        let go = Plan {
            dry_run: false,
            ..keep_one
        };
        assert_eq!(removed(&prune(dir.path(), &go).unwrap()), made[..2]);
        assert_eq!(sessions(dir.path()), [made[2].clone()]);
    }

    #[test]
    fn cleanup_leaves_a_running_session_and_one_that_does_not_verify() {
        let dir = tempfile::tempdir().unwrap();
        let running = open(dir.path());
        let tampered = session_in(dir.path(), 2, true);
        let path = dir.path().join(&tampered);
        let mut l = lines(&path);
        l[1] = l[1].replace("echo", "ech0");
        write(&path, &l);
        let old = session_in(dir.path(), 1, true);
        let plan = Plan {
            keep: Some(0),
            verify_first: true,
            ..Plan::default()
        };
        let p = prune(dir.path(), &plan).unwrap();
        assert_eq!(removed(&p), [old]);
        assert_eq!(p.unverified, std::slice::from_ref(&tampered));
        assert!(dir.path().join(&running.name).exists() && path.exists());
    }

    /// A plan with no filter would remove everything: it is refused, and
    /// nothing is touched.
    #[test]
    fn a_cleanup_with_no_filter_is_refused_and_removes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        session_in(dir.path(), 1, true);
        session_in(dir.path(), 1, true);
        assert!(prune(dir.path(), &Plan::default()).is_err());
        assert_eq!(sessions(dir.path()).len(), 2);
    }

    #[test]
    fn several_filters_all_have_to_hold() {
        let dir = tempfile::tempdir().unwrap();
        let old = session_in(dir.path(), 1, true);
        let newer = session_in(dir.path(), 1, true);
        age(&dir.path().join(&old), 10 * DAY);
        age(&dir.path().join(&newer), 3600);
        let by_age = Plan {
            older_than_days: Some(1),
            ..Plan::default()
        };
        assert_eq!(
            removed(&prune(dir.path(), &by_age).unwrap()),
            std::slice::from_ref(&old)
        );
        // Old enough *and* beyond the newest two: nothing is both.
        let both = Plan {
            older_than_days: Some(1),
            keep: Some(2),
            ..Plan::default()
        };
        assert!(prune(dir.path(), &both).unwrap().removed.is_empty());
    }
}

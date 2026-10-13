//! `--audit-log`: one line per run, each one chained to the one before it.
//!
//! A line is `{"seq", "prev", "event", "hash"}`, where `hash` is the SHA-256
//! of `seq`, `prev` (the previous line's hash) and the event's JSON, so
//! changing, removing or reordering any line breaks the chain from there on.
//! What it can't show: that lines were cut off the end, or the whole file
//! replaced by a new chain. The file is only as safe as where it lives; the
//! sandboxed commands can neither write nor read it (see `Config::build`),
//! but whoever runs the server can. Keep a copy of the last hash somewhere
//! else to close that gap.

use nanosandbox::audit::{AuditEvent, AuditSink};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;

/// The `prev` of the first line.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn digest(seq: u64, prev: &str, event: &str) -> String {
    let mut h = Sha256::new();
    h.update(format!("{seq}\n{prev}\n{event}"));
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// What a whole, unbroken log holds.
#[derive(Debug, PartialEq)]
pub struct Verified {
    pub records: u64,
    /// The last line's hash: [`GENESIS`] for an empty log.
    pub head: String,
}

/// Checks every line of the log at `path`, and says which one is wrong.
pub fn verify(path: &Path) -> Result<Verified, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut head = GENESIS.to_string();
    let mut records = 0;
    for (i, line) in text.split_inclusive('\n').enumerate() {
        let n = i + 1;
        let bad = |what: &str| format!("{}: line {n}: {what}", path.display());
        let Some(line) = line.strip_suffix('\n') else {
            return Err(bad(
                "incomplete (no newline): cut off, or written to while running",
            ));
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
        if hash != digest(seq, prev, &v["event"].to_string()) {
            return Err(bad("its content does not match its hash: it was changed"));
        }
        head = hash.to_string();
        records += 1;
    }
    Ok(Verified { records, head })
}

pub struct ChainedLog {
    state: Mutex<State>,
}

struct State {
    file: File,
    seq: u64,
    head: String,
}

impl ChainedLog {
    /// Opens the log, creating it (mode 0600) if it isn't there. Refuses a
    /// log that's broken, or that another server has open: two writers would
    /// each extend the chain and neither line would follow the other.
    pub fn open(path: &Path) -> Result<Self, String> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("--audit-log {}: {e}", path.display()))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(format!(
                "--audit-log {} is in use by another server",
                path.display()
            ));
        }
        let Verified { records, head } = verify(path)?;
        Ok(Self {
            state: Mutex::new(State {
                file,
                seq: records,
                head,
            }),
        })
    }
}

impl AuditSink for ChainedLog {
    fn record(&self, event: &AuditEvent) {
        let Ok(value) = serde_json::to_value(event) else {
            return;
        };
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let hash = digest(st.seq, &st.head, &value.to_string());
        let line = json!({"seq": st.seq, "prev": st.head, "event": value, "hash": hash});
        let written = writeln!(st.file, "{line}").and_then(|()| st.file.sync_data());
        match written {
            Ok(()) => {
                st.seq += 1;
                st.head = hash;
            }
            // The command has run already; what's lost is its line.
            Err(e) => eprintln!("nanosandbox-mcp: audit log: could not write: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosandbox::Sandbox;
    use std::sync::Arc;

    fn log_with(n: usize) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = Arc::new(ChainedLog::open(&path).unwrap());
        let sb = Sandbox::builder()
            .working_dir("/")
            .audit(log.clone())
            .build()
            .unwrap();
        for i in 0..n {
            sb.run("echo", &[&i.to_string()]).unwrap();
        }
        (dir, path)
    }

    #[test]
    fn a_log_of_runs_verifies_and_resumes() {
        let (_dir, path) = log_with(3);
        let v = verify(&path).unwrap();
        assert_eq!(v.records, 3);
        // Reopened (the first server is gone), it carries on from the head.
        let again = ChainedLog::open(&path).unwrap();
        assert_eq!(again.state.lock().unwrap().seq, 3);
        assert_eq!(again.state.lock().unwrap().head, v.head);
    }

    #[test]
    fn an_empty_log_is_valid_and_starts_at_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.jsonl");
        let _log = ChainedLog::open(&path).unwrap();
        assert_eq!(
            verify(&path).unwrap(),
            Verified {
                records: 0,
                head: GENESIS.into()
            }
        );
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
    fn changing_removing_or_reordering_a_line_is_found() {
        let (_dir, path) = log_with(4);
        let original = lines(&path);

        let mut changed = original.clone();
        changed[1] = changed[1].replace("\"1\"", "\"X\"");
        write(&path, &changed);
        let err = verify(&path).unwrap_err();
        assert!(err.contains("line 2") && err.contains("changed"), "{err}");

        let mut removed = original.clone();
        removed.remove(1);
        write(&path, &removed);
        let err = verify(&path).unwrap_err();
        assert!(err.contains("line 2") && err.contains("missing"), "{err}");

        let mut swapped = original.clone();
        swapped.swap(1, 2);
        write(&path, &swapped);
        assert!(verify(&path).is_err());

        // Cutting the end off leaves a chain that still verifies: that's
        // what keeping the head elsewhere is for.
        write(&path, &original[..2]);
        assert_eq!(verify(&path).unwrap().records, 2);
    }

    #[test]
    fn a_line_cut_short_is_refused() {
        let (_dir, path) = log_with(2);
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.pop();
        text.pop();
        std::fs::write(&path, text).unwrap();
        assert!(verify(&path).unwrap_err().contains("line 2"));
        assert!(ChainedLog::open(&path).is_err());
    }

    #[test]
    fn a_log_another_server_has_open_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.jsonl");
        let _first = ChainedLog::open(&path).unwrap();
        let err = ChainedLog::open(&path).err().unwrap();
        assert!(err.contains("in use by another server"), "{err}");
    }

    #[test]
    fn a_new_log_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.jsonl");
        let _log = ChainedLog::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
    }
}

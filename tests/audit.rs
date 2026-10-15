//! The events each run hands to the sink.
#![cfg_attr(
    not(unix),
    allow(dead_code, unused_imports, unused_variables, unused_mut)
)]

use nanosandbox::audit::{AuditEnd, AuditOutcome, AuditSink, AuditStart};
use nanosandbox::{Sandbox, SandboxError};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Recorder {
    starts: Mutex<Vec<AuditStart>>,
    ends: Mutex<Vec<AuditEnd>>,
    /// The order things happened in.
    order: Mutex<Vec<&'static str>>,
}

impl AuditSink for Recorder {
    fn begin(&self, start: &AuditStart) -> Result<(), String> {
        self.starts.lock().unwrap().push(start.clone());
        self.order.lock().unwrap().push("begin");
        Ok(())
    }
    fn end(&self, end: &AuditEnd) {
        self.ends.lock().unwrap().push(end.clone());
        self.order.lock().unwrap().push("end");
    }
}

/// Refuses every run.
struct Refuses;

impl AuditSink for Refuses {
    fn begin(&self, _: &AuditStart) -> Result<(), String> {
        Err("the log is full".into())
    }
    fn end(&self, _: &AuditEnd) {
        panic!("nothing ran, so there is nothing to end");
    }
}

struct PanicsAtBegin;

impl AuditSink for PanicsAtBegin {
    fn begin(&self, _: &AuditStart) -> Result<(), String> {
        panic!("a sink that fails");
    }
    fn end(&self, _: &AuditEnd) {}
}

struct PanicsAtEnd;

impl AuditSink for PanicsAtEnd {
    fn begin(&self, _: &AuditStart) -> Result<(), String> {
        Ok(())
    }
    fn end(&self, _: &AuditEnd) {
        panic!("a sink that fails");
    }
}

fn sandbox(sink: Arc<dyn AuditSink>) -> Sandbox {
    let builder = Sandbox::builder();
    // Without the one-time install, Windows only runs with the host's network.
    #[cfg(windows)]
    let builder = builder.host_network();
    builder
        .working_dir("/")
        .env("SECRET_TOKEN", "hunter2-hunter2")
        .audit(sink)
        .build()
        .unwrap()
}

#[test]
#[cfg(unix)]
fn a_run_has_a_start_before_it_and_an_end_after() {
    let rec = Arc::new(Recorder::default());
    let sb = sandbox(rec.clone());
    let out = sb
        .run("sh", &["-c", "echo out; echo err >&2; exit 3"])
        .unwrap();
    assert_eq!(out.exit_code, 3);

    assert_eq!(*rec.order.lock().unwrap(), ["begin", "end"]);
    let (starts, ends) = (rec.starts.lock().unwrap(), rec.ends.lock().unwrap());
    let (s, e) = (&starts[0], &ends[0]);
    assert_eq!(s.command, "sh");
    assert_eq!(s.args, ["-c", "echo out; echo err >&2; exit 3"]);
    assert_eq!(s.policy.network, "none");
    assert!(s.ts_ms > 1_700_000_000_000 && e.ts_ms >= s.ts_ms);
    assert_eq!((&s.sandbox_id, s.run), (&e.sandbox_id, e.run));
    assert_eq!(s.sandbox_id, sb.id());
    match &e.outcome {
        AuditOutcome::Completed {
            exit_code,
            stdout_bytes,
            stderr_bytes,
            timed_out,
            ..
        } => {
            assert_eq!(*exit_code, 3);
            assert_eq!((*stdout_bytes, *stderr_bytes), (4, 4));
            assert!(!timed_out);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn each_run_of_a_sandbox_has_its_own_number() {
    let rec = Arc::new(Recorder::default());
    let sb = sandbox(rec.clone());
    sb.run("echo", &["a"]).unwrap();
    sb.run("echo", &["b"]).unwrap();
    let runs: Vec<u64> = rec.starts.lock().unwrap().iter().map(|s| s.run).collect();
    assert_eq!(runs, [0, 1]);
}

/// The point of recording the start first: a run that can't be recorded
/// doesn't happen.
#[test]
#[cfg(unix)]
fn a_run_whose_start_cannot_be_recorded_does_not_run() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    // A root caller's sandbox runs as nobody, which has to be able to write it.
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o777)).unwrap();
    let proof = dir.join("ran");
    for sink in [
        Arc::new(Refuses) as Arc<dyn AuditSink>,
        Arc::new(PanicsAtBegin),
    ] {
        let sb = sandbox_writing_to(&dir, sink);
        let err = sb
            .run("sh", &["-c", &format!("echo yes > {}", proof.display())])
            .unwrap_err();
        assert!(matches!(err, SandboxError::Audit(_)), "{err:?}");
        assert!(err.to_string().contains("not running the command"), "{err}");
        assert!(!proof.exists(), "the command ran anyway");
    }
}

fn sandbox_writing_to(dir: &std::path::Path, sink: Arc<dyn AuditSink>) -> Sandbox {
    Sandbox::builder()
        .working_dir(dir)
        .writable(dir)
        .audit(sink)
        .build()
        .unwrap()
}

#[test]
#[cfg(unix)]
fn a_sink_that_panics_at_the_end_does_not_lose_the_result() {
    let sb = sandbox(Arc::new(PanicsAtEnd));
    let out = sb.run("echo", &["still here"]).unwrap();
    assert_eq!(out.stdout, "still here\n");
}

/// Nothing from the run, no value from the configuration, and no secret on
/// the command line is in it.
#[test]
#[cfg(unix)]
fn an_event_holds_no_input_output_environment_value_or_secret_argument() {
    let rec = Arc::new(Recorder::default());
    let sb = sandbox(rec.clone());
    let out = sb
        .run_with_input("cat", &[], Some(b"input-that-is-private"))
        .unwrap();
    assert_eq!(out.stdout, "input-that-is-private");
    sb.run(
        "sh",
        &[
            "-c",
            "echo hi; curl -H 'Authorization: Bearer abc-xyz-123' https://me:pw-777@h.test/",
        ],
    )
    .ok();
    sb.run("echo", &["--token=tok-456", "--password", "pw-888"])
        .ok();

    let json = serde_json::to_string(&*rec.starts.lock().unwrap()).unwrap();
    for secret in [
        "input-that-is-private",
        "hunter2",
        "abc-xyz-123",
        "pw-777",
        "tok-456",
        "pw-888",
    ] {
        assert!(!json.contains(secret), "{secret} is in {json}");
    }
    assert!(json.contains("SECRET_TOKEN"), "the name is: {json}");
    assert!(json.contains("<redacted>"), "{json}");
    assert_eq!(rec.starts.lock().unwrap()[0].stdin_bytes, 21);
}

#[test]
fn a_command_that_cannot_run_still_has_an_end() {
    let rec = Arc::new(Recorder::default());
    let sb = sandbox(rec.clone());
    assert!(sb.run("no-such-command-here", &[]).is_err());

    assert_eq!(*rec.order.lock().unwrap(), ["begin", "end"]);
    let ends = rec.ends.lock().unwrap();
    assert!(
        matches!(&ends[0].outcome, AuditOutcome::Failed { error } if error.contains("no-such-command-here")),
        "{:?}",
        ends[0].outcome
    );
}

#[test]
#[cfg(unix)]
fn the_same_event_always_serializes_to_the_same_text() {
    let rec = Arc::new(Recorder::default());
    let sb = sandbox(rec.clone());
    sb.run("echo", &["x"]).unwrap();
    let start = rec.starts.lock().unwrap()[0].clone();
    let once = serde_json::to_string(&serde_json::to_value(&start).unwrap()).unwrap();
    let twice = serde_json::to_string(&serde_json::to_value(&start).unwrap()).unwrap();
    assert_eq!(once, twice);
    assert!(!once.contains(".0"), "no floats in an event: {once}");
}

//! The audit event each run hands to the sink.

use nanosandbox::Sandbox;
use nanosandbox::audit::{AuditEvent, AuditOutcome, AuditSink};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Recorder(Mutex<Vec<AuditEvent>>);

impl AuditSink for Recorder {
    fn record(&self, event: &AuditEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

struct Panics;

impl AuditSink for Panics {
    fn record(&self, _: &AuditEvent) {
        panic!("a sink that fails");
    }
}

fn sandbox(sink: Arc<dyn AuditSink>) -> Sandbox {
    Sandbox::builder()
        .working_dir("/")
        .env("SECRET_TOKEN", "hunter2-hunter2")
        .audit(sink)
        .build()
        .unwrap()
}

#[test]
fn a_run_leaves_one_event_saying_what_ran_and_how_it_ended() {
    let rec = Arc::new(Recorder::default());
    let sb = sandbox(rec.clone());
    let out = sb
        .run("sh", &["-c", "echo out; echo err >&2; exit 3"])
        .unwrap();
    assert_eq!(out.exit_code, 3);

    let events = rec.0.lock().unwrap();
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.command, "sh");
    assert_eq!(e.args, ["-c", "echo out; echo err >&2; exit 3"]);
    assert_eq!(e.sandbox_id, sb.id());
    assert_eq!(e.policy.network, "none");
    assert!(e.ts_ms > 1_700_000_000_000);
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

/// Nothing from the run, and no value from the configuration, is in it.
#[test]
fn an_event_holds_no_input_output_or_environment_value() {
    let rec = Arc::new(Recorder::default());
    let sb = sandbox(rec.clone());
    let out = sb
        .run_with_input("cat", &[], Some(b"input-that-is-private"))
        .unwrap();
    assert_eq!(out.stdout, "input-that-is-private");

    let events = rec.0.lock().unwrap();
    let json = serde_json::to_string(&events[0]).unwrap();
    assert!(!json.contains("input-that-is-private"), "{json}");
    assert!(!json.contains("hunter2"), "{json}");
    assert!(json.contains("SECRET_TOKEN"), "the name is: {json}");
    assert_eq!(events[0].stdin_bytes, 21);
}

#[test]
fn a_command_that_cannot_run_is_an_event_too() {
    let rec = Arc::new(Recorder::default());
    let sb = sandbox(rec.clone());
    assert!(sb.run("no-such-command-here", &[]).is_err());

    let events = rec.0.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert!(
        matches!(&events[0].outcome, AuditOutcome::Failed { error } if error.contains("no-such-command-here")),
        "{:?}",
        events[0].outcome
    );
}

#[test]
fn a_sink_that_panics_does_not_lose_the_result() {
    let sb = sandbox(Arc::new(Panics));
    let out = sb.run("echo", &["still here"]).unwrap();
    assert_eq!(out.stdout, "still here\n");
}

#[test]
fn the_same_event_always_serializes_to_the_same_text() {
    let rec = Arc::new(Recorder::default());
    let sb = sandbox(rec.clone());
    sb.run("echo", &["x"]).unwrap();
    let events = rec.0.lock().unwrap();
    let once = serde_json::to_string(&serde_json::to_value(&events[0]).unwrap()).unwrap();
    let twice = serde_json::to_string(&serde_json::to_value(&events[0]).unwrap()).unwrap();
    assert_eq!(once, twice);
    assert!(!once.contains('.'), "no floats in an event: {once}");
}

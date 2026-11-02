//! Random and damaged JSON-RPC lines into `handle_line` and `execute_call`: no panic, every
//! response well-formed and addressed to the request's own id, a cancellation never outliving
//! the call it names. Seeded; `NANOSANDBOX_FUZZ_ITERS` sets the count.

use super::*;
use serde_json::{Map, Value, json};

struct Rng(u64);

impl Rng {
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
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

fn iterations(default: usize) -> usize {
    std::env::var("NANOSANDBOX_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

struct Quiet;

impl Runner for Quiet {
    fn run(
        &self,
        command: &str,
        args: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<RunOutput, String> {
        if command == "unrunnable" {
            return Err("no such thing".into());
        }
        Ok(RunOutput {
            stdout: format!("{command} {} {:?}", args.len(), stdin.map(<[u8]>::len)),
            ..RunOutput::default()
        })
    }
}

fn server() -> Server<Quiet> {
    Server::new(Quiet, "Network: off.".into(), 2, false)
}

const KEYS: [&str; 16] = [
    "jsonrpc",
    "id",
    "method",
    "params",
    "name",
    "arguments",
    "command",
    "args",
    "stdin",
    "_meta",
    "requestId",
    "protocolVersion",
    "io.modelcontextprotocol/protocolVersion",
    "io.modelcontextprotocol/clientCapabilities",
    "result",
    "error",
];
const METHODS: [&str; 10] = [
    "initialize",
    "ping",
    "tools/list",
    "tools/call",
    "server/discover",
    "notifications/cancelled",
    "notifications/initialized",
    "nope",
    "",
    "tools/call\u{0}",
];
const STRINGS: [&str; 12] = [
    "",
    "run_command",
    "true",
    "sh",
    "2026-07-28",
    "2025-03-26",
    "x",
    "unrunnable",
    "\u{0}",
    "é\u{301}",
    "\u{1f600}",
    "-c",
];

fn any_value(rng: &mut Rng, depth: usize) -> Value {
    match rng.below(if depth > 3 { 7 } else { 10 }) {
        0 => Value::Null,
        1 => Value::Bool(rng.chance(50)),
        2 => json!(*rng.pick(&[0i64, -1, 1, i64::MAX, i64::MIN, 1 << 53])),
        3 => json!(u64::MAX),
        4 => json!(*rng.pick(&[0.5f64, -0.0, 1e300, 1.5e-300])),
        5 | 6 => json!(*rng.pick(&STRINGS)),
        7 => Value::Array(
            (0..rng.below(4))
                .map(|_| any_value(rng, depth + 1))
                .collect(),
        ),
        _ => {
            let mut m = Map::new();
            for _ in 0..rng.below(5) {
                m.insert(rng.pick(&KEYS).to_string(), any_value(rng, depth + 1));
            }
            Value::Object(m)
        }
    }
}

/// A message that is mostly right, with parts swapped for anything.
fn message(rng: &mut Rng) -> Value {
    let mut m = Map::new();
    if rng.chance(90) {
        m.insert("jsonrpc".into(), json!("2.0"));
    }
    if rng.chance(85) {
        let id = match rng.below(4) {
            0 => json!(rng.below(5)),
            1 => json!(rng.pick(&STRINGS)),
            2 => json!(-(rng.below(5) as i64)),
            _ => any_value(rng, 2),
        };
        m.insert("id".into(), id);
    }
    m.insert(
        "method".into(),
        if rng.chance(90) {
            json!(rng.pick(&METHODS))
        } else {
            any_value(rng, 2)
        },
    );
    let params = if rng.chance(50) {
        let mut p = Map::new();
        if rng.chance(70) {
            p.insert("name".into(), json!("run_command"));
        }
        if rng.chance(60) {
            p.insert(
                "arguments".into(),
                if rng.chance(70) {
                    json!({"command": rng.pick(&STRINGS), "args": [rng.pick(&STRINGS)], "stdin": rng.pick(&STRINGS)})
                } else {
                    any_value(rng, 1)
                },
            );
        }
        if rng.chance(40) {
            p.insert(
                "_meta".into(),
                json!({
                    "io.modelcontextprotocol/protocolVersion": *rng.pick(&["2026-07-28", "1999"]),
                    "io.modelcontextprotocol/clientCapabilities": if rng.chance(80) { json!({}) } else { json!(1) }
                }),
            );
        }
        if rng.chance(30) {
            p.insert("requestId".into(), any_value(rng, 2));
        }
        Value::Object(p)
    } else {
        any_value(rng, 0)
    };
    if rng.chance(90) {
        m.insert("params".into(), params);
    }
    Value::Object(m)
}

fn damage(rng: &mut Rng, line: &str) -> String {
    let mut bytes = line.as_bytes().to_vec();
    for _ in 0..1 + rng.below(3) {
        if bytes.is_empty() {
            break;
        }
        let at = rng.below(bytes.len());
        match rng.below(5) {
            0 => bytes[at] ^= 1 << rng.below(8),
            1 => {
                bytes.remove(at);
            }
            2 => bytes.truncate(at),
            3 => bytes.insert(
                at,
                *rng.pick(&[b'"', b'\\', b'{', b'}', b'[', b']', 0, b',', b':']),
            ),
            _ => {
                let end = (at + rng.below(10)).min(bytes.len());
                let chunk = bytes[at..end].to_vec();
                bytes.splice(at..at, chunk);
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// A response is a JSON-RPC 2.0 object with the id it answers and a result or an error.
fn well_formed(response: &Value) -> Result<(), String> {
    let Some(o) = response.as_object() else {
        return Err("not an object".into());
    };
    if o.get("jsonrpc") != Some(&json!("2.0")) {
        return Err("no jsonrpc 2.0".into());
    }
    match (o.contains_key("result"), o.contains_key("error")) {
        (true, false) | (false, true) => {}
        _ => return Err("needs exactly one of result and error".into()),
    }
    match o.get("id") {
        Some(Value::Null | Value::String(_) | Value::Number(_)) => Ok(()),
        _ => Err("id missing or of a kind a request can't carry".into()),
    }
}

#[test]
fn test_any_line_gets_a_well_formed_answer_or_none() {
    let s = server();
    let mut rng = Rng(0xabad_1dea_0000_0001);
    let mut problems = Vec::new();
    for _ in 0..iterations(150_000) {
        let msg = message(&mut rng);
        let mut line = msg.to_string();
        if rng.chance(30) {
            line = damage(&mut rng, &line);
        }
        let action =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.handle_line(&line))) {
                Ok(a) => a,
                Err(_) => {
                    problems.push(format!("handle_line panicked on {line}"));
                    continue;
                }
            };
        let response = match action {
            Action::Nothing => continue,
            Action::Respond(v) => v,
            Action::Call(call) => {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    s.execute_call(call)
                })) {
                    Ok(Some(v)) => v,
                    Ok(None) => continue,
                    Err(_) => {
                        problems.push(format!("execute_call panicked on {line}"));
                        continue;
                    }
                }
            }
        };
        if let Err(why) = well_formed(&response) {
            problems.push(format!("{why}: {response} (to {line})"));
            continue;
        }
        // Addressed to the request's own id when that was a valid one.
        if let Ok(Value::Object(sent)) = serde_json::from_str::<Value>(&line)
            && let Some(id @ (Value::String(_) | Value::Number(_))) = sent.get("id")
            && sent.get("method").is_some_and(Value::is_string)
            && response["id"] != *id
        {
            problems.push(format!(
                "answered {} to a request with id {id}: {line}",
                response["id"]
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "{} problems, first:\n{}",
        problems.len(),
        problems[..problems.len().min(6)].join("\n")
    );
}

#[test]
fn test_hostile_shapes_get_a_parse_or_request_error() {
    let s = server();
    let deep_array = "[".repeat(1_000_000);
    let deep_object = r#"{"a":"#.repeat(200_000);
    let long_string = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}"}}"#,
        "m".repeat(5 << 20)
    );
    let many_keys: String = format!(
        "{{{}}}",
        (0..100_000)
            .map(|i| format!("\"k{i}\":{i}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    for (name, line) in [
        ("empty", String::new()),
        ("whitespace", "   \t ".into()),
        ("deep array", deep_array),
        ("deep object", deep_object),
        ("long method", long_string),
        ("many keys", many_keys),
        ("nul", "\u{0}".into()),
        (
            "batch",
            r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#.into(),
        ),
        (
            "lone surrogate escape",
            r#"{"jsonrpc":"2.0","id":1,"method":"\ud800"}"#.into(),
        ),
        (
            "duplicate keys",
            r#"{"id":1,"id":"2","method":"ping","method":"nope"}"#.into(),
        ),
        (
            "huge number",
            format!(r#"{{"id":{},"method":"ping"}}"#, "9".repeat(5000)),
        ),
        (
            "float id",
            r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#.into(),
        ),
    ] {
        let action =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.handle_line(&line)))
                .unwrap_or_else(|_| panic!("{name}: panicked"));
        if let Action::Respond(v) = action {
            well_formed(&v).unwrap_or_else(|why| panic!("{name}: {why}: {v}"));
        }
    }
}

#[test]
fn test_a_cancel_never_outlives_the_call_it_names() {
    let s = server();
    let call = |id: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"run_command","arguments":{{"command":"true"}}}}}}"#
        )
    };
    let cancel = |id: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":{id}}}}}"#
        )
    };
    let mut rng = Rng(77);
    for i in 0..iterations(5000) {
        let id = if rng.chance(50) {
            format!("{}", rng.below(4))
        } else {
            format!("\"{}\"", rng.below(4))
        };
        // Cancelled in flight: nothing is answered.
        let Action::Call(c) = s.handle_line(&call(&id)) else {
            panic!("not a call");
        };
        assert!(matches!(s.handle_line(&cancel(&id)), Action::Nothing));
        assert!(
            s.execute_call(c).is_none(),
            "round {i}: cancelled but answered ({id})"
        );
        // A cancel for something finished or never started is stale: the next call under the
        // same id still runs.
        assert!(matches!(s.handle_line(&cancel(&id)), Action::Nothing));
        let Action::Call(c) = s.handle_line(&call(&id)) else {
            panic!("not a call");
        };
        assert!(
            s.execute_call(c).is_some(),
            "round {i}: a stale cancel swallowed the next call ({id})"
        );
        // Number 1 and string "1" are different ids.
        let (num, text) = ("1", "\"1\"");
        let Action::Call(c) = s.handle_line(&call(num)) else {
            panic!("not a call");
        };
        let _ = s.handle_line(&cancel(text));
        assert!(
            s.execute_call(c).is_some(),
            "round {i}: cancelling \"1\" cancelled 1"
        );
    }
    assert!(
        s.in_flight.lock().unwrap().is_empty(),
        "calls left in flight"
    );
}

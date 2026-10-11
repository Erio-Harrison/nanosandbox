//! MCP over JSON-RPC, for a server whose only job is one tool.
//!
//! Serves both protocol eras on the same stream, as the spec allows: a
//! request carrying `_meta["io.modelcontextprotocol/protocolVersion"]` is
//! stateless and modern (2026-07-28 and later); anything else, `initialize`
//! included, gets the older handshake-era shapes (2025-11-25 and earlier).
//! No state is kept between requests either way.

use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::sync::{Condvar, Mutex};

pub const MODERN_VERSIONS: &[&str] = &["2026-07-28"];
pub const LEGACY_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

pub const TOOL_NAME: &str = "run_command";

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// What one `run_command` produced. Mirrors `nanosandbox::ExecutionResult`
/// without depending on it, so the protocol layer tests without a sandbox.
#[derive(Debug, Clone, Default)]
pub struct RunOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub out_of_memory: bool,
    pub cpu_limit_hit: bool,
    pub tmp_limit_hit: bool,
    pub output_truncated: bool,
    pub blocked_hosts: Vec<String>,
    pub failure_reason: Option<String>,
}

pub trait Runner: Send + Sync + 'static {
    /// `Err` only when the command could not be run at all.
    fn run(
        &self,
        command: &str,
        args: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<RunOutput, String>;
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Era {
    Modern,
    Legacy,
}

/// What the read loop should do with one line.
pub enum Action {
    Nothing,
    Respond(Value),
    /// A `tools/call`: slow, so run it off the read loop with `execute_call`.
    Call(Call),
}

pub struct Call {
    id: Value,
    era: Era,
    params: Value,
}

pub struct Server<R: Runner> {
    runner: R,
    /// Appended to the tool description: what the operator allowed, so the
    /// model isn't left guessing at its limits.
    summary: String,
    gate: Gate,
    cancelled: Mutex<HashSet<String>>,
    log_io: bool,
}

impl<R: Runner> Server<R> {
    pub fn new(runner: R, summary: String, max_concurrent: usize, log_io: bool) -> Self {
        Self {
            runner,
            summary,
            gate: Gate::new(max_concurrent.max(1)),
            cancelled: Mutex::new(HashSet::new()),
            log_io,
        }
    }

    pub fn handle_line(&self, line: &str) -> Action {
        let message: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return Action::Respond(error(Value::Null, PARSE_ERROR, "Parse error")),
        };
        let Value::Object(message) = message else {
            // Batches were dropped from the protocol after 2025-03-26.
            return Action::Respond(error(
                Value::Null,
                INVALID_REQUEST,
                "Expected a single JSON-RPC message object (batches are not supported)",
            ));
        };
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            // A response to something we sent: we never send requests.
            if message.contains_key("result") || message.contains_key("error") {
                return Action::Nothing;
            }
            return Action::Respond(error(Value::Null, INVALID_REQUEST, "Missing method"));
        };
        let params = message.get("params").cloned().unwrap_or(Value::Null);

        let id = match message.get("id") {
            None => {
                self.notification(method, &params);
                return Action::Nothing;
            }
            Some(id @ (Value::String(_) | Value::Number(_))) => id.clone(),
            Some(_) => {
                return Action::Respond(error(
                    Value::Null,
                    INVALID_REQUEST,
                    "Request id must be a string or a number",
                ));
            }
        };

        let era = if method != "initialize" && modern_meta(&params).is_some() {
            Era::Modern
        } else {
            Era::Legacy
        };
        if era == Era::Modern
            && let Err(e) = validate_modern(&id, &params)
        {
            return Action::Respond(e);
        }

        match method {
            "initialize" => Action::Respond(self.initialize(id, &params)),
            "ping" => Action::Respond(ok(id, json!({}), era)),
            "server/discover" => {
                if era == Era::Legacy {
                    return Action::Respond(error(
                        id,
                        INVALID_PARAMS,
                        "server/discover needs the per-request _meta fields",
                    ));
                }
                Action::Respond(ok(id, self.discover(), era))
            }
            "tools/list" => Action::Respond(ok(id, json!({ "tools": [self.tool()] }), era)),
            "tools/call" => Action::Call(Call { id, era, params }),
            _ => Action::Respond(error(
                id,
                METHOD_NOT_FOUND,
                &format!("Method not found: {method}"),
            )),
        }
    }

    fn notification(&self, method: &str, params: &Value) {
        if method == "notifications/cancelled"
            && let Some(request_id) = params.get("requestId")
        {
            self.cancelled
                .lock()
                .unwrap()
                .insert(request_id.to_string());
        }
    }

    fn initialize(&self, id: Value, params: &Value) -> Value {
        let requested = params.get("protocolVersion").and_then(Value::as_str);
        let version = match requested {
            Some(v) if LEGACY_VERSIONS.contains(&v) => v,
            _ => LEGACY_VERSIONS[0],
        };
        ok(
            id,
            json!({
                "protocolVersion": version,
                "capabilities": { "tools": {} },
                "serverInfo": server_info(),
                "instructions": instructions(),
            }),
            Era::Legacy,
        )
    }

    fn discover(&self) -> Value {
        json!({
            "supportedVersions": supported_versions(),
            "capabilities": { "tools": {} },
            "instructions": instructions(),
        })
    }

    fn tool(&self) -> Value {
        json!({
            "name": TOOL_NAME,
            "title": "Run a command in a sandbox",
            "description": format!(
                "Run one program in a sandbox and return its stdout, stderr and exit code. \
                 `args` is the argument vector: there is no shell, so for pipes, redirects or \
                 `&&` run `sh` with args [\"-c\", \"...\"]. Every call starts a fresh sandbox; \
                 only files in the workspace carry over. A command that fails still returns \
                 normally, with a non-zero exit_code. {}",
                self.summary
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Program to run, found on PATH or given as a path."
                    },
                    "args": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Arguments, one array element each."
                    },
                    "stdin": {
                        "type": "string",
                        "description": "Text to pipe to the program's standard input."
                    }
                },
                "required": ["command"],
                "additionalProperties": false
            }
        })
    }

    /// Runs a `tools/call`. `None` when the client cancelled it meanwhile:
    /// nothing may be sent for a cancelled request.
    pub fn execute_call(&self, call: Call) -> Option<Value> {
        let key = call.id.to_string();
        let _permit = self.gate.acquire();
        if self.take_cancelled(&key) {
            return None;
        }
        let response = self.call_tool(&call);
        if self.take_cancelled(&key) {
            return None;
        }
        Some(response)
    }

    fn take_cancelled(&self, key: &str) -> bool {
        self.cancelled.lock().unwrap().remove(key)
    }

    fn call_tool(&self, call: &Call) -> Value {
        let (id, era) = (call.id.clone(), call.era);
        match call.params.get("name").and_then(Value::as_str) {
            None => return error(id, INVALID_PARAMS, "Missing tool name"),
            Some(TOOL_NAME) => {}
            Some(other) => return error(id, INVALID_PARAMS, &format!("Unknown tool: {other}")),
        }
        let arguments = match call.params.get("arguments") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(m)) => m.clone(),
            Some(_) => return error(id, INVALID_PARAMS, "arguments must be an object"),
        };
        let parsed = match parse_arguments(&arguments) {
            Ok(p) => p,
            Err(message) => return ok(id, tool_error(&message), era),
        };
        let (command, args, stdin) = parsed;

        match self
            .runner
            .run(&command, &args, stdin.as_deref().map(str::as_bytes))
        {
            Ok(out) => {
                self.log(&command, &args, stdin.as_deref(), &out);
                ok(id, run_result(&out), era)
            }
            Err(message) => {
                self.log_failure(&command, &args, &message);
                ok(
                    id,
                    tool_error(&format!("Could not run the command: {message}")),
                    era,
                )
            }
        }
    }

    fn log(&self, command: &str, args: &[String], stdin: Option<&str>, out: &RunOutput) {
        let mut line = json!({
            "ts_ms": now_ms(),
            "command": command,
            "args": args,
            "exit_code": out.exit_code,
            "duration_ms": out.duration_ms,
            "timed_out": out.timed_out,
            "out_of_memory": out.out_of_memory,
            "cpu_limit_hit": out.cpu_limit_hit,
            "tmp_limit_hit": out.tmp_limit_hit,
            "blocked_hosts": out.blocked_hosts,
        });
        if self.log_io {
            line["stdin"] = json!(stdin);
            line["stdout"] = json!(out.stdout);
            line["stderr"] = json!(out.stderr);
        }
        eprintln!("{line}");
    }

    fn log_failure(&self, command: &str, args: &[String], message: &str) {
        eprintln!(
            "{}",
            json!({ "ts_ms": now_ms(), "command": command, "args": args, "error": message })
        );
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

type Parsed = (String, Vec<String>, Option<String>);

fn parse_arguments(arguments: &Map<String, Value>) -> Result<Parsed, String> {
    for key in arguments.keys() {
        if !["command", "args", "stdin"].contains(&key.as_str()) {
            return Err(format!(
                "Unknown argument `{key}`; run_command takes `command`, `args` and `stdin`"
            ));
        }
    }
    let command = match arguments.get("command") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err("`command` is required and must be a non-empty string".into()),
    };
    let args = match arguments.get("args") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or("`args` must be an array of strings")?,
        Some(_) => return Err("`args` must be an array of strings".into()),
    };
    let stdin = match arguments.get("stdin") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err("`stdin` must be a string".into()),
    };
    Ok((command, args, stdin))
}

fn run_result(out: &RunOutput) -> Value {
    let mut structured = json!({
        "stdout": out.stdout,
        "stderr": out.stderr,
        "exit_code": out.exit_code,
        "duration_ms": out.duration_ms,
        "timed_out": out.timed_out,
        "out_of_memory": out.out_of_memory,
        "cpu_limit_hit": out.cpu_limit_hit,
        "tmp_limit_hit": out.tmp_limit_hit,
        "output_truncated": out.output_truncated,
        "blocked_hosts": out.blocked_hosts,
    });
    if let Some(reason) = &out.failure_reason {
        structured["failure_reason"] = json!(reason);
    }
    json!({
        "content": [{ "type": "text", "text": structured.to_string() }],
        "structuredContent": structured,
        "isError": false,
    })
}

/// A call that could not run, reported where the model reads it.
fn tool_error(message: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}

fn server_info() -> Value {
    json!({ "name": "nanosandbox-mcp", "version": env!("CARGO_PKG_VERSION") })
}

fn instructions() -> &'static str {
    "Runs commands in a nanosandbox sandbox: files limited to a workspace, network off unless \
     the operator allowed it, with memory, CPU and time limits set by the operator."
}

fn supported_versions() -> Vec<&'static str> {
    MODERN_VERSIONS
        .iter()
        .chain(LEGACY_VERSIONS)
        .copied()
        .collect()
}

/// The `_meta` object, if it carries the modern per-request version.
fn modern_meta(params: &Value) -> Option<&Map<String, Value>> {
    let meta = params.get("_meta")?.as_object()?;
    meta.contains_key(META_VERSION).then_some(meta)
}

fn validate_modern(id: &Value, params: &Value) -> Result<(), Value> {
    let meta = modern_meta(params).expect("checked by the caller");
    let Some(version) = meta.get(META_VERSION).and_then(Value::as_str) else {
        return Err(error(
            id.clone(),
            INVALID_PARAMS,
            "protocolVersion in _meta must be a string",
        ));
    };
    if !meta.get(META_CAPABILITIES).is_some_and(Value::is_object) {
        return Err(error(
            id.clone(),
            INVALID_PARAMS,
            "clientCapabilities is required in _meta",
        ));
    }
    if !MODERN_VERSIONS.contains(&version) {
        return Err(error_with_data(
            id.clone(),
            UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version",
            json!({ "supported": supported_versions(), "requested": version }),
        ));
    }
    Ok(())
}

fn ok(id: Value, mut result: Value, era: Era) -> Value {
    if era == Era::Modern {
        result["resultType"] = json!("complete");
        result["_meta"] = json!({ META_SERVER_INFO: server_info() });
    }
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn error_with_data(id: Value, code: i64, message: &str, data: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message, "data": data }
    })
}

/// Caps how many sandboxes run at once; the rest wait their turn.
struct Gate {
    max: usize,
    running: Mutex<usize>,
    freed: Condvar,
}

struct Permit<'a>(&'a Gate);

impl Gate {
    fn new(max: usize) -> Self {
        Self {
            max,
            running: Mutex::new(0),
            freed: Condvar::new(),
        }
    }

    fn acquire(&self) -> Permit<'_> {
        let mut running = self.running.lock().unwrap();
        while *running >= self.max {
            running = self.freed.wait(running).unwrap();
        }
        *running += 1;
        Permit(self)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.running.lock().unwrap() -= 1;
        self.0.freed.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake;

    impl Runner for Fake {
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
                stdout: format!("{command} {args:?} {:?}", stdin.map(<[u8]>::len)),
                exit_code: if command == "fails" { 7 } else { 0 },
                failure_reason: (command == "fails").then(|| "Exit code 7".to_string()),
                ..RunOutput::default()
            })
        }
    }

    fn server() -> Server<Fake> {
        Server::new(Fake, "Network: off.".into(), 2, false)
    }

    const MODERN: &str = r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}"#;

    fn respond(s: &Server<Fake>, line: &str) -> Value {
        match s.handle_line(line) {
            Action::Respond(v) => v,
            _ => panic!("expected an immediate response to {line}"),
        }
    }

    fn call(s: &Server<Fake>, line: &str) -> Value {
        match s.handle_line(line) {
            Action::Call(c) => s.execute_call(c).expect("not cancelled"),
            _ => panic!("expected a tools/call"),
        }
    }

    #[test]
    fn legacy_initialize_echoes_a_known_version() {
        let r = respond(
            &server(),
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
        );
        assert_eq!(r["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(r["result"]["capabilities"], json!({"tools":{}}));
        assert_eq!(r["result"]["serverInfo"]["name"], "nanosandbox-mcp");
        assert!(r["result"].get("resultType").is_none(), "legacy shape");
    }

    #[test]
    fn legacy_initialize_offers_its_latest_for_an_unknown_version() {
        let r = respond(
            &server(),
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#,
        );
        assert_eq!(r["result"]["protocolVersion"], LEGACY_VERSIONS[0]);
    }

    #[test]
    fn modern_discover() {
        let r = respond(
            &server(),
            &format!(
                r#"{{"jsonrpc":"2.0","id":"x","method":"server/discover","params":{{{MODERN}}}}}"#
            ),
        );
        assert_eq!(r["id"], "x");
        assert_eq!(r["result"]["resultType"], "complete");
        assert_eq!(r["result"]["supportedVersions"][0], "2026-07-28");
        assert_eq!(r["result"]["capabilities"], json!({"tools":{}}));
        assert_eq!(
            r["result"]["_meta"][META_SERVER_INFO]["name"],
            "nanosandbox-mcp"
        );
    }

    #[test]
    fn modern_requests_must_carry_their_metadata() {
        let s = server();
        // Version without capabilities.
        let r = respond(
            &s,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#,
        );
        assert_eq!(r["error"]["code"], INVALID_PARAMS);
        // Version of the wrong type.
        let r = respond(
            &s,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":5,"io.modelcontextprotocol/clientCapabilities":{}}}}"#,
        );
        assert_eq!(r["error"]["code"], INVALID_PARAMS);
        // discover is modern-only.
        let r = respond(&s, r#"{"jsonrpc":"2.0","id":1,"method":"server/discover"}"#);
        assert_eq!(r["error"]["code"], INVALID_PARAMS);
    }

    #[test]
    fn unsupported_modern_version_lists_what_is_supported() {
        let r = respond(
            &server(),
            r#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
        );
        assert_eq!(r["error"]["code"], -32022);
        assert_eq!(r["error"]["data"]["requested"], "2099-01-01");
        let supported = r["error"]["data"]["supported"].as_array().unwrap();
        assert!(supported.contains(&json!("2026-07-28")));
        assert!(supported.contains(&json!("2025-11-25")));
    }

    /// The tool takes no parameter that widens what the sandbox may do.
    #[test]
    fn the_tool_schema_exposes_only_what_to_run() {
        let r = respond(
            &server(),
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        );
        let tool = &r["result"]["tools"][0];
        assert_eq!(tool["name"], TOOL_NAME);
        assert_eq!(r["result"]["tools"].as_array().unwrap().len(), 1);
        let schema = &tool["inputSchema"];
        let mut props: Vec<_> = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        props.sort();
        assert_eq!(props, ["args", "command", "stdin"]);
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["required"], json!(["command"]));
        assert!(
            tool["description"]
                .as_str()
                .unwrap()
                .contains("Network: off.")
        );
    }

    #[test]
    fn a_call_returns_text_and_structured_content() {
        let r = call(
            &server(),
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"echo","args":["a","b"],"stdin":"xyz"}}}"#,
        );
        let res = &r["result"];
        assert_eq!(res["isError"], false);
        assert_eq!(
            res["structuredContent"]["stdout"],
            r#"echo ["a", "b"] Some(3)"#
        );
        let text: Value =
            serde_json::from_str(res["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text, res["structuredContent"]);
        assert!(res.get("resultType").is_none(), "legacy shape");
    }

    #[test]
    fn modern_results_say_they_are_complete() {
        let r = call(
            &server(),
            &format!(
                r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"run_command","arguments":{{"command":"echo"}},{MODERN}}}}}"#
            ),
        );
        assert_eq!(r["result"]["resultType"], "complete");
        assert_eq!(r["result"]["isError"], false);
    }

    #[test]
    fn a_failing_command_is_a_normal_result() {
        let r = call(
            &server(),
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"fails"}}}"#,
        );
        assert_eq!(r["result"]["isError"], false);
        assert_eq!(r["result"]["structuredContent"]["exit_code"], 7);
        assert_eq!(
            r["result"]["structuredContent"]["failure_reason"],
            "Exit code 7"
        );
    }

    #[test]
    fn a_command_that_cannot_run_is_a_tool_error() {
        let r = call(
            &server(),
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"unrunnable"}}}"#,
        );
        assert_eq!(r["result"]["isError"], true);
        assert!(
            r["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("no such thing")
        );
    }

    #[test]
    fn bad_arguments_are_tool_errors_the_model_can_fix() {
        for arguments in [
            r#"{}"#,
            r#"{"command":""}"#,
            r#"{"command":5}"#,
            r#"{"command":"x","args":"notalist"}"#,
            r#"{"command":"x","args":[1]}"#,
            r#"{"command":"x","stdin":3}"#,
            r#"{"command":"x","writable":"/"}"#,
            r#"{"command":"x","network":"*"}"#,
        ] {
            let r = call(
                &server(),
                &format!(
                    r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"run_command","arguments":{arguments}}}}}"#
                ),
            );
            assert_eq!(r["result"]["isError"], true, "{arguments}");
        }
    }

    #[test]
    fn unknown_tool_and_method() {
        let s = server();
        let r = call(
            &s,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nope"}}"#,
        );
        assert_eq!(r["error"]["code"], INVALID_PARAMS);
        let r = respond(&s, r#"{"jsonrpc":"2.0","id":3,"method":"resources/list"}"#);
        assert_eq!(r["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn malformed_input() {
        let s = server();
        assert_eq!(respond(&s, "{not json")["error"]["code"], PARSE_ERROR);
        assert_eq!(respond(&s, "[]")["error"]["code"], INVALID_REQUEST);
        assert_eq!(respond(&s, r#"{"id":1}"#)["error"]["code"], INVALID_REQUEST);
        let r = respond(&s, r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#);
        assert_eq!(r["error"]["code"], INVALID_REQUEST);
        assert_eq!(r["id"], Value::Null);
    }

    #[test]
    fn notifications_and_stray_responses_get_no_reply() {
        let s = server();
        for line in [
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","method":"anything/else"}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        ] {
            assert!(matches!(s.handle_line(line), Action::Nothing), "{line}");
        }
    }

    #[test]
    fn a_cancelled_call_sends_nothing() {
        let s = server();
        let Action::Call(c) = s.handle_line(
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"x"}}}"#,
        ) else {
            panic!()
        };
        s.handle_line(
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}"#,
        );
        assert!(s.execute_call(c).is_none());
        // The mark is spent: the same id can be used again.
        let r = call(
            &s,
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"x"}}}"#,
        );
        assert_eq!(r["result"]["isError"], false);
    }

    #[test]
    fn the_gate_caps_concurrency() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let gate = Arc::new(Gate::new(2));
        let (now, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (gate, now, peak) = (gate.clone(), now.clone(), peak.clone());
                std::thread::spawn(move || {
                    let _p = gate.acquire();
                    let n = now.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(n, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    now.fetch_sub(1, Ordering::SeqCst);
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    }
}

//! The real binary, spoken to the way an MCP client does: JSON-RPC lines
//! over stdin/stdout.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

struct Client {
    child: Child,
    lines: Receiver<String>,
}

impl Client {
    fn start(args: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_nanosandbox-mcp"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self { child, lines }
    }

    fn in_workspace(workspace: &std::path::Path, extra: &[&str]) -> Self {
        let mut args = vec!["--workspace", workspace.to_str().unwrap()];
        args.extend_from_slice(extra);
        Self::start(&args)
    }

    fn send(&mut self, message: Value) {
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    fn recv(&self) -> Value {
        match self.lines.recv_timeout(Duration::from_secs(20)) {
            Ok(line) => serde_json::from_str(&line).unwrap_or_else(|_| panic!("not JSON: {line}")),
            Err(RecvTimeoutError::Timeout) => panic!("no reply within 20s"),
            Err(RecvTimeoutError::Disconnected) => panic!("server closed its output"),
        }
    }

    fn request(&mut self, id: i64, method: &str, params: Value) -> Value {
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        self.recv()
    }

    fn run(&mut self, id: i64, command: &str, args: &[&str]) -> Value {
        let r = self.request(
            id,
            "tools/call",
            json!({"name":"run_command","arguments":{"command":command,"args":args}}),
        );
        r["result"]["structuredContent"].clone()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Inside the target directory, which every platform's sandbox can see
/// (unlike `/tmp`, which is private to each run).
fn workspace() -> tempfile::TempDir {
    tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
}

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

#[test]
fn legacy_client_handshake_then_a_command() {
    let ws = workspace();
    let mut c = Client::in_workspace(ws.path(), &[]);
    let r = c.request(
        1,
        "initialize",
        json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}),
    );
    assert_eq!(r["result"]["protocolVersion"], "2025-06-18");
    c.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));

    let out = c.run(2, "echo", &["hello"]);
    assert_eq!(out["stdout"], "hello\n");
    assert_eq!(out["exit_code"], 0);
    assert_eq!(out["timed_out"], false);
}

#[test]
fn modern_client_discovers_then_runs_a_command() {
    let ws = workspace();
    let mut c = Client::in_workspace(ws.path(), &[]);
    let r = c.request(1, "server/discover", json!({"_meta": modern_meta()}));
    assert_eq!(r["result"]["resultType"], "complete");
    assert_eq!(r["result"]["supportedVersions"][0], "2026-07-28");

    let r = c.request(
        2,
        "tools/call",
        json!({"name":"run_command","arguments":{"command":"sh","args":["-c","echo out; echo err >&2; exit 3"]},"_meta":modern_meta()}),
    );
    assert_eq!(r["result"]["resultType"], "complete");
    assert_eq!(r["result"]["isError"], false);
    let out = &r["result"]["structuredContent"];
    assert_eq!(out["stdout"], "out\n");
    assert_eq!(out["stderr"], "err\n");
    assert_eq!(out["exit_code"], 3);
    assert_eq!(out["failure_reason"], "Exit code 3");
}

#[test]
fn stdin_reaches_the_program() {
    let ws = workspace();
    let mut c = Client::in_workspace(ws.path(), &[]);
    let r = c.request(
        1,
        "tools/call",
        json!({"name":"run_command","arguments":{"command":"cat","stdin":"piped"}}),
    );
    assert_eq!(r["result"]["structuredContent"]["stdout"], "piped");
}

#[test]
fn the_time_limit_is_the_operators_not_the_models() {
    let ws = workspace();
    let mut c = Client::in_workspace(ws.path(), &["--timeout", "1"]);
    let start = Instant::now();
    let out = c.run(1, "sleep", &["30"]);
    assert_eq!(out["timed_out"], true);
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );

    // The model can't ask for more: an extra argument is refused.
    let r = c.request(
        2,
        "tools/call",
        json!({"name":"run_command","arguments":{"command":"sleep","args":["30"],"timeout":600}}),
    );
    assert_eq!(r["result"]["isError"], true);
}

#[test]
fn writes_stay_in_the_workspace() {
    let ws = workspace();
    let outside = workspace();
    let mut c = Client::in_workspace(ws.path(), &["--no-hide-home"]);

    let out = c.run(1, "sh", &["-c", "echo ok > inside.txt"]);
    assert_eq!(out["exit_code"], 0, "{out}");
    assert_eq!(
        std::fs::read_to_string(ws.path().join("inside.txt")).unwrap(),
        "ok\n"
    );

    let target = outside.path().join("outside.txt");
    let script = format!("echo no > '{}'", target.display());
    let out = c.run(2, "sh", &["-c", &script]);
    assert_ne!(out["exit_code"], 0, "{out}");
    assert!(!target.exists(), "a command wrote outside the workspace");
}

#[test]
fn the_network_is_off_unless_the_operator_allowed_it() {
    let ws = workspace();
    let mut c = Client::in_workspace(ws.path(), &[]);
    let r = c.request(1, "tools/list", json!({}));
    let description = r["result"]["tools"][0]["description"].as_str().unwrap();
    assert!(description.contains("Network: off"), "{description}");

    let args = [
        "--workspace",
        ws.path().to_str().unwrap(),
        "--allow-network",
        "example.com,*.example.org",
    ];
    // Where AppArmor denies the network namespace a filtered network needs,
    // the server says so at startup instead of running without the filter.
    let (code, stderr) = refused_with_stdin_closed(&args);
    if code == Some(2) && stderr.contains("AppArmor") {
        eprintln!("skipping the allowlist half: {stderr}");
        return;
    }
    let mut c = Client::start(&args);
    let r = c.request(1, "tools/list", json!({}));
    let description = r["result"]["tools"][0]["description"].as_str().unwrap();
    assert!(
        description.contains("only example.com, *.example.org"),
        "{description}"
    );
}

#[test]
fn commands_run_in_parallel_up_to_the_limit() {
    let ws = workspace();
    let mut c = Client::in_workspace(ws.path(), &["--max-concurrent", "4"]);
    let start = Instant::now();
    for id in 1..=3 {
        c.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
            "params":{"name":"run_command","arguments":{"command":"sleep","args":["1"]}}}));
    }
    let mut seen = Vec::new();
    for _ in 0..3 {
        let r = c.recv();
        assert_eq!(r["result"]["structuredContent"]["exit_code"], 0, "{r}");
        seen.push(r["id"].as_i64().unwrap());
    }
    seen.sort();
    assert_eq!(seen, [1, 2, 3]);
    assert!(
        start.elapsed() < Duration::from_millis(2500),
        "ran one after another: {:?}",
        start.elapsed()
    );
}

#[test]
fn a_slow_command_does_not_block_other_requests() {
    let ws = workspace();
    let mut c = Client::in_workspace(ws.path(), &[]);
    c.send(json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"run_command","arguments":{"command":"sleep","args":["2"]}}}));
    let start = Instant::now();
    let r = c.request(2, "ping", json!({}));
    assert_eq!(r["id"], 2);
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "ping waited on the command"
    );
    assert_eq!(c.recv()["id"], 1);
}

#[test]
fn it_exits_when_stdin_closes() {
    let ws = workspace();
    let mut c = Client::in_workspace(ws.path(), &[]);
    c.send(json!({"jsonrpc":"2.0","id":1,"method":"ping"}));
    c.recv();
    drop(c.child.stdin.take());
    let start = Instant::now();
    let status = c.child.wait().unwrap();
    assert!(status.success());
    assert!(start.elapsed() < Duration::from_secs(5));
}

fn refused(args: &[&str]) -> (Option<i32>, String) {
    refused_with_stdin_closed(args)
}

/// Starts the server with nothing on stdin: it either refuses at once (exit
/// 2, with the reason) or sees end-of-input and exits 0.
fn refused_with_stdin_closed(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_nanosandbox-mcp"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn it_refuses_to_start_without_a_workspace() {
    let (code, stderr) = refused(&[]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("--workspace"), "{stderr}");

    let (code, stderr) = refused(&["--workspace", "/definitely/not/a/dir"]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("not a directory"), "{stderr}");
}

#[cfg(target_os = "macos")]
#[test]
fn it_refuses_a_limit_this_platform_cannot_enforce() {
    let ws = workspace();
    let (code, stderr) = refused(&[
        "--workspace",
        ws.path().to_str().unwrap(),
        "--max-pids",
        "5",
    ]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("max_pids"), "{stderr}");
}

#[cfg(target_os = "macos")]
#[test]
fn strict_tmp_leaves_only_the_private_temp_directory_writable() {
    let ws = workspace();
    let probe = format!("/tmp/nsb-mcp-strict-{}", std::process::id());

    let mut c = Client::in_workspace(ws.path(), &["--strict-tmp"]);
    let r = c.request(1, "tools/list", json!({}));
    let description = r["result"]["tools"][0]["description"].as_str().unwrap();
    assert!(description.contains("/tmp is read-only"), "{description}");

    let script =
        format!("echo hi > {probe}; echo \"tmp:$?\"; echo hi > \"$TMPDIR/p\"; echo \"private:$?\"");
    let out = c.run(2, "sh", &["-c", &script]);
    let leaked = std::path::Path::new(&probe).exists();
    let _ = std::fs::remove_file(&probe);
    assert!(!leaked, "a command wrote the host's /tmp");
    let stdout = out["stdout"].as_str().unwrap();
    assert!(
        stdout.contains("tmp:1") && stdout.contains("private:0"),
        "{stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn without_strict_tmp_the_host_tmp_is_writable() {
    let ws = workspace();
    let probe = format!("/tmp/nsb-mcp-default-{}", std::process::id());
    let mut c = Client::in_workspace(ws.path(), &[]);
    let out = c.run(1, "sh", &["-c", &format!("echo hi > {probe}")]);
    let there = std::path::Path::new(&probe).exists();
    let _ = std::fs::remove_file(&probe);
    assert_eq!(out["exit_code"], 0, "{out}");
    assert!(there);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn it_refuses_strict_tmp_off_macos() {
    let ws = workspace();
    let (code, stderr) = refused(&["--workspace", ws.path().to_str().unwrap(), "--strict-tmp"]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("macOS only"), "{stderr}");
}

#[test]
fn help_and_version() {
    let out = Command::new(env!("CARGO_BIN_EXE_nanosandbox-mcp"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("--workspace"));
    let out = Command::new(env!("CARGO_BIN_EXE_nanosandbox-mcp"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("nanosandbox-mcp "));
}

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
        let mut command = Command::new(env!("CARGO_BIN_EXE_nanosandbox-mcp"));
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        Self::spawn(command)
    }

    fn spawn(mut command: Command) -> Self {
        let mut child = command.spawn().unwrap();
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

/// A directory holding one executable, `nsb-hello`, that prints its name.
fn tool_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = workspace();
    let tool = dir.path().join("nsb-hello");
    std::fs::write(&tool, "#!/bin/sh\necho hello from nsb-hello\n").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

fn client_with_path(ws: &std::path::Path, path: &str, extra: &[&str]) -> Client {
    let mut args = vec!["--workspace", ws.to_str().unwrap(), "--no-hide-home"];
    args.extend_from_slice(extra);
    let mut c = Command::new(env!("CARGO_BIN_EXE_nanosandbox-mcp"));
    c.args(&args)
        .env("PATH", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    Client::spawn(c)
}

#[test]
fn commands_find_what_the_servers_own_path_finds() {
    let ws = workspace();
    let tools = tool_dir();
    let path = format!("{}:/usr/bin:/bin", tools.path().display());

    let mut c = client_with_path(ws.path(), &path, &[]);
    let out = c.run(1, "nsb-hello", &[]);
    assert_eq!(out["stdout"], "hello from nsb-hello\n", "{out}");

    // An explicit PATH for the commands wins over the server's own.
    let mut c = client_with_path(ws.path(), &path, &["--env", "PATH=/usr/bin:/bin"]);
    let r = c.request(
        2,
        "tools/call",
        json!({"name":"run_command","arguments":{"command":"nsb-hello"}}),
    );
    assert_eq!(r["result"]["isError"], true, "{r}");
}

#[test]
fn one_noisy_command_cannot_flood_the_model() {
    let ws = workspace();
    let mut c = Client::in_workspace(ws.path(), &[]);
    let out = c.run(1, "sh", &["-c", "yes x | head -c 5000000"]);
    assert_eq!(out["output_truncated"], true, "{}", out["exit_code"]);
    assert!(out["stdout"].as_str().unwrap().len() <= 1 << 20);

    // Raised on request.
    let mut c = Client::in_workspace(ws.path(), &["--max-output", "8M"]);
    let out = c.run(1, "sh", &["-c", "yes x | head -c 5000000"]);
    assert_eq!(out["output_truncated"], false);
    assert_eq!(out["stdout"].as_str().unwrap().len(), 5_000_000);
}

#[test]
fn downloads_are_cached_in_the_workspace_and_kept_out_of_git() {
    let ws = workspace();
    let git_here = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(ws.path())
            .output()
            .ok()
            .filter(|o| o.status.success())
    };
    let has_git = git_here(&["init", "-q"]).is_some();

    let mut c = Client::in_workspace(ws.path(), &[]);
    let out = c.run(
        1,
        "sh",
        &[
            "-c",
            "echo \"$npm_config_cache\"; echo \"$PIP_CACHE_DIR\"; echo \"$XDG_CACHE_HOME\"; \
             echo cached > \"$npm_config_cache/entry\"; echo \"$HOME\"",
        ],
    );
    assert_eq!(out["exit_code"], 0, "{out}");
    let lines: Vec<&str> = out["stdout"].as_str().unwrap().lines().collect();
    let cache = ws.path().canonicalize().unwrap().join(".nanosandbox-cache");
    assert_eq!(lines[0], cache.join("npm").to_str().unwrap());
    assert_eq!(lines[1], cache.join("pip").to_str().unwrap());
    assert_eq!(lines[2], cache.join("xdg").to_str().unwrap());
    // HOME is still the run's own, not the cache: configuration and
    // credentials don't outlive the call.
    assert!(!lines[3].starts_with(cache.to_str().unwrap()), "{lines:?}");

    // What was cached is there for the next call.
    let again = c.run(2, "sh", &["-c", "cat \"$npm_config_cache/entry\""]);
    assert_eq!(again["stdout"], "cached\n", "{again}");

    // The directory ignores itself, so it isn't in `git status`.
    assert_eq!(
        std::fs::read_to_string(cache.join(".gitignore")).unwrap(),
        "# Created by nanosandbox-mcp.\n*\n"
    );
    if has_git {
        let status = git_here(&["status", "--porcelain"]).unwrap().stdout;
        assert_eq!(
            String::from_utf8_lossy(&status),
            "",
            "the cache shows in git"
        );
    }
}

#[test]
fn no_cache_leaves_the_workspace_alone() {
    let ws = workspace();
    let mut c = Client::in_workspace(ws.path(), &["--no-cache"]);
    let out = c.run(
        1,
        "sh",
        &[
            "-c",
            "echo \"[${npm_config_cache-unset}|${PIP_CACHE_DIR-unset}]\"",
        ],
    );
    assert_eq!(out["stdout"], "[unset|unset]\n", "{out}");
    assert!(!ws.path().join(".nanosandbox-cache").exists());
}

#[test]
fn a_cache_variable_the_operator_sets_wins() {
    let ws = workspace();
    let mut c = Client::in_workspace(ws.path(), &["--env", "PIP_CACHE_DIR=/somewhere/else"]);
    let out = c.run(
        1,
        "sh",
        &["-c", "echo \"$PIP_CACHE_DIR\"; echo \"$npm_config_cache\""],
    );
    let lines: Vec<&str> = out["stdout"].as_str().unwrap().lines().collect();
    assert_eq!(lines[0], "/somewhere/else");
    assert!(lines[1].ends_with(".nanosandbox-cache/npm"), "{lines:?}");
}

/// The reason the cache isn't in HOME: HOME is the run's private temp
/// directory, capped at 256 MB, and a large package is bigger than that.
#[test]
fn a_download_bigger_than_the_private_temp_directory_fits_in_the_cache() {
    let ws = workspace();
    let mut c = Client::in_workspace(ws.path(), &[]);
    let script = "dd if=/dev/zero bs=1048576 count=300 2>/dev/null > \"$npm_config_cache/big\" \
                  && wc -c < \"$npm_config_cache/big\" && rm \"$npm_config_cache/big\"";
    let out = c.run(1, "sh", &["-c", script]);
    assert_eq!(out["exit_code"], 0, "{out}");
    assert_eq!(out["tmp_limit_hit"], false, "{out}");
    assert_eq!(out["stdout"].as_str().unwrap().trim(), "314572800", "{out}");
}

/// Several servers on one machine, as when a person has more than one agent
/// open. A server that dies mid-run leaves its private temp directory behind;
/// the next one to run a command sweeps it. It must not touch a live
/// server's, however old that looks.
#[test]
fn a_dead_servers_leftover_directory_is_swept_and_a_live_ones_is_not() {
    let temp = std::env::temp_dir();
    let dir_of = |c: &Client| temp.join(format!("nanosandbox-tmp-{}-0", c.child.id()));
    let wait_for = |what: &str, cond: &dyn Fn() -> bool| {
        for _ in 0..200 {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        eprintln!("gave up waiting for: {what}");
        false
    };
    let age = |dir: &std::path::Path| {
        std::fs::File::open(dir)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
    };
    let start_running = |ws: &std::path::Path| {
        let mut c = Client::in_workspace(ws, &[]);
        c.send(json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"run_command","arguments":{"command":"sleep","args":["60"]}}}));
        c
    };

    let ws = workspace();
    let live = start_running(ws.path());
    let mut dead = start_running(ws.path());
    if !wait_for("the live server's directory", &|| dir_of(&live).exists()) {
        // Where the private temp directory is a tmpfs mount, there's no
        // directory on the host to leak or to sweep.
        eprintln!("skipping: this host mounts a tmpfs instead of making a directory");
        return;
    }
    assert!(wait_for("the second server's directory", &|| dir_of(&dead).exists()));

    // One dies with no chance to clean up. Both directories look abandoned
    // by their age; only one actually is.
    let dead_dir = dir_of(&dead);
    dead.child.kill().unwrap();
    dead.child.wait().unwrap();
    age(&dead_dir);
    age(&dir_of(&live));

    // A new server runs a command, which sweeps.
    let mut fresh = Client::in_workspace(ws.path(), &[]);
    assert_eq!(fresh.run(1, "echo", &["hi"])["exit_code"], 0);

    assert!(
        wait_for("the dead server's directory to be swept", &|| !dead_dir
            .exists()),
        "the leftover directory of a killed server was not removed"
    );
    assert!(
        dir_of(&live).exists(),
        "SAFETY: a live server's directory was removed from under it"
    );
}

#[test]
fn commands_get_a_home_they_can_write() {
    let ws = workspace();
    let mut c = Client::in_workspace(ws.path(), &[]);
    let out = c.run(
        1,
        "sh",
        &["-c", "cd && echo ok > .npmrc-probe && echo $HOME"],
    );
    assert_eq!(out["exit_code"], 0, "{out}");
    assert!(!out["stdout"].as_str().unwrap().trim().is_empty());
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

/// `--clean-tmp` removes what nothing holds, in whatever TMPDIR it's given,
/// and leaves what a live process holds.
#[test]
fn clean_tmp_removes_unheld_directories_and_keeps_held_ones() {
    use std::os::fd::AsRawFd;
    let root = tempfile::tempdir().unwrap();
    let age = |p: &std::path::Path| {
        let old = std::time::SystemTime::now() - Duration::from_secs(3600);
        std::fs::File::open(p).unwrap().set_modified(old).unwrap();
    };
    let dead = root.path().join("nanosandbox-tmp-1-0");
    let live = root.path().join("nanosandbox-tmp-1-1");
    let other = root.path().join("not-ours");
    for d in [&dead, &live, &other] {
        std::fs::create_dir(d).unwrap();
        age(d);
    }
    let held = std::fs::File::open(&live).unwrap();
    assert_eq!(
        unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let out = Command::new(env!("CARGO_BIN_EXE_nanosandbox-mcp"))
        .arg("--clean-tmp")
        .env("TMPDIR", root.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(!dead.exists(), "an unheld directory should be removed");
    assert!(live.exists(), "SAFETY: a held directory was removed");
    assert!(other.exists(), "a directory not ours was removed");
    drop(held);
}

/// The first command of a fresh server was once killed about one time in
/// five (a libc call made while the run started); it only shows over many
/// starts.
#[test]
fn the_first_command_of_a_fresh_server_is_not_killed() {
    let ws = workspace();
    for i in 0..25 {
        let mut c = Client::in_workspace(ws.path(), &[]);
        let out = c.run(1, "echo", &["hi"]);
        assert_eq!(out["exit_code"], 0, "start {i}: {out}");
    }
}

/// A command must not be able to delete its own run marker, which is how a
/// process that left the group (setsid, double fork) would outlive the call.
#[cfg(target_os = "macos")]
#[test]
fn a_command_cannot_strip_its_markers_to_leave_a_daemon_behind() {
    let ws = workspace();
    let mut c = Client::in_workspace(ws.path(), &[]);
    let script = r#"rm -f "$(dirname "$TMPDIR")"/nanosandbox-run-*-out 2>/dev/null
python3 -c '
import os, time
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        os.execvp("sleep", ["sleep", "31987"])
    os._exit(0)
time.sleep(0.5)'"#;
    let out = c.run(1, "sh", &["-c", script]);
    assert_eq!(out["exit_code"], 0, "{out}");
    std::thread::sleep(Duration::from_millis(500));
    let left = Command::new("pgrep")
        .args(["-f", "[s]leep 31987"])
        .output()
        .unwrap();
    let _ = Command::new("pkill").args(["-f", "[s]leep 31987"]).status();
    assert!(
        left.stdout.is_empty(),
        "a daemon outlived the call: {}",
        String::from_utf8_lossy(&left.stdout)
    );
}

/// `--read-only` on a path inside the workspace makes it read-only again:
/// the file can't be changed, replaced or moved off (nor its directory),
/// while the rest of the workspace is still writable. On Linux this needs
/// mounting, which the default AppArmor restriction denies.
#[cfg(target_os = "macos")]
#[test]
fn a_read_only_path_inside_the_workspace_stays_read_only() {
    let ws = workspace();
    let root = ws.path().canonicalize().unwrap();
    std::fs::create_dir(root.join(".dc")).unwrap();
    let file = root.join(".dc/settings.json");
    std::fs::write(&file, "SAFE").unwrap();
    let mut c = Client::in_workspace(&root, &["--read-only", file.to_str().unwrap()]);
    let attacks = "echo EVIL > .dc/settings.json; rm -f .dc/settings.json; \
        mv .dc .dc.bak; mv .dc/settings.json .dc/x; echo ok > newfile.txt; echo done";
    let out = c.run(1, "sh", &["-c", attacks]);
    assert_eq!(out["stdout"].as_str().unwrap().trim(), "done", "{out}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "SAFE");
    assert!(!root.join(".dc.bak").exists());
    assert_eq!(
        std::fs::read_to_string(root.join("newfile.txt")).unwrap(),
        "ok\n"
    );
}

fn audit_dir() -> tempfile::TempDir {
    tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
}

fn audit_cmd(args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_nanosandbox-mcp"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn verify_dir(dir: &std::path::Path) -> (Option<i32>, String, String) {
    audit_cmd(&["--audit-verify", dir.to_str().unwrap()])
}

fn session_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("session-")
        })
        .collect();
    v.sort();
    v
}

/// Each command is a start and an end; the chain verifies; the session is
/// sealed when the client goes away; nothing private is in it; the commands
/// themselves can't read it.
#[test]
fn the_audit_dir_records_each_command_and_keeps_what_is_private_out() {
    let ws = workspace();
    let dir = audit_dir();
    let mut c = Client::in_workspace(
        ws.path(),
        &[
            "--audit-dir",
            dir.path().to_str().unwrap(),
            // The home directory is hidden by default, which would hide the
            // record too: with it visible, only its own protection stops a
            // read.
            "--no-hide-home",
            "--env",
            "API_KEY=value-that-must-not-leak",
        ],
    );
    let out = c.run(1, "sh", &["-c", "echo first; exit 4"]);
    assert_eq!(out["exit_code"], 4);
    c.run(2, "curl", &["--token=tok-live-999", "http://localhost:1"]);
    let read = c.run(
        3,
        "sh",
        &["-c", &format!("cat {}/session-*", dir.path().display())],
    );
    assert_ne!(read["exit_code"], 0, "a command read the record: {read}");
    assert!(
        !read["stdout"].as_str().unwrap().contains("first"),
        "{read}"
    );

    drop(c.child.stdin.take());
    assert!(c.child.wait().unwrap().success());

    let (code, stdout, err) = verify_dir(dir.path());
    assert_eq!(code, Some(0), "{err}");
    assert!(
        stdout.starts_with("ok: 1 sessions (1 sealed), 3 commands"),
        "{stdout}"
    );
    let text = std::fs::read_to_string(&session_files(dir.path())[0]).unwrap();
    assert!(text.contains("\"exit_code\":4"), "{text}");
    assert!(text.contains("echo first; exit 4"), "{text}");
    assert!(text.contains("API_KEY"), "the name is kept: {text}");
    assert!(!text.contains("value-that-must-not-leak"), "{text}");
    assert!(!text.contains("tok-live-999"), "{text}");
    assert!(text.contains("<redacted>"), "{text}");
    assert!(text.contains("session_end"), "{text}");
}

/// The server killed while a command runs: the record shows it started, and
/// never ended, and that the session was never sealed.
#[test]
fn a_server_killed_mid_command_leaves_the_command_started_and_not_ended() {
    let ws = workspace();
    let dir = audit_dir();
    let mut c = Client::in_workspace(ws.path(), &["--audit-dir", dir.path().to_str().unwrap()]);
    c.run(1, "echo", &["fine"]);
    c.send(
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":
        {"name":"run_command","arguments":{"command":"sleep","args":["31234"]}}}),
    );
    // Wait until the sleep's start is on disk.
    let file = session_files(dir.path())[0].clone();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !std::fs::read_to_string(&file).unwrap().contains("31234") {
        assert!(Instant::now() < deadline, "the start was never written");
        std::thread::sleep(Duration::from_millis(50));
    }
    c.child.kill().unwrap();
    c.child.wait().unwrap();

    let (code, stdout, err) = verify_dir(dir.path());
    assert_eq!(code, Some(0), "killing the server isn't tampering: {err}");
    assert!(stdout.contains("unsealed"), "{stdout}");
    assert!(
        stdout.contains("2 commands started, 1 with no end"),
        "{stdout}"
    );
    let _ = Command::new("pkill").args(["-f", "[s]leep 31234"]).status();
}

#[test]
fn a_changed_audit_file_fails_verification() {
    let ws = workspace();
    let dir = audit_dir();
    {
        let mut c = Client::in_workspace(ws.path(), &["--audit-dir", dir.path().to_str().unwrap()]);
        c.run(1, "echo", &["a"]);
        c.run(2, "echo", &["b"]);
        drop(c.child.stdin.take());
        c.child.wait().unwrap();
    }
    assert_eq!(verify_dir(dir.path()).0, Some(0));
    let file = &session_files(dir.path())[0];
    let text = std::fs::read_to_string(file).unwrap();
    std::fs::write(file, text.replacen("\"b\"", "\"c\"", 1)).unwrap();
    let (code, _, err) = verify_dir(dir.path());
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("changed"), "{err}");
}

/// Where commands can write, they could rewrite their own record.
#[test]
fn the_audit_dir_is_refused_where_commands_can_write() {
    let ws = workspace();
    for place in [
        ws.path().join("audit").to_str().unwrap().to_string(),
        "/tmp/nsb-audit-should-not-exist".to_string(),
    ] {
        let (code, err) = refused(&[
            "--workspace",
            ws.path().to_str().unwrap(),
            "--audit-dir",
            &place,
        ]);
        assert_eq!(code, Some(2), "{place}: {err}");
        assert!(err.contains("where commands can write"), "{err}");
        assert!(
            !std::path::Path::new(&place).exists(),
            "{place} was created"
        );
    }
}

/// Two agents on one machine can share a directory: a session file each.
#[test]
fn two_servers_can_record_into_the_same_directory() {
    let ws1 = workspace();
    let ws2 = workspace();
    let dir = audit_dir();
    let args = ["--audit-dir", dir.path().to_str().unwrap()];
    let mut a = Client::in_workspace(ws1.path(), &args);
    let mut b = Client::in_workspace(ws2.path(), &args);
    a.run(1, "echo", &["a"]);
    b.run(1, "echo", &["b"]);
    for c in [&mut a, &mut b] {
        drop(c.child.stdin.take());
        c.child.wait().unwrap();
    }
    assert_eq!(session_files(dir.path()).len(), 2);
    let (code, stdout, err) = verify_dir(dir.path());
    assert_eq!(code, Some(0), "{err}");
    assert!(
        stdout.starts_with("ok: 2 sessions (2 sealed), 2 commands"),
        "{stdout}"
    );
}

#[test]
fn audit_cleanup_removes_old_sessions_on_request_and_leaves_the_record_sound() {
    let ws = workspace();
    let dir = audit_dir();
    for _ in 0..3 {
        let mut c = Client::in_workspace(ws.path(), &["--audit-dir", dir.path().to_str().unwrap()]);
        c.run(1, "echo", &["x"]);
        drop(c.child.stdin.take());
        c.child.wait().unwrap();
        std::thread::sleep(Duration::from_millis(5));
    }
    let d = dir.path().to_str().unwrap();
    assert_eq!(
        audit_cmd(&["--audit-cleanup", d]).0,
        Some(2),
        "a filter is required"
    );
    let (_, dry, _) = audit_cmd(&["--audit-cleanup", d, "--keep", "1", "--dry-run"]);
    assert!(dry.contains("would remove 2 sessions"), "{dry}");
    assert_eq!(
        session_files(dir.path()).len(),
        3,
        "a dry run removes nothing"
    );
    let (code, out, err) = audit_cmd(&["--audit-cleanup", d, "--keep", "1"]);
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("removed 2 sessions"), "{out}");
    assert_eq!(session_files(dir.path()).len(), 1);
    let (code, stdout, err) = verify_dir(dir.path());
    assert_eq!(code, Some(0), "{err}");
    assert!(stdout.starts_with("ok: 1 sessions"), "{stdout}");
}

/// Starting a server removes the sessions past the retention, by default 30
/// days, and `--audit-keep-days` changes that. A running one is left alone.
#[test]
fn a_new_server_removes_sessions_past_the_retention() {
    let ws = workspace();
    let dir = audit_dir();
    let d = dir.path().to_str().unwrap();
    let made = |ws: &std::path::Path| {
        let mut c = Client::in_workspace(ws, &["--audit-dir", d]);
        c.run(1, "echo", &["x"]);
        drop(c.child.stdin.take());
        c.child.wait().unwrap();
        std::thread::sleep(Duration::from_millis(5));
    };
    made(ws.path());
    made(ws.path());
    let files = session_files(dir.path());
    assert_eq!(files.len(), 2);
    let aged = |path: &std::path::Path, days: u64| {
        let when = std::time::SystemTime::now() - Duration::from_secs(days * 86_400);
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(when)
            .unwrap();
    };
    aged(&files[0], 40);
    aged(&files[1], 10);

    // With no limit on age, nothing goes.
    let mut c = Client::in_workspace(
        ws.path(),
        &["--audit-dir", d, "--audit-keep-days", "forever"],
    );
    c.run(1, "echo", &["y"]);
    drop(c.child.stdin.take());
    c.child.wait().unwrap();
    assert_eq!(session_files(dir.path()).len(), 3);

    // The default is 30 days: the 40-day-old one goes, the 10-day-old stays.
    let mut c = Client::in_workspace(ws.path(), &["--audit-dir", d]);
    c.run(1, "echo", &["z"]);
    let left = session_files(dir.path());
    assert!(!left.contains(&files[0]), "{left:?}");
    assert!(left.contains(&files[1]), "{left:?}");
    drop(c.child.stdin.take());
    c.child.wait().unwrap();
    let (code, stdout, err) = verify_dir(dir.path());
    assert_eq!(code, Some(0), "{err}");
    assert!(stdout.starts_with("ok: 3 sessions"), "{stdout}");
}

/// How an agent got into the audit directory: delete its own workspace, put
/// a symlink to the directory in its place, and write through the path on the
/// next call. Once with the workspace in a directory commands can't write,
/// once in one they can.
#[test]
fn a_command_cannot_reach_the_audit_dir_by_swapping_its_workspace_for_a_symlink() {
    for writable_parent in [false, true] {
        let outer = audit_dir();
        let root = outer.path().canonicalize().unwrap();
        let parent = root.join("parent");
        let ws = parent.join("ws");
        let dir = root.join("audit");
        std::fs::create_dir_all(&ws).unwrap();
        let parent_arg = parent.to_str().unwrap().to_string();
        let mut args = vec!["--audit-dir", dir.to_str().unwrap(), "--no-hide-home"];
        if writable_parent {
            args.extend(["--writable", &parent_arg]);
        }
        let mut c = Client::in_workspace(&ws, &args);
        let d = dir.display();
        let w = ws.display();
        c.run(
            1,
            "sh",
            &["-c", &format!("rm -rf {w}; mv {w} {w}.bak; ln -s {d} {w}")],
        );
        c.run(
            2,
            "sh",
            &[
                "-c",
                &format!("echo FORGED > {w}/session-forged.jsonl; rm -f {w}/session-*.jsonl"),
            ],
        );
        drop(c.child.stdin.take());
        c.child.wait().unwrap();
        let names: Vec<_> = session_files(&dir)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names.len(),
            1,
            "writable_parent={writable_parent}: {names:?}"
        );
        assert!(!names[0].contains("forged"), "{names:?}");
        let (code, stdout, err) = verify_dir(&dir);
        assert_eq!(code, Some(0), "writable_parent={writable_parent}: {err}");
        assert!(stdout.starts_with("ok: 1 sessions"), "{stdout}");
    }
}

/// What an `npm install` that hit the time limit did to the server on
/// Linux: node sets O_NONBLOCK on its stdin, which was the server's own, so
/// the server's next read failed and it exited. The command gets /dev/null.
#[test]
fn a_command_cannot_touch_the_servers_stdin() {
    let ws = workspace();
    let mut c = Client::in_workspace(ws.path(), &[]);
    let out = c.run(
        1,
        "sh",
        &[
            "-c",
            "python3 -c \"import os; a = os.fstat(0); b = os.stat('/dev/null'); \
             print('devnull' if a.st_rdev and a.st_rdev == b.st_rdev else 'not')\"; \
             python3 -c 'import fcntl, os; fcntl.fcntl(0, fcntl.F_SETFL, os.O_NONBLOCK)'; \
             head -c 10 /dev/stdin",
        ],
    );
    assert_eq!(out["stdout"].as_str().unwrap().trim(), "devnull", "{out}");
    let again = c.run(2, "echo", &["alive"]);
    assert_eq!(
        again["stdout"], "alive\n",
        "the server died after a command touched its stdin"
    );
}

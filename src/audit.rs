//! Audit trail: a start and an end event per run, handed to the [`AuditSink`] set with [`SandboxBuilder::audit`].
//!
//! `begin` may refuse a run, so nothing runs unaudited; a start with no end means the host
//! died mid-run. Events carry only sizes and env names, never stdin/stdout/env values.
//! Secret-looking arguments (`--token=...`, `Authorization:`, URL passwords, `NAME=value`)
//! become `<redacted>`; best effort, keep secrets out of arguments.
//!
//! [`SandboxBuilder::audit`]: crate::SandboxBuilder::audit

use crate::builder::{NetworkMode, Permission, SandboxConfig};
use crate::error::SandboxError;
use crate::result::ExecutionResult;
use serde::Serialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Receives each run's events on the thread that ran it; called concurrently, keep it fast.
pub trait AuditSink: Send + Sync {
    /// Called before the command starts. `Err` or a panic refuses the run with [`SandboxError::Audit`].
    fn begin(&self, start: &AuditStart) -> Result<(), String>;

    /// Called after the run; a panic is caught and the result still returned.
    fn end(&self, end: &AuditEnd);
}

/// What is about to run. Serializes to JSON with integer fields only.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct AuditStart {
    /// When the run began, in milliseconds since the Unix epoch.
    pub ts_ms: u64,
    pub sandbox_id: String,
    /// `(sandbox_id, run)` names the run and ties it to its [`AuditEnd`].
    pub run: u64,
    pub platform: &'static str,
    pub command: String,
    /// As given, with likely secrets replaced by `<redacted>`.
    pub args: Vec<String>,
    /// Length of the input given on stdin; the input itself isn't kept.
    pub stdin_bytes: u64,
    pub policy: AuditPolicy,
}

/// How a run ended.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct AuditEnd {
    /// When the run ended, in milliseconds since the Unix epoch.
    pub ts_ms: u64,
    pub sandbox_id: String,
    pub run: u64,
    pub outcome: AuditOutcome,
}

/// The sandbox's configuration, as far as it bears on what the run could do.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct AuditPolicy {
    /// `none`, `proxied` or `host`.
    pub network: &'static str,
    pub allowed_domains: Vec<String>,
    pub allow_private_destinations: bool,
    /// Readable and writable paths; `source:target` for binds.
    pub read_only: Vec<String>,
    pub writable: Vec<String>,
    pub deny_read: Vec<String>,
    pub hide_home: bool,
    pub working_dir: String,
    pub rootfs: Option<String>,
    pub private_tmp_bytes: Option<u64>,
    pub shared_tmp: bool,
    pub seccomp: bool,
    pub memory_limit: Option<u64>,
    /// CPUs, in thousandths.
    pub cpu_limit_millis: Option<u64>,
    pub wall_time_limit_ms: Option<u64>,
    pub cpu_time_limit_ms: Option<u64>,
    pub max_pids: Option<u32>,
    pub max_file_size: Option<u64>,
    pub max_open_files: Option<u32>,
    pub max_output: u64,
    pub clear_env: bool,
    /// Names only, never values.
    pub env_names: Vec<String>,
}

/// How the run ended.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditOutcome {
    /// The command ran and finished, however it finished.
    Completed {
        exit_code: i32,
        signal: Option<i32>,
        duration_ms: u64,
        timed_out: bool,
        out_of_memory: bool,
        tmp_limit_hit: bool,
        cpu_limit_hit: bool,
        output_truncated: bool,
        stdout_bytes: u64,
        stderr_bytes: u64,
        peak_memory: Option<u64>,
        cpu_time_ms: Option<u64>,
        /// Hosts the proxy refused.
        blocked_hosts: Vec<String>,
    },
    /// The command didn't run (not found, the sandbox couldn't be set up...).
    Failed { error: String },
}

/// Shared handle to a sink, kept in the configuration.
#[derive(Clone)]
pub(crate) struct AuditHook(pub(crate) Arc<dyn AuditSink>);

impl std::fmt::Debug for AuditHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditHook")
    }
}

impl AuditPolicy {
    pub(crate) fn from_config(config: &SandboxConfig) -> Self {
        let show = |source: &std::path::Path, target: &std::path::Path| {
            if source == target {
                source.display().to_string()
            } else {
                format!("{}:{}", source.display(), target.display())
            }
        };
        let mounts = |permission: Permission| -> Vec<String> {
            config
                .mounts
                .iter()
                .filter(|m| m.permission == permission)
                .map(|m| show(&m.source, &m.target))
                .collect()
        };
        let paths = |list: &[std::path::PathBuf]| -> Vec<String> {
            list.iter().map(|p| p.display().to_string()).collect()
        };
        let (network, allowed_domains) = match &config.network_mode {
            NetworkMode::None => ("none", Vec::new()),
            NetworkMode::Host => ("host", Vec::new()),
            NetworkMode::Proxied { allowed_domains } => ("proxied", allowed_domains.clone()),
        };
        let ms = |d: std::time::Duration| d.as_millis() as u64;
        let mut env_names: Vec<String> = config.env.keys().cloned().collect();
        env_names.sort();
        Self {
            network,
            allowed_domains,
            allow_private_destinations: config.allow_private_destinations,
            read_only: mounts(Permission::ReadOnly),
            writable: mounts(Permission::ReadWrite),
            deny_read: paths(&config.deny_read),
            hide_home: config.hide_home,
            working_dir: config.working_dir.display().to_string(),
            rootfs: config.rootfs.as_ref().map(|p| p.display().to_string()),
            private_tmp_bytes: config.private_tmp,
            shared_tmp: config.shared_tmp,
            seccomp: config.seccomp,
            memory_limit: config.memory_limit,
            cpu_limit_millis: config.cpu_limit.map(|c| (c * 1000.0).round() as u64),
            wall_time_limit_ms: config.wall_time_limit.map(ms),
            cpu_time_limit_ms: config.cpu_time_limit.map(ms),
            max_pids: config.max_pids,
            max_file_size: config.max_file_size,
            max_open_files: config.max_open_files,
            max_output: config.max_output,
            clear_env: config.clear_env,
            env_names,
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Records the start of a run. An error means it must not go ahead.
pub(crate) fn begin(
    hook: &AuditHook,
    sandbox_id: &str,
    run: u64,
    config: &SandboxConfig,
    cmd: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
) -> Result<(), SandboxError> {
    let start = AuditStart {
        ts_ms: now_ms(),
        sandbox_id: sandbox_id.to_string(),
        run,
        platform: crate::platform::name(),
        command: redact::word(cmd),
        args: redact::args(args),
        stdin_bytes: stdin.map_or(0, |s| s.len() as u64),
        policy: AuditPolicy::from_config(config),
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook.0.begin(&start))) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(SandboxError::Audit(format!(
            "{e}; not running the command, since it could not be recorded"
        ))),
        Err(_) => Err(SandboxError::Audit(
            "the audit sink panicked; not running the command, since it could not be recorded"
                .into(),
        )),
    }
}

/// Records how a run ended.
pub(crate) fn end(
    hook: &AuditHook,
    sandbox_id: &str,
    run: u64,
    result: &Result<ExecutionResult, SandboxError>,
) {
    let outcome = match result {
        Ok(r) => AuditOutcome::Completed {
            exit_code: r.exit_code,
            signal: r.signal,
            duration_ms: r.duration.as_millis() as u64,
            timed_out: r.killed_by_timeout,
            out_of_memory: r.killed_by_oom,
            tmp_limit_hit: r.killed_by_tmp_limit,
            cpu_limit_hit: r.killed_by_cpu_limit,
            output_truncated: r.output_truncated,
            stdout_bytes: r.stdout.len() as u64,
            stderr_bytes: r.stderr.len() as u64,
            peak_memory: r.peak_memory,
            cpu_time_ms: r.cpu_time.map(|d| d.as_millis() as u64),
            blocked_hosts: r.blocked_hosts.clone(),
        },
        Err(e) => AuditOutcome::Failed {
            error: e.to_string(),
        },
    };
    let end = AuditEnd {
        ts_ms: now_ms(),
        sandbox_id: sandbox_id.to_string(),
        run,
        outcome,
    };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook.0.end(&end)));
}

/// Best-effort removal of what looks like a secret from a command line.
mod redact {
    const REDACTED: &str = "<redacted>";

    /// Words that mark a name (`--api-key`, `GITHUB_TOKEN`) as holding a secret.
    const SECRET_WORDS: [&str; 11] = [
        "token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "apikey",
        "api_key",
        "api-key",
        "credential",
        "auth",
        "private_key",
    ];

    /// Headers whose whole value is one.
    const SECRET_HEADERS: [&str; 6] = [
        "authorization:",
        "proxy-authorization:",
        "x-api-key:",
        "x-auth-token:",
        "cookie:",
        "set-cookie:",
    ];

    fn secret_name(name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        SECRET_WORDS.iter().any(|w| name.contains(w))
    }

    /// Flags whose next argument is a credential, whatever the flag's name.
    fn takes_credential(flag: &str) -> bool {
        matches!(flag, "-u" | "--user" | "--proxy-user") || secret_name(flag)
    }

    pub(super) fn args(args: &[&str]) -> Vec<String> {
        let mut out = Vec::with_capacity(args.len());
        let mut redact_next = false;
        for arg in args {
            if std::mem::take(&mut redact_next) {
                out.push(REDACTED.to_string());
                continue;
            }
            let is_flag = arg.starts_with('-') && !arg.contains(char::is_whitespace);
            if is_flag && !arg.contains('=') && takes_credential(arg) {
                redact_next = true;
            }
            out.push(word(arg));
        }
        out
    }

    /// One argument: a flag, a value, or a whole `sh -c` script.
    pub(super) fn word(text: &str) -> String {
        let text = headers(text);
        let text = bearer(&text);
        let text = url_passwords(&text);
        assignments(&text)
    }

    /// `Authorization: ...` up to the end of the line or the closing quote.
    fn headers(text: &str) -> String {
        let lower = text.to_ascii_lowercase();
        let mut out = String::new();
        let mut at = 0;
        while at < text.len() {
            let hit = SECRET_HEADERS
                .iter()
                .filter_map(|h| lower[at..].find(h).map(|i| (at + i, h.len())))
                .min();
            let Some((start, len)) = hit else { break };
            let value = start + len;
            out.push_str(&text[at..value]);
            out.push(' ');
            out.push_str(REDACTED);
            let end = text[value..]
                .find(['"', '\'', '\n'])
                .map_or(text.len(), |i| value + i);
            at = end;
        }
        out.push_str(&text[at..]);
        out
    }

    /// `Bearer abc` and `Basic abc`, anywhere.
    fn bearer(text: &str) -> String {
        let mut out = String::new();
        let mut words = text.split_inclusive(char::is_whitespace).peekable();
        while let Some(w) = words.next() {
            out.push_str(w);
            let name = w.trim_end().to_ascii_lowercase();
            if (name == "bearer" || name == "basic" || name.ends_with(" bearer"))
                && w.ends_with(char::is_whitespace)
                && let Some(secret) = words.next()
            {
                let trail = &secret[secret.trim_end().len()..];
                if secret.trim_end() != REDACTED {
                    out.push_str(REDACTED);
                    out.push_str(trail);
                } else {
                    out.push_str(secret);
                }
            }
        }
        out
    }

    /// `scheme://user:password@host`.
    fn url_passwords(text: &str) -> String {
        let mut out = String::new();
        let mut rest = text;
        while let Some(i) = rest.find("://") {
            let after = i + 3;
            out.push_str(&rest[..after]);
            rest = &rest[after..];
            let end = rest
                .find(|c: char| {
                    c == '/' || c == '?' || c == '#' || c.is_whitespace() || c == '"' || c == '\''
                })
                .unwrap_or(rest.len());
            let authority = &rest[..end];
            match authority.rsplit_once('@') {
                Some((userinfo, host)) if userinfo.contains(':') => {
                    let user = userinfo.split(':').next().unwrap_or("");
                    out.push_str(&format!("{user}:{REDACTED}@{host}"));
                }
                _ => out.push_str(authority),
            }
            rest = &rest[end..];
        }
        out.push_str(rest);
        out
    }

    /// `NAME=value` where `NAME` sounds like a secret, in any word of it.
    fn assignments(text: &str) -> String {
        let mut out = String::new();
        for w in text.split_inclusive(char::is_whitespace) {
            let body = w.trim_end();
            let trail = &w[body.len()..];
            match body.split_once('=') {
                Some((name, value))
                    if !value.is_empty()
                        && value != REDACTED
                        && secret_name(name.trim_start_matches('-')) =>
                {
                    out.push_str(&format!("{name}={REDACTED}{trail}"));
                }
                _ => out.push_str(w),
            }
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn args_of(a: &[&str]) -> Vec<String> {
            args(a)
        }

        #[test]
        fn flags_with_secret_names_lose_their_value() {
            assert_eq!(
                args_of(&["--token=abc123", "x"]),
                ["--token=<redacted>", "x"]
            );
            assert_eq!(
                args_of(&["--password", "hunter2", "x"]),
                ["--password", "<redacted>", "x"]
            );
            assert_eq!(
                args_of(&["-u", "me:pw", "url"]),
                ["-u", "<redacted>", "url"]
            );
            assert_eq!(args_of(&["--api-key=k"]), ["--api-key=<redacted>"]);
        }

        #[test]
        fn headers_and_bearer_tokens_are_removed_inside_a_script() {
            let script =
                r#"curl -H "Authorization: Bearer abc.def" -H 'X-Api-Key: k1' https://x.test"#;
            let out = word(script);
            assert!(!out.contains("abc.def") && !out.contains("k1"), "{out}");
            assert!(out.contains("https://x.test"), "{out}");
            assert!(word("curl --oauth2-bearer x").contains("--oauth2-bearer"));
            assert!(!word("echo Bearer sk-live-123").contains("sk-live-123"));
        }

        #[test]
        fn a_password_in_a_url_goes_and_the_rest_stays() {
            assert_eq!(
                word("git clone https://me:s3cret@github.com/a/b.git"),
                "git clone https://me:<redacted>@github.com/a/b.git"
            );
            assert_eq!(word("https://github.com/a/b"), "https://github.com/a/b");
            assert_eq!(word("http://localhost:8080/x"), "http://localhost:8080/x");
        }

        #[test]
        fn secret_looking_assignments_in_a_script_lose_their_value() {
            let out = word("export GITHUB_TOKEN=ghp_abc && AWS_SECRET_ACCESS_KEY=zzz run");
            assert!(!out.contains("ghp_abc") && !out.contains("zzz"), "{out}");
            assert!(out.contains("GITHUB_TOKEN=<redacted>"), "{out}");
            assert_eq!(word("PATH=/usr/bin ls"), "PATH=/usr/bin ls");
            assert_eq!(word("N=3 ./run"), "N=3 ./run");
        }

        #[test]
        fn ordinary_commands_are_left_alone() {
            let cmd = ["-c", "ls -la /tmp && python3 -c 'print(2+2)' > out.txt"];
            assert_eq!(args_of(&cmd), cmd);
        }
    }
}

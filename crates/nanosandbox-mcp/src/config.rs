//! Launch options. The operator decides what the sandbox may touch; no tool parameter can change it.

use crate::protocol::{RunOutput, Runner};
use nanosandbox::{Sandbox, SandboxBuilder};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where, in the workspace, npm's and pip's caches are kept.
const CACHE_DIR: &str = ".nanosandbox-cache";
const CACHE_SUBDIRS: [&str; 3] = ["npm", "pip", "xdg"];

pub const USAGE: &str = "\
nanosandbox-mcp: an MCP server (stdio) that runs commands in a nanosandbox sandbox.

USAGE:
    nanosandbox-mcp --workspace <DIR> [OPTIONS]

The model chooses what to run. Everything below is chosen here, at launch,
and cannot be changed by a tool call.

FILES
    --workspace <DIR>       Working directory, and the only directory the
                            command can write to by default. Required.
    --read-only <PATH>      Also let commands read PATH (repeatable)
    --writable <PATH>       Also let commands write PATH (repeatable)
    --deny-read <PATH>      Hide PATH from commands (repeatable)
    --no-hide-home          Don't hide the home directory

NETWORK (off by default)
    --allow-network <HOST>  Allow connecting to HOST, comma-separated or
                            repeated (wildcards like *.example.com work)
    --host-network          Unrestricted network. Use with care.

LIMITS
    --memory <SIZE>         Memory limit, e.g. 512M, 2G      [default: 512M]
    --timeout <SECS>        Wall-clock limit per command     [default: 30]
    --cpu <N>               CPU share, e.g. 1.5       (Linux only)
    --max-pids <N>          Process count             (Linux only) [default: 128]
    --max-output <SIZE>     Cap on each of stdout and stderr per command,
                            so one call can't flood the model   [default: 1M]
    --max-concurrent <N>    Commands running at once         [default: CPU count]

ENVIRONMENT
    --no-cache              Don't keep npm's and pip's download caches in
                            <workspace>/.nanosandbox-cache (kept by default,
                            so a reinstall doesn't download again; delete the
                            directory to clear it)
    --env <KEY=VALUE>       Environment variable for commands (repeatable).
                            Commands otherwise get this process's PATH (so
                            what your terminal finds, they find), a HOME in
                            their private temp directory, and nothing else

MACOS ONLY
    --strict-tmp            Make /tmp and the other system temp directories
                            read-only; commands get only a private $TMPDIR.
                            Breaks programs that write /tmp by name, `mktemp -t`
                            and Apple's /usr/bin clang/cc shims

LINUX ONLY
    --no-seccomp            Turn the syscall filter off
    --host-uid <UID>        When run as root, run commands as this host user
    --host-gid <GID>        instead of nobody

AUDIT
    --audit-dir <DIR>       Keep a record in DIR: one file per server run. Each
                            command is recorded before it runs (and doesn't run
                            if that fails) and again when it ends: the command,
                            the policy, how it ended; never stdin, output or env
                            values, and likely secrets in arguments are replaced.
                            Lines are chained by hash. DIR must be somewhere
                            commands can't write, and they can't read it
    --audit-keep-days <N>   Starting a server removes sessions last written more
                            than N days ago     [default: 30; forever: no limit]
    --audit-max-size <S>    ...and the oldest until DIR holds no more than S
                                                [default: 1G; unlimited: no limit]
    --audit-verify <PATH>   Check the chains of DIR, or of one session file, report
                            sessions that were never sealed, and exit nonzero if
                            anything was changed
    --audit-cleanup <DIR>   Remove old sessions now. Needs one of:
        --keep <N>              keep the N newest
        --older-than <DAYS>     only those older than this
        --max-total-size <S>    oldest first, until DIR is under S
        --dry-run               only say what would go
                            Several have to hold together. Running sessions, and
                            any that don't verify, stay

OTHER
    --log-io                Also log stdin/stdout/stderr bodies to stderr
    --clean-tmp             Remove private temp directories that killed
                            servers left behind, then exit. Looks in $TMPDIR
                            (and /tmp on Linux); ones still in use are kept
    -h, --help              Print this help
    -V, --version           Print the version
";

#[derive(Debug, Default)]
pub struct Config {
    pub workspace: PathBuf,
    pub read_only: Vec<PathBuf>,
    pub writable: Vec<PathBuf>,
    pub deny_read: Vec<PathBuf>,
    pub no_hide_home: bool,
    pub no_cache: bool,
    pub allow_network: Vec<String>,
    pub host_network: bool,
    pub memory: u64,
    pub timeout: f64,
    pub cpu: Option<f64>,
    pub max_pids: Option<u32>,
    pub max_output: Option<u64>,
    pub max_concurrent: usize,
    pub env: Vec<(String, String)>,
    pub strict_tmp: bool,
    pub no_seccomp: bool,
    pub host_uid: Option<u32>,
    pub host_gid: Option<u32>,
    pub log_io: bool,
    pub audit_dir: Option<PathBuf>,
    pub audit_retention: crate::audit::Retention,
}

#[derive(Debug)]
pub enum Parsed {
    Run(Box<Config>),
    Help,
    Version,
    CleanTmp,
    AuditVerify(PathBuf),
    AuditCleanup(PathBuf, crate::audit::Plan),
}

pub fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Parsed, String> {
    let mut cfg = Config {
        memory: 512 * 1024 * 1024,
        timeout: 30.0,
        max_concurrent: std::thread::available_parallelism().map_or(2, |n| n.get()),
        max_pids: cfg!(target_os = "linux").then_some(128),
        // Library default is 16 MB per stream; far more than a model can use.
        max_output: Some(1 << 20),
        ..Config::default()
    };
    let mut workspace = None;
    let mut cleanup_dir: Option<PathBuf> = None;
    let mut cleanup = crate::audit::Plan::default();
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_owned(), Some(v.to_owned())),
            _ => (arg, None),
        };
        let mut value = |what: &str| -> Result<String, String> {
            inline
                .clone()
                .or_else(|| it.next())
                .ok_or_else(|| format!("{flag} needs {what}"))
        };
        match flag.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-V" | "--version" => return Ok(Parsed::Version),
            "--clean-tmp" => return Ok(Parsed::CleanTmp),
            "--audit-verify" => {
                return Ok(Parsed::AuditVerify(PathBuf::from(value(
                    "a directory or file",
                )?)));
            }
            "--audit-dir" => cfg.audit_dir = Some(PathBuf::from(value("a directory")?)),
            "--audit-keep-days" => {
                let v = value("a number of days, or forever")?;
                cfg.audit_retention.keep_days = match v.as_str() {
                    "forever" | "0" => None,
                    _ => Some(parse_num(&v, "--audit-keep-days")?),
                };
            }
            "--audit-max-size" => {
                let v = value("a size, or unlimited")?;
                cfg.audit_retention.max_bytes = match v.as_str() {
                    "unlimited" | "0" => None,
                    _ => Some(parse_size(&v)?),
                };
            }
            "--audit-cleanup" => cleanup_dir = Some(PathBuf::from(value("a directory")?)),
            "--keep" => cleanup.keep = Some(parse_num(&value("a number")?, "--keep")?),
            "--older-than" => {
                cleanup.older_than_days =
                    Some(parse_num(&value("a number of days")?, "--older-than")?)
            }
            "--max-total-size" => cleanup.max_total_bytes = Some(parse_size(&value("a size")?)?),
            "--dry-run" => cleanup.dry_run = true,
            "--workspace" => workspace = Some(PathBuf::from(value("a directory")?)),
            "--read-only" => cfg.read_only.push(PathBuf::from(value("a path")?)),
            "--writable" => cfg.writable.push(PathBuf::from(value("a path")?)),
            "--deny-read" => cfg.deny_read.push(PathBuf::from(value("a path")?)),
            "--no-hide-home" => cfg.no_hide_home = true,
            "--no-cache" => cfg.no_cache = true,
            "--allow-network" => cfg.allow_network.extend(
                value("a host")?
                    .split(',')
                    .map(str::trim)
                    .filter(|h| !h.is_empty())
                    .map(str::to_owned),
            ),
            "--host-network" => cfg.host_network = true,
            "--memory" => cfg.memory = parse_size(&value("a size")?)?,
            "--timeout" => cfg.timeout = parse_num(&value("seconds")?, "--timeout")?,
            "--cpu" => cfg.cpu = Some(parse_num(&value("a number")?, "--cpu")?),
            "--max-pids" => cfg.max_pids = Some(parse_num(&value("a number")?, "--max-pids")?),
            "--max-output" => cfg.max_output = Some(parse_size(&value("a size")?)?),
            "--max-concurrent" => {
                cfg.max_concurrent = parse_num(&value("a number")?, "--max-concurrent")?
            }
            "--env" => {
                let kv = value("KEY=VALUE")?;
                let (k, v) = kv
                    .split_once('=')
                    .filter(|(k, _)| !k.is_empty())
                    .ok_or_else(|| format!("--env needs KEY=VALUE, got `{kv}`"))?;
                cfg.env.push((k.to_owned(), v.to_owned()));
            }
            "--strict-tmp" => cfg.strict_tmp = true,
            "--no-seccomp" => cfg.no_seccomp = true,
            "--host-uid" => cfg.host_uid = Some(parse_num(&value("a uid")?, "--host-uid")?),
            "--host-gid" => cfg.host_gid = Some(parse_num(&value("a gid")?, "--host-gid")?),
            "--log-io" => cfg.log_io = true,
            other => return Err(format!("unknown option `{other}` (see --help)")),
        }
    }
    if let Some(dir) = cleanup_dir {
        cleanup.verify_first = true;
        return Ok(Parsed::AuditCleanup(dir, cleanup));
    }
    if cleanup.keep.is_some()
        || cleanup.older_than_days.is_some()
        || cleanup.max_total_bytes.is_some()
        || cleanup.dry_run
    {
        return Err(
            "--keep, --older-than, --max-total-size and --dry-run go with --audit-cleanup".into(),
        );
    }
    cfg.workspace = workspace.ok_or("--workspace is required (see --help)")?;
    if cfg.host_network && !cfg.allow_network.is_empty() {
        return Err("--host-network and --allow-network contradict each other".into());
    }
    if !(cfg.timeout.is_finite() && cfg.timeout > 0.0) {
        return Err("--timeout must be a positive number of seconds".into());
    }
    if cfg.max_concurrent == 0 {
        return Err("--max-concurrent must be at least 1".into());
    }
    Ok(Parsed::Run(Box::new(cfg)))
}

fn parse_num<T: std::str::FromStr>(s: &str, flag: &str) -> Result<T, String> {
    s.trim()
        .parse()
        .map_err(|_| format!("{flag}: `{s}` is not a valid number"))
}

/// `512`, `64K`, `512M`, `2G` (also `MB`, `MiB`, ...): powers of 1024.
fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim().to_ascii_lowercase();
    let t = t
        .strip_suffix("ib")
        .or_else(|| t.strip_suffix('b'))
        .unwrap_or(&t);
    let (digits, unit) = match t.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => t.split_at(i),
        None => (t, ""),
    };
    let multiplier: u64 = match unit {
        "" => 1,
        "k" => 1 << 10,
        "m" => 1 << 20,
        "g" => 1 << 30,
        _ => return Err(format!("`{s}` is not a size like 512M or 2G")),
    };
    digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .filter(|&n| n > 0)
        .ok_or_else(|| format!("`{s}` is not a size like 512M or 2G"))
}

impl Config {
    /// Opens `--audit-dir`, refusing a place commands could write (they could rewrite their record).
    fn open_audit_dir(
        &self,
        path: &Path,
        workspace: &Path,
    ) -> Result<(PathBuf, std::sync::Arc<crate::audit::Session>), String> {
        let dir = match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) => {
                let parent = if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                };
                parent
                    .canonicalize()
                    .map_err(|e| format!("--audit-dir {}: {e}", path.display()))?
                    .join(name)
            }
            _ => {
                return Err(format!(
                    "--audit-dir {} is not a directory path",
                    path.display()
                ));
            }
        };
        let shared_temp = [
            "/tmp",
            "/private/tmp",
            "/var/tmp",
            "/private/var/tmp",
            "/dev/shm",
            "/var/folders",
            "/private/var/folders",
        ]
        .map(PathBuf::from);
        let roots = std::iter::once(workspace.to_path_buf())
            .chain(self.writable.iter().filter_map(|p| p.canonicalize().ok()))
            .chain(shared_temp)
            .chain(std::iter::once(std::env::temp_dir()));
        for root in roots {
            let root = root.canonicalize().unwrap_or(root);
            if dir.starts_with(&root) {
                return Err(format!(
                    "--audit-dir {} is inside {}, where commands can write: they could change \
                     their own record. Put it somewhere else",
                    path.display(),
                    root.display()
                ));
            }
        }
        let session = crate::audit::Session::open(&dir, &self.audit_retention)?;
        Ok((dir, std::sync::Arc::new(session)))
    }

    pub fn build(
        &self,
    ) -> Result<(Sandbox, Option<std::sync::Arc<crate::audit::Session>>), String> {
        let workspace = self
            .workspace
            .canonicalize()
            .ok()
            .filter(|p| p.is_dir())
            .ok_or_else(|| {
                format!(
                    "--workspace {} is not a directory",
                    self.workspace.display()
                )
            })?;
        let audit = match &self.audit_dir {
            Some(path) => Some(self.open_audit_dir(path, &workspace)?),
            None => None,
        };
        let mut b: SandboxBuilder = Sandbox::builder()
            .working_dir(&workspace)
            .writable(&workspace)
            .memory_limit(self.memory)
            .wall_time_limit(Duration::from_secs_f64(self.timeout));
        if !self.no_hide_home {
            b = b.hide_home();
        }
        for p in &self.read_only {
            b = b.read_only(p);
        }
        for p in &self.writable {
            b = b.writable(p);
        }
        for p in &self.deny_read {
            b = b.deny_read(p);
        }
        if self.host_network {
            b = b.host_network();
        } else if !self.allow_network.is_empty() {
            let hosts: Vec<&str> = self.allow_network.iter().map(String::as_str).collect();
            b = b.allow_network(&hosts);
        }
        if let Some(n) = self.cpu {
            b = b.cpu_limit(n);
        }
        if let Some(n) = self.max_pids {
            b = b.max_pids(n);
        }
        if let Some(n) = self.max_output {
            b = b.max_output(n);
        }
        if let Some((dir, log)) = &audit {
            b = b.deny_read(dir).audit(log.clone());
        }
        for (k, v) in &self.env {
            b = b.env(k, v);
        }
        for (k, v) in self.cache_env(&workspace) {
            if !self.env.iter().any(|(set, _)| *set == k) {
                b = b.env(k, v);
            }
        }
        // Empty environment, but PATH is this process's: the library default misses Homebrew.
        // An explicit --env PATH=... wins.
        if !self.env.iter().any(|(k, _)| k == "PATH")
            && let Some(path) = std::env::var_os("PATH").and_then(|p| p.into_string().ok())
        {
            b = b.env("PATH", path);
        }
        b = self.linux_only(b)?;
        b = self.macos_only(b)?;
        let sandbox = b.build().map_err(|e| e.to_string())?;
        Ok((sandbox, audit.map(|(_, log)| log)))
    }

    #[cfg(target_os = "linux")]
    fn linux_only(&self, mut b: SandboxBuilder) -> Result<SandboxBuilder, String> {
        if self.no_seccomp {
            b = b.seccomp(false);
        }
        if let Some(uid) = self.host_uid {
            b = b.host_uid(uid);
        }
        if let Some(gid) = self.host_gid {
            b = b.host_gid(gid);
        }
        Ok(b)
    }

    #[cfg(not(target_os = "linux"))]
    fn linux_only(&self, b: SandboxBuilder) -> Result<SandboxBuilder, String> {
        for (set, flag) in [
            (self.no_seccomp, "--no-seccomp"),
            (self.host_uid.is_some(), "--host-uid"),
            (self.host_gid.is_some(), "--host-gid"),
        ] {
            if set {
                return Err(format!("{flag} is Linux only"));
            }
        }
        Ok(b)
    }

    /// Points npm, pip and `XDG_CACHE_HOME` users at a workspace directory so downloads persist.
    /// `HOME` stays private per call (no credentials survive); it isn't used because its tmpdir
    /// is capped at 256 MB. The dir ignores itself in git. Returns nothing if it can't be made.
    fn cache_env(&self, workspace: &Path) -> Vec<(String, String)> {
        if self.no_cache {
            return Vec::new();
        }
        let dir = workspace.join(CACHE_DIR);
        let made = (|| -> std::io::Result<()> {
            for sub in CACHE_SUBDIRS {
                std::fs::create_dir_all(dir.join(sub))?;
            }
            let ignore = dir.join(".gitignore");
            if !ignore.exists() {
                std::fs::write(ignore, "# Created by nanosandbox-mcp.\n*\n")?;
            }
            #[cfg(target_os = "linux")]
            if unsafe { libc::geteuid() } == 0 {
                const NOBODY: u32 = 65534;
                let (uid, gid) = (
                    self.host_uid.unwrap_or(NOBODY),
                    self.host_gid.unwrap_or(NOBODY),
                );
                std::os::unix::fs::chown(&dir, Some(uid), Some(gid))?;
                for sub in CACHE_SUBDIRS {
                    std::os::unix::fs::chown(dir.join(sub), Some(uid), Some(gid))?;
                }
            }
            Ok(())
        })();
        if let Err(e) = made {
            eprintln!(
                "nanosandbox-mcp: no download cache, can't make {}: {e}",
                dir.display()
            );
            return Vec::new();
        }
        [
            ("npm_config_cache", "npm"),
            ("PIP_CACHE_DIR", "pip"),
            ("XDG_CACHE_HOME", "xdg"),
        ]
        .into_iter()
        .map(|(var, sub)| {
            (
                var.to_string(),
                dir.join(sub).to_string_lossy().into_owned(),
            )
        })
        .collect()
    }

    #[cfg(target_os = "macos")]
    fn macos_only(&self, b: SandboxBuilder) -> Result<SandboxBuilder, String> {
        Ok(if self.strict_tmp {
            b.shared_tmp(false)
        } else {
            b
        })
    }

    #[cfg(not(target_os = "macos"))]
    fn macos_only(&self, b: SandboxBuilder) -> Result<SandboxBuilder, String> {
        if self.strict_tmp {
            return Err(
                "--strict-tmp is macOS only: elsewhere /tmp is already private to each \
                        run where the kernel allows it (see docs/THREAT_MODEL.md)"
                    .into(),
            );
        }
        Ok(b)
    }

    /// One line for the tool description: what the operator allowed.
    pub fn summary(&self) -> String {
        let network = if self.host_network {
            "unrestricted".to_string()
        } else if self.allow_network.is_empty() {
            "off".to_string()
        } else {
            format!("only {}", self.allow_network.join(", "))
        };
        let temp = if self.strict_tmp {
            " /tmp is read-only; use $TMPDIR for scratch files."
        } else {
            ""
        };
        format!(
            "Workspace (working directory, writable): {}. Network: {network}. Time limit: {}s \
             per call. Memory limit: {} MB.{temp}",
            self.workspace.display(),
            self.timeout,
            self.memory >> 20
        )
    }
}

impl Runner for Sandbox {
    fn run(
        &self,
        command: &str,
        args: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<RunOutput, String> {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let r = self
            .run_with_input(command, &args, stdin)
            .map_err(|e| e.to_string())?;
        Ok(RunOutput {
            failure_reason: r.failure_reason(),
            exit_code: r.exit_code,
            duration_ms: r.duration.as_millis() as u64,
            timed_out: r.killed_by_timeout,
            out_of_memory: r.killed_by_oom,
            cpu_limit_hit: r.killed_by_cpu_limit,
            tmp_limit_hit: r.killed_by_tmp_limit,
            output_truncated: r.output_truncated,
            blocked_hosts: r.blocked_hosts,
            stdout: r.stdout,
            stderr: r.stderr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Parsed, String> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    fn cfg(args: &[&str]) -> Config {
        match parse(args).unwrap() {
            Parsed::Run(c) => *c,
            _ => panic!("expected a config"),
        }
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(parse_size("64K").unwrap(), 64 << 10);
        assert_eq!(parse_size("512m").unwrap(), 512 << 20);
        assert_eq!(parse_size("2GiB").unwrap(), 2 << 30);
        assert_eq!(parse_size("1MB").unwrap(), 1 << 20);
        for bad in ["", "M", "0", "12x", "-1", "1.5G"] {
            assert!(parse_size(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn workspace_is_required() {
        assert!(parse(&[]).unwrap_err().contains("--workspace"));
        assert!(matches!(parse(&["--help"]).unwrap(), Parsed::Help));
        assert!(matches!(parse(&["-V"]).unwrap(), Parsed::Version));
    }

    #[test]
    fn both_flag_forms_and_repeats() {
        let c = cfg(&[
            "--workspace=/w",
            "--writable",
            "/a",
            "--writable=/b",
            "--allow-network",
            "a.com, b.com",
            "--allow-network=c.com",
            "--env",
            "K=V=W",
            "--timeout",
            "2.5",
            "--memory=1G",
        ]);
        assert_eq!(c.workspace, PathBuf::from("/w"));
        assert_eq!(c.writable, [PathBuf::from("/a"), PathBuf::from("/b")]);
        assert_eq!(c.allow_network, ["a.com", "b.com", "c.com"]);
        assert_eq!(c.env, [("K".to_string(), "V=W".to_string())]);
        assert_eq!(c.timeout, 2.5);
        assert_eq!(c.memory, 1 << 30);
    }

    #[test]
    fn the_download_cache_is_on_unless_turned_off() {
        assert!(!cfg(&["--workspace", "/w"]).no_cache);
        assert!(matches!(parse(&["--clean-tmp"]).unwrap(), Parsed::CleanTmp));
        assert!(
            matches!(parse(&["--audit-verify", "/x"]).unwrap(), Parsed::AuditVerify(p) if p == Path::new("/x"))
        );
        assert_eq!(
            cfg(&["--workspace", "/w", "--audit-dir", "/a/log"]).audit_dir,
            Some(PathBuf::from("/a/log"))
        );
        let default = cfg(&["--workspace", "/w"]).audit_retention;
        assert_eq!(default.keep_days, Some(30));
        assert_eq!(default.max_bytes, Some(1 << 30));
        let c = cfg(&[
            "--workspace",
            "/w",
            "--audit-keep-days",
            "7",
            "--audit-max-size",
            "200M",
        ]);
        assert_eq!(c.audit_retention.keep_days, Some(7));
        assert_eq!(c.audit_retention.max_bytes, Some(200 << 20));
        let c = cfg(&[
            "--workspace",
            "/w",
            "--audit-keep-days",
            "forever",
            "--audit-max-size",
            "unlimited",
        ]);
        assert_eq!(
            (c.audit_retention.keep_days, c.audit_retention.max_bytes),
            (None, None)
        );
        assert!(parse(&["--workspace", "/w", "--keep", "3"]).is_err());
        assert!(cfg(&["--workspace", "/w", "--no-cache"]).no_cache);
    }

    #[test]
    fn output_is_capped_at_a_size_a_model_can_use() {
        assert_eq!(cfg(&["--workspace", "/w"]).max_output, Some(1 << 20));
        assert_eq!(
            cfg(&["--workspace", "/w", "--max-output", "4M"]).max_output,
            Some(4 << 20)
        );
    }

    #[test]
    fn strict_tmp_is_off_unless_asked_for() {
        assert!(!cfg(&["--workspace", "/w"]).strict_tmp);
        let c = cfg(&["--workspace", "/w", "--strict-tmp"]);
        assert!(c.strict_tmp);
        assert!(c.summary().contains("/tmp is read-only"));
        assert!(
            !cfg(&["--workspace", "/w"])
                .summary()
                .contains("/tmp is read-only")
        );
    }

    #[test]
    fn rejects_bad_input() {
        for args in [
            &["--workspace", "/w", "--bogus"][..],
            &["--workspace", "/w", "--timeout", "0"],
            &["--workspace", "/w", "--timeout", "abc"],
            &["--workspace", "/w", "--env", "NOEQUALS"],
            &["--workspace", "/w", "--max-concurrent", "0"],
            &[
                "--workspace",
                "/w",
                "--host-network",
                "--allow-network",
                "a.com",
            ],
            &["--workspace"],
        ] {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }
}

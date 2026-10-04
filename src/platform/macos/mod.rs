//! macOS platform implementation
//!
//! Uses macOS sandbox-exec (Seatbelt) for sandboxing.
//!
//! ## Implementation
//!
//! - **Process isolation**: sandbox-exec with SBPL profiles
//! - **Filesystem**: Sandbox profile file system restrictions
//! - **Network**: Sandbox profile network restrictions + HTTP proxy for whitelisting
//! - **Resource limits**: `memory_limit` by polling `rusage` over every
//!   process of the run (see run_marker.rs); the rest (`max_open_files`,
//!   `max_file_size`, `cpu_time_limit`) via `setrlimit`. Not `RLIMIT_AS`
//!   (the kernel rejects it) or `RLIMIT_NPROC` (it counts the whole user,
//!   not just the sandbox).

use crate::builder::SandboxConfig;
use crate::error::{Result, SandboxError};
use crate::network::ProxiedNetwork;
use crate::platform::private_tmp::PrivateTmp;
use crate::platform::{rlimit_cpu_secs, PlatformExecutor};
use crate::result::ExecutionResult;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

mod profile;
mod run_marker;
use run_marker::RunMarker;
mod wait;
mod watchdog;
use watchdog::Watchdog;

/// Guards this crate's own forks (the sandboxed program, the watchdog
/// shell) against watchdog.rs's `cloexec_pipe()`: macOS has no atomic
/// `pipe2(O_CLOEXEC)`, so a fork landing between `pipe()` and the `fcntl`
/// that sets close-on-exec would inherit a plain copy of the watchdog's
/// write end, leaking it into an unrelated process and keeping the pipe
/// open long after the real write end closes -- silently defeating the
/// watchdog for that run. Confirmed for real under concurrent spawns
/// without this lock: leaked in about 1 in 5 tries. `cloexec_pipe` holds
/// this for writing around `pipe()`+`fcntl()`; every fork here holds it
/// for reading, so none can land inside that window. It can't do anything
/// about some unrelated fork elsewhere in a process embedding this crate.
static FORK_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

// std's spawn error carries only errno, so the child reports which setrlimit
// failed through a side pipe as [limit, errno].
const LIMIT_OPEN_FILES: u8 = 1;
const LIMIT_FILE_SIZE: u8 = 2;
const LIMIT_CPU_TIME: u8 = 3;

/// Check if sandbox-exec is available
pub fn is_supported() -> bool {
    std::path::Path::new("/usr/bin/sandbox-exec").exists()
}

/// macOS sandbox executor using sandbox-exec
pub struct MacOSExecutor {
    _private: (),
}

impl MacOSExecutor {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Apply resource limits using setrlimit.
    /// Runs in the child between fork and exec, so it must not allocate.
    /// `memory_limit` is not applied here: the macOS kernel rejects RLIMIT_AS,
    /// so `wait_with_timeout` enforces it by polling instead.
    fn apply_resource_limits(
        max_open_files: Option<u32>,
        max_file_size: Option<u64>,
        cpu_time_limit: Option<Duration>,
        report_fd: libc::c_int,
    ) -> std::io::Result<()> {
        // NOTE: RLIMIT_NPROC is NOT used on macOS because it limits processes
        // for the ENTIRE USER, not just the sandbox. This is not useful for
        // sandboxing and can interfere with other processes.
        // On Linux, we use cgroups pids controller instead.
        if let Some(max_files) = max_open_files {
            Self::set_rlimit(libc::RLIMIT_NOFILE, max_files as u64)
                .map_err(|e| Self::report_limit_failure(report_fd, LIMIT_OPEN_FILES, e))?;
        }
        if let Some(size) = max_file_size {
            Self::set_rlimit(libc::RLIMIT_FSIZE, size)
                .map_err(|e| Self::report_limit_failure(report_fd, LIMIT_FILE_SIZE, e))?;
        }
        if let Some(cpu_time) = cpu_time_limit {
            Self::set_rlimit(libc::RLIMIT_CPU, rlimit_cpu_secs(cpu_time))
                .map_err(|e| Self::report_limit_failure(report_fd, LIMIT_CPU_TIME, e))?;
        }
        Ok(())
    }

    /// Runs in the child, so it only makes one write(2) and does not allocate.
    fn report_limit_failure(fd: libc::c_int, limit: u8, err: std::io::Error) -> std::io::Error {
        let mut buf = [0u8; 5];
        buf[0] = limit;
        buf[1..].copy_from_slice(&err.raw_os_error().unwrap_or(0).to_ne_bytes());
        unsafe {
            libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len());
        }
        err
    }

    fn report_pipe() -> Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0 as libc::c_int; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(SandboxError::Internal(format!(
                "create limit report pipe: {}",
                std::io::Error::last_os_error()
            )));
        }
        for fd in fds {
            unsafe {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
        }
        Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
    }

    /// Turn a child's report into a message naming the rejected setting.
    fn limit_failure(report: OwnedFd, config: &SandboxConfig) -> Option<String> {
        let mut buf = [0u8; 5];
        let n = unsafe {
            libc::read(
                report.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n != buf.len() as isize {
            return None;
        }
        let errno = i32::from_ne_bytes(buf[1..].try_into().ok()?);
        let (setting, value, rlimit) = match buf[0] {
            LIMIT_OPEN_FILES => (
                "max_open_files",
                config.max_open_files?.to_string(),
                "RLIMIT_NOFILE",
            ),
            LIMIT_FILE_SIZE => (
                "max_file_size",
                config.max_file_size?.to_string(),
                "RLIMIT_FSIZE",
            ),
            LIMIT_CPU_TIME => (
                "cpu_time_limit",
                format!("{}s", rlimit_cpu_secs(config.cpu_time_limit?)),
                "RLIMIT_CPU",
            ),
            _ => return None,
        };
        Some(format!(
            "cannot apply {setting}={value} ({rlimit}): {}",
            std::io::Error::from_raw_os_error(errno)
        ))
    }

    fn set_rlimit(resource: libc::c_int, value: u64) -> std::io::Result<()> {
        let rlim = libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        if unsafe { libc::setrlimit(resource, &rlim) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Whether `cmd` resolves to something executable, the way `execvp` would
/// search `path_value` (":"-separated): `cmd` itself if it contains '/',
/// else each directory of `path_value` joined with it.
fn executable_in_path(cmd: &str, path_value: &str) -> bool {
    let access_x_ok = |p: &Path| {
        std::ffi::CString::new(p.as_os_str().as_bytes())
            .is_ok_and(|c| unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 })
    };
    if cmd.contains('/') {
        return access_x_ok(Path::new(cmd));
    }
    path_value
        .split(':')
        .filter(|d| !d.is_empty())
        .any(|dir| access_x_ok(&Path::new(dir).join(cmd)))
}

impl Default for MacOSExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformExecutor for MacOSExecutor {
    fn execute(
        &self,
        config: &SandboxConfig,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        proxy: Option<&ProxiedNetwork>,
    ) -> Result<ExecutionResult> {
        let start = Instant::now();

        // A NUL byte can't be passed to the program: say so the way Linux
        // does, instead of as a generic spawn failure.
        for s in std::iter::once(cmd).chain(args.iter().copied()).chain(
            config
                .env
                .iter()
                .flat_map(|(k, v)| [k.as_str(), v.as_str()]),
        ) {
            std::ffi::CString::new(s)?;
        }

        // Command::spawn() below always succeeds (it spawns sandbox-exec,
        // which exists); without this, a missing `cmd` only ever surfaced
        // as sandbox-exec's own exit 71 and stderr wording, which is
        // Apple's text, not this crate's, and not something to depend on
        // staying the same. Checked directly against the host's $PATH
        // instead, which macOS (no rootfs remapping, unlike Linux) also
        // sees. Matches execvp: a `cmd` containing '/' is used as-is.
        let path_value = config
            .env
            .get("PATH")
            .map(String::as_str)
            .unwrap_or("/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
        if !executable_in_path(cmd, path_value) {
            return Err(SandboxError::CommandNotFound(cmd.to_string()));
        }

        // private_tmp: a directory for this run, removed when this returns.
        // See platform/private_tmp.rs.
        let mut private_tmp = config
            .private_tmp
            .map(PrivateTmp::create)
            .transpose()
            .map_err(|e| SandboxError::ExecutionFailed(format!("create private /tmp: {e}")))?;

        let marker = RunMarker::create()
            .map_err(|e| SandboxError::ExecutionFailed(format!("create run marker: {e}")))?;

        // allow_network: a proxy listener for this run alone, on a fresh
        // loopback port the profile lets only this run reach. It closes when
        // the run ends; nothing listens between runs.
        let proxy_run = match proxy {
            Some(proxy) => {
                let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
                let port = listener.local_addr()?.port();
                Some((port, proxy.attach(listener)?))
            }
            None => None,
        };
        let proxy_port = proxy_run.as_ref().map(|(port, _)| *port);

        // Generate sandbox profile
        let profile = self.generate_profile(
            config,
            proxy_port,
            private_tmp.as_ref().map(PrivateTmp::path),
            Some(&marker),
        );

        let (report_rd, report_wr) = Self::report_pipe()?;
        let report_fd = report_wr.as_raw_fd();

        // Clone config values for the closure
        let max_open_files = config.max_open_files;
        let max_file_size = config.max_file_size;
        let cpu_time_limit = config.cpu_time_limit;

        // Build command: sandbox-exec -p <profile> -Dkey=value... -- <cmd> <args>
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.arg("-p").arg(&profile.policy);
        for (key, value) in &profile.params {
            command.arg(format!("-D{key}={value}"));
        }
        command.arg("--");
        command.arg(cmd);
        command.args(args);

        // Set working directory
        command.current_dir(&config.working_dir);

        // Clear and set environment
        if config.clear_env {
            command.env_clear();
        }
        for (key, value) in &config.env {
            command.env(key, value);
        }
        // Set default PATH if not provided
        if !config.env.contains_key("PATH") {
            command.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
        }
        if let Some(tmp) = &private_tmp {
            if !config.env.contains_key("TMPDIR") {
                command.env("TMPDIR", tmp.path());
            }
        }

        // Set proxy environment variables if proxied network
        if let Some(port) = proxy_port {
            command.envs(ProxiedNetwork::env_vars(port));
        }

        // Setup stdin/stdout/stderr
        command.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        // CRITICAL: Set up process group and resource limits before exec
        // This runs in the child process after fork but before exec
        unsafe {
            command.pre_exec(move || {
                // Create a new process group with this process as leader
                // This allows us to kill all children with killpg
                libc::setpgid(0, 0);

                MacOSExecutor::apply_resource_limits(
                    max_open_files,
                    max_file_size,
                    cpu_time_limit,
                    report_fd,
                )
            });
        }

        // Held for the fork; see FORK_LOCK on why.
        let spawned = {
            let _fork = FORK_LOCK.read().unwrap_or_else(|e| e.into_inner());
            command.spawn()
        };
        drop(report_wr);
        let mut child = match spawned {
            Ok(child) => {
                drop(report_rd);
                child
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(SandboxError::CommandNotFound(cmd.to_string()));
            }
            Err(e) => {
                let msg = Self::limit_failure(report_rd, config).unwrap_or_else(|| e.to_string());
                return Err(SandboxError::ExecutionFailed(msg));
            }
        };

        // Stands in for PR_SET_PDEATHSIG, which macOS doesn't have (see
        // watchdog.rs). Kept alive for the rest of this call via Drop.
        let pgid = child.id() as i32;
        let _watchdog = Watchdog::spawn(pgid).inspect_err(|_| {
            let _ = child.kill();
            let _ = child.wait();
        })?;

        // stdin is written inside wait_with_timeout's own loop, interleaved
        // with draining stdout/stderr -- not all upfront here. A program
        // that echoes input to output as it goes (e.g. `cat`) can block on
        // writing its own output once enough of it is buffered and unread,
        // which stops it reading more stdin in turn; writing stdin to
        // completion before anything drains stdout/stderr deadlocks against
        // that once either side exceeds one pipe buffer (confirmed for real
        // with 200KB of stdin, and independently with >64KB of output alone
        // and no stdin at all).
        let mut result = self.wait_with_timeout(
            &mut child,
            stdin,
            config,
            private_tmp.as_mut(),
            &marker,
            start,
        )?;
        result.blocked_hosts = proxy_run.map(|(_, a)| a.finish()).unwrap_or_default();
        Ok(result)
    }

    fn check_support(&self, config: &SandboxConfig) -> Result<()> {
        if !is_supported() {
            return Err(SandboxError::SandboxExecUnavailable);
        }
        // macOS has no per-sandbox process count or CPU share: RLIMIT_NPROC
        // counts every process the user has, not the sandbox's.
        for (set, setting) in [
            (config.max_pids.is_some(), "max_pids"),
            (config.cpu_limit.is_some(), "cpu_limit"),
        ] {
            if set {
                return Err(SandboxError::Unsupported {
                    setting: format!("{setting} on macOS"),
                    reason: "macOS has no way to limit it per sandbox (no cgroups); leave it \
                             unset there"
                        .into(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_is_supported() {
        // On macOS, sandbox-exec should exist
        #[cfg(target_os = "macos")]
        assert!(is_supported());
    }
}

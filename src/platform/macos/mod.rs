//! macOS backend: sandbox-exec (Seatbelt) with SBPL profiles, plus an HTTP proxy for the
//! network allowlist. `memory_limit` is enforced by polling rusage over the whole run
//! (run_marker.rs); other limits use `setrlimit`. No `RLIMIT_AS` (kernel rejects it) or
//! `RLIMIT_NPROC` (counts the whole user).

use crate::builder::SandboxConfig;
use crate::error::{Result, SandboxError};
use crate::network::ProxiedNetwork;
use crate::platform::private_tmp::PrivateTmp;
use crate::platform::supervise::{Handles, Launched, Outcome, Supervisor};
use crate::platform::{PlatformExecutor, rlimit_cpu_secs};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

pub(crate) mod kqueue;
mod profile;
pub(crate) mod run_marker;
use run_marker::RunMarker;
mod wait;
mod watchdog;
use watchdog::Watchdog;

/// Orders forks against `cloexec_pipe()`: macOS has no `pipe2(O_CLOEXEC)`, so a fork between
/// `pipe()` and `fcntl` leaks the fds. `cloexec_pipe` writes; every fork here reads.
static FORK_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// A pipe with `O_CLOEXEC` fds, under FORK_LOCK.
pub(crate) fn cloexec_pipe(what: &str) -> Result<(OwnedFd, OwnedFd)> {
    let _fork = FORK_LOCK.write().unwrap_or_else(|e| e.into_inner());
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(SandboxError::Internal {
            context: format!("create {what} pipe"),
            source: Box::new(std::io::Error::last_os_error()),
        });
    }
    for fd in fds {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(SandboxError::Internal {
                context: format!("set close-on-exec on {what} pipe"),
                source: Box::new(err),
            });
        }
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

// The child reports which setrlimit failed over a side pipe as [limit, errno].
const LIMIT_OPEN_FILES: u8 = 1;
const LIMIT_FILE_SIZE: u8 = 2;
const LIMIT_CPU_TIME: u8 = 3;

pub fn is_supported() -> bool {
    std::path::Path::new("/usr/bin/sandbox-exec").exists()
}

pub struct MacOSExecutor {
    _private: (),
}

impl MacOSExecutor {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Apply setrlimit limits in the child after fork: must not allocate. `memory_limit` is
    /// polled in `wait_with_timeout` instead (kernel rejects RLIMIT_AS).
    fn apply_resource_limits(
        max_open_files: Option<u32>,
        max_file_size: Option<u64>,
        cpu_time_limit: Option<Duration>,
        report_fd: libc::c_int,
    ) -> std::io::Result<()> {
        // No RLIMIT_NPROC: it counts the whole user, not the sandbox.
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
        cloexec_pipe("limit report")
    }

    /// Turn a child's report into a message naming the rejected setting, plus the `io::Error`
    /// rebuilt from the child's errno.
    fn limit_failure(report: OwnedFd, config: &SandboxConfig) -> Option<(String, std::io::Error)> {
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
        Some((
            format!("cannot apply {setting}={value} ({rlimit})"),
            std::io::Error::from_raw_os_error(errno),
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

/// Whether `cmd` resolves like `execvp` over `path_value`: used as-is if it contains '/'.
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

/// Starts the command (on the supervisor thread) and returns its I/O ends with the closure that
/// supervises it there to the end.
fn launch_in_thread(
    config: &Arc<SandboxConfig>,
    cmd: &str,
    args: &[String],
    stdin: bool,
    proxy: Option<Arc<ProxiedNetwork>>,
) -> Result<(Handles, impl FnOnce() -> Result<Outcome> + use<>)> {
    // A NUL byte is reported as on Linux, not as a generic spawn failure.
    for s in std::iter::once(cmd)
        .chain(args.iter().map(String::as_str))
        .chain(
            config
                .env
                .iter()
                .flat_map(|(k, v)| [k.as_str(), v.as_str()]),
        )
    {
        std::ffi::CString::new(s)?;
    }

    // spawn() always succeeds (it runs sandbox-exec), and sandbox-exec's exit 71 text is
    // Apple's, so check `cmd` against the host $PATH like execvp (a '/' is used as-is).
    let path_value = config
        .env
        .get("PATH")
        .map(String::as_str)
        .unwrap_or("/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
    if !executable_in_path(cmd, path_value) {
        return Err(SandboxError::CommandNotFound(cmd.to_string()));
    }

    // Private dir for this run, removed on return.
    let mut private_tmp = config
        .private_tmp
        .map(PrivateTmp::create)
        .transpose()
        .map_err(|e| SandboxError::ExecutionFailed {
            context: "create private /tmp".into(),
            source: Box::new(e),
        })?;

    let marker = RunMarker::create().map_err(|e| SandboxError::ExecutionFailed {
        context: "create run marker".into(),
        source: Box::new(e),
    })?;

    // allow_network: per-run proxy on a fresh loopback port only this run's profile reaches.
    let proxy_run = match &proxy {
        Some(proxy) => {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
            let port = listener.local_addr()?.port();
            Some((port, proxy.attach(listener)?))
        }
        None => None,
    };
    let proxy_port = proxy_run.as_ref().map(|(port, _)| *port);

    let profile = MacOSExecutor::new().generate_profile(
        config,
        proxy_port,
        private_tmp.as_ref().map(PrivateTmp::path),
        Some(&marker),
    );

    let (report_rd, report_wr) = MacOSExecutor::report_pipe()?;
    let report_fd = report_wr.as_raw_fd();

    let max_open_files = config.max_open_files;
    let max_file_size = config.max_file_size;
    let cpu_time_limit = config.cpu_time_limit;

    let mut command = Command::new("/usr/bin/sandbox-exec");
    command.arg("-p").arg(&profile.policy);
    for (key, value) in &profile.params {
        command.arg(format!("-D{key}={value}"));
    }
    command.arg("--");
    command.arg(cmd);
    command.args(args);

    command.current_dir(&config.working_dir);

    if config.clear_env {
        command.env_clear();
    }
    for (key, value) in &config.env {
        command.env(key, value);
    }
    if !config.env.contains_key("PATH") {
        command.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
    }
    if let Some(tmp) = &private_tmp
        && !config.env.contains_key("TMPDIR")
    {
        command.env("TMPDIR", tmp.path());
    }
    // HOME in the private dir unless set; npm/pip otherwise look up a real home.
    if let Some(tmp) = &private_tmp
        && config.clear_env
        && !config.env.contains_key("HOME")
    {
        command.env("HOME", tmp.path());
    }

    if let Some(port) = proxy_port {
        command.envs(ProxiedNetwork::env_vars_for(
            port,
            config.allow_private_destinations,
        ));
    }

    command.stdin(if stdin { Stdio::piped() } else { Stdio::null() });
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    unsafe {
        command.pre_exec(move || {
            // New session and process group: no controlling terminal (see linux/child.rs).
            libc::setsid();

            MacOSExecutor::apply_resource_limits(
                max_open_files,
                max_file_size,
                cpu_time_limit,
                report_fd,
            )
        });
    }

    // Held for the fork (see FORK_LOCK).
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
            let (context, source) = MacOSExecutor::limit_failure(report_rd, config)
                .unwrap_or_else(|| ("spawn sandbox-exec".into(), e));
            return Err(SandboxError::ExecutionFailed {
                context,
                source: Box::new(source),
            });
        }
    };

    // Stands in for PR_SET_PDEATHSIG (watchdog.rs); alive until dropped.
    let pgid = child.id() as i32;
    let watchdog = Watchdog::spawn(pgid).inspect_err(|_| {
        let _ = child.kill();
        let _ = child.wait();
    })?;

    let handles = Handles {
        stdin: child.stdin.take().map(OwnedFd::from),
        stdout: child.stdout.take().map(OwnedFd::from),
        stderr: child.stderr.take().map(OwnedFd::from),
        pid: child.id(),
    };
    let timeout = config.wall_time_limit.unwrap_or(Duration::from_secs(3600));
    let memory_limit = config.memory_limit;

    let supervise = move || {
        let _watchdog = watchdog;
        let ended = MacOSExecutor::supervise(
            &mut child,
            timeout,
            memory_limit,
            private_tmp.as_mut(),
            &marker,
        )?;
        let blocked_hosts = proxy_run.map(|(_, a)| a.finish()).unwrap_or_default();
        drop(private_tmp);
        drop(marker);

        let rusage = ended.rusage;
        let user_time = Duration::new(
            rusage.ru_utime.tv_sec as u64,
            rusage.ru_utime.tv_usec as u32 * 1000,
        );
        let sys_time = Duration::new(
            rusage.ru_stime.tv_sec as u64,
            rusage.ru_stime.tv_usec as u32 * 1000,
        );
        Ok(Outcome {
            exit_code: ended.exit_code,
            signal: ended.signal,
            killed_by_timeout: ended.killed_by_timeout,
            killed_by_oom: ended.killed_by_oom,
            killed_by_tmp_limit: ended.killed_by_tmp_limit,
            killed_by_cpu_limit: false,
            // ru_maxrss is in bytes on macOS.
            peak_memory: Some(rusage.ru_maxrss as u64),
            cpu_time: Some(user_time + sys_time),
            proc_isolated: true,
            blocked_hosts,
        })
    };
    Ok((handles, supervise))
}

impl PlatformExecutor for MacOSExecutor {
    fn launch(
        &self,
        config: Arc<SandboxConfig>,
        cmd: &str,
        args: &[&str],
        stdin: bool,
        proxy: Option<Arc<ProxiedNetwork>>,
    ) -> Result<Launched> {
        let cmd = cmd.to_string();
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        Supervisor::start(move || launch_in_thread(&config, &cmd, &args, stdin, proxy))
    }

    fn check_support(&self, config: &SandboxConfig) -> Result<()> {
        if !is_supported() {
            return Err(SandboxError::SandboxExecUnavailable);
        }
        // No per-sandbox process count or CPU share (RLIMIT_NPROC is per-user).
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
        #[cfg(target_os = "macos")]
        assert!(is_supported());
    }
}

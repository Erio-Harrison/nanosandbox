//! Host-side preparation for `execute()`, before clone(): builds what the child needs so it
//! never has to (see child.rs). Ordinary Rust, runs in the parent.

use crate::builder::SandboxConfig;
use crate::error::{Result, SandboxError};
use crate::network::{ProxiedNetwork, SANDBOX_PROXY_PORT};
use crate::platform::rlimit_cpu_secs;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::path::Path;

use super::cgroup::{self, CgroupManager};
use super::exec_candidates;
use super::mount::needed_cgroup_controllers;
use super::namespace;

/// The pipes `execute()` wires to the child: stdout, stderr, optional stdin, and a "ready"
/// pipe releasing the child after uid/gid mapping and cgroup join. Owned, so early returns close them.
pub(super) struct Pipes {
    pub(super) stdout_read_fd: OwnedFd,
    pub(super) stdout_write_fd: OwnedFd,
    pub(super) stderr_read_fd: OwnedFd,
    pub(super) stderr_write_fd: OwnedFd,
    pub(super) ready_read_fd: OwnedFd,
    pub(super) ready_write_fd: OwnedFd,
    /// The init shim writes one byte here: the signal that killed the command, reported as
    /// `signal` (the shim can only exit with a status).
    pub(super) signal_read_fd: OwnedFd,
    pub(super) signal_write_fd: OwnedFd,
    pub(super) stdin_read_fd: Option<OwnedFd>,
    pub(super) stdin_write_fd: Option<OwnedFd>,
}

impl Pipes {
    /// Close-on-exec, so a concurrent clone() on another thread doesn't hand these to its
    /// program. dup2() onto 0/1/2 in the child clears the flag.
    pub(super) fn create(stdin: Option<&[u8]>, owner: (u32, u32)) -> Result<Self> {
        use nix::fcntl::OFlag;
        use nix::unistd::pipe2;

        let pipe = |what: &str| {
            pipe2(OFlag::O_CLOEXEC).map_err(|e| SandboxError::Internal {
                context: format!("create pipe for child {what}"),
                source: Box::new(e),
            })
        };
        let (stdout_read_fd, stdout_write_fd) = pipe("stdout")?;
        let (stderr_read_fd, stderr_write_fd) = pipe("stderr")?;
        let (ready_read_fd, ready_write_fd) = pipe("sync")?;
        let (signal_read_fd, signal_write_fd) = pipe("signal")?;
        let (stdin_read_fd, stdin_write_fd) = match stdin {
            Some(_) => {
                let (r, w) = pipe("stdin")?;
                (Some(r), Some(w))
            }
            None => (None, None),
        };

        // As root the sandbox runs as nobody (or chosen ids; see namespace::runs_as_root) and a
        // 0600 pipe belongs to its maker, so it couldn't reopen /dev/stdout. Give them to `owner`.
        if namespace::runs_as_root() {
            for fd in [
                Some(stdout_write_fd.as_raw_fd()),
                Some(stderr_write_fd.as_raw_fd()),
                stdin_read_fd.as_ref().map(AsRawFd::as_raw_fd),
            ]
            .into_iter()
            .flatten()
            {
                unsafe {
                    libc::fchown(fd, owner.0, owner.1);
                }
            }
        }

        Ok(Self {
            stdout_read_fd,
            stdout_write_fd,
            stderr_read_fd,
            stderr_write_fd,
            ready_read_fd,
            ready_write_fd,
            signal_read_fd,
            signal_write_fd,
            stdin_read_fd,
            stdin_write_fd,
        })
    }
}

/// Creates and configures the cgroup leaf before clone(), so a failure never strands a child
/// on the ready pipe. Adding the process is the only step needing child_pid.
pub(super) fn prepare_cgroup(config: &SandboxConfig) -> Result<Option<CgroupManager>> {
    let controllers = needed_cgroup_controllers(config);
    // cpu_time_limit needs no enabled controller: cpu.stat's usage_usec (read in wait.rs) works
    // as long as the cgroup exists.
    if controllers.is_empty() && config.cpu_time_limit.is_none() {
        return Ok(None);
    }
    let leaf_id = cgroup::next_leaf_id();
    let cg = CgroupManager::create(&leaf_id, &controllers)?;
    if let Some(memory) = config.memory_limit {
        cg.set_memory_limit(memory)?;
    }
    if let Some(cpu) = config.cpu_limit {
        cg.set_cpu_limit(cpu)?;
    }
    if let Some(pids) = config.max_pids {
        cg.set_pids_limit(pids)?;
    }
    Ok(Some(cg))
}

/// The sandboxed program's environment: this process's env (unless `clear_env(true)`) plus
/// `config.env`. `TMPDIR`, and `HOME` if unset, point at `private_tmp_path` when on; proxy
/// vars when `proxy_active`; default `PATH` if unset.
pub(super) fn prepare_env(
    config: &SandboxConfig,
    proxy_active: bool,
    private_tmp_path: Option<&Path>,
) -> HashMap<String, String> {
    let mut env: HashMap<String, String> = if config.clear_env {
        HashMap::new()
    } else {
        std::env::vars().collect()
    };
    env.extend(config.env.clone());

    if config.private_tmp.is_some() {
        let dir = private_tmp_path
            .unwrap_or(Path::new("/tmp"))
            .to_string_lossy()
            .into_owned();
        env.entry("TMPDIR".to_string())
            .or_insert_with(|| dir.clone());
        // Without HOME, npm/pip/git consult the password database: macOS finds the real home (EPERM
        // on write), Linux has no entry for the uid (ENOENT). The private dir gives them a cache.
        env.entry("HOME".to_string()).or_insert(dir);
    }

    if proxy_active {
        env.extend(ProxiedNetwork::env_vars_for(
            SANDBOX_PROXY_PORT,
            config.allow_private_destinations,
        ));
    }
    if !env.contains_key("PATH") {
        env.insert(
            "PATH".to_string(),
            "/usr/local/bin:/usr/bin:/bin".to_string(),
        );
    }
    env
}

/// Applied with raw setrlimit() in the child; built here to avoid allocating after clone().
pub(super) fn prepare_rlimits(config: &SandboxConfig) -> Vec<(u32, u64, &'static [u8])> {
    let mut rlimits = Vec::new();
    if let Some(n) = config.max_open_files {
        rlimits.push((
            libc::RLIMIT_NOFILE,
            u64::from(n),
            &b"Failed to apply max_open_files\n"[..],
        ));
    }
    if let Some(size) = config.max_file_size {
        rlimits.push((
            libc::RLIMIT_FSIZE,
            size,
            &b"Failed to apply max_file_size\n"[..],
        ));
    }
    if let Some(cpu) = config.cpu_time_limit {
        rlimits.push((
            libc::RLIMIT_CPU,
            rlimit_cpu_secs(cpu),
            &b"Failed to apply cpu_time_limit\n"[..],
        ));
    }
    rlimits
}

/// Everything execve() needs, built once: nix's wrapper would allocate a pointer array on the
/// success path; here the child's execve is two pointer derefs and a raw syscall.
pub(super) struct ExecBuffers {
    pub(super) cmd_cstr: CString,
    /// Kept alive for `args_ptrs`, which points into these buffers.
    pub(super) args_cstr: Vec<CString>,
    /// Kept alive for `envp_ptrs`, which points into these buffers.
    pub(super) envp_cstr: Vec<CString>,
    pub(super) args_ptrs: Vec<*const libc::c_char>,
    pub(super) envp_ptrs: Vec<*const libc::c_char>,
    pub(super) exec_paths: Vec<CString>,
}

impl ExecBuffers {
    /// `cmd_cstr`/`args_cstr` are built before `env` so a NUL byte is caught before private_tmp
    /// or the cgroup leaf exist.
    pub(super) fn build(
        cmd: &str,
        cmd_cstr: CString,
        args_cstr: Vec<CString>,
        env: &HashMap<String, String>,
    ) -> Result<Self> {
        // Built before clone(), not via set_var/remove_var in the child: clone() copies a
        // multi-threaded process, so a std::env lock held by another thread at that instant stays
        // locked forever in the child (hang or stale env under concurrent creation). NUL bytes error.
        let envp_cstr: Vec<CString> = env
            .iter()
            .map(|(k, v)| CString::new(format!("{k}={v}")))
            .collect::<std::result::Result<_, _>>()?;
        let exec_paths = exec_candidates(cmd, env.get("PATH").map(String::as_str).unwrap_or(""))?;

        // args_cstr/envp_cstr are kept in `ChildSetup` (see child.rs) so the strings the pointer
        // arrays reference stay alive.
        let mut args_ptrs: Vec<*const libc::c_char> =
            args_cstr.iter().map(|c| c.as_ptr()).collect();
        args_ptrs.push(std::ptr::null());
        let mut envp_ptrs: Vec<*const libc::c_char> =
            envp_cstr.iter().map(|c| c.as_ptr()).collect();
        envp_ptrs.push(std::ptr::null());

        Ok(Self {
            cmd_cstr,
            args_cstr,
            envp_cstr,
            args_ptrs,
            envp_ptrs,
            exec_paths,
        })
    }
}

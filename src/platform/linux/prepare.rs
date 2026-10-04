//! Host-side preparation for `execute()`, run before clone(): building
//! what the child needs so it never has to itself (see child.rs). Nothing
//! here is under that constraint -- it's all ordinary pre-clone Rust,
//! running in the parent.

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

/// The pipes `execute()` wires up to the child: stdout, stderr, a stdin
/// pipe if there's input to feed, and a "ready" pipe the parent uses to
/// release the child once its uid/gid mapping and cgroup membership are
/// set up. Owned, so that any early return closes them; they used to be
/// raw fds that every error path leaked.
pub(super) struct Pipes {
    pub(super) stdout_read_fd: OwnedFd,
    pub(super) stdout_write_fd: OwnedFd,
    pub(super) stderr_read_fd: OwnedFd,
    pub(super) stderr_write_fd: OwnedFd,
    pub(super) ready_read_fd: OwnedFd,
    pub(super) ready_write_fd: OwnedFd,
    pub(super) stdin_read_fd: Option<OwnedFd>,
    pub(super) stdin_write_fd: Option<OwnedFd>,
}

impl Pipes {
    /// Close-on-exec, so no sandboxed program inherits them. Without it, a
    /// run on another thread that clone()s while these are open hands them
    /// to its own program: it could read this run's stdin, write into its
    /// output, and hold its stdin open so it never sees EOF. dup2() onto
    /// 0/1/2 in the child clears the flag on those.
    pub(super) fn create(stdin: Option<&[u8]>) -> Result<Self> {
        use nix::fcntl::OFlag;
        use nix::unistd::pipe2;

        let pipe = |what: &str| {
            pipe2(OFlag::O_CLOEXEC)
                .map_err(|e| SandboxError::Internal(format!("create pipe for child {what}: {e}")))
        };
        let (stdout_read_fd, stdout_write_fd) = pipe("stdout")?;
        let (stderr_read_fd, stderr_write_fd) = pipe("stderr")?;
        let (ready_read_fd, ready_write_fd) = pipe("sync")?;
        let (stdin_read_fd, stdin_write_fd) = match stdin {
            Some(_) => {
                let (r, w) = pipe("stdin")?;
                (Some(r), Some(w))
            }
            None => (None, None),
        };

        // As root, the sandbox runs as nobody (see namespace::runs_as_root),
        // and a pipe belongs to whoever made it, mode 0600: so it couldn't
        // reopen its own stdout through /dev/stdout. Give them to nobody.
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
                    libc::fchown(fd, namespace::NOBODY, namespace::NOBODY);
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
            stdin_read_fd,
            stdin_write_fd,
        })
    }
}

/// Creates and configures the cgroup leaf for this run, *before* clone(),
/// so a failure here (rootless with no delegated subtree, a missing
/// controller...) never leaves a half-started child stuck on the ready
/// pipe. Adding the process to it is the only step that needs child_pid,
/// so it's the only cgroup step `execute()` still does after clone().
pub(super) fn prepare_cgroup(config: &SandboxConfig) -> Result<Option<CgroupManager>> {
    let controllers = needed_cgroup_controllers(config);
    // cpu_time_limit alone doesn't need a controller enabled: cpu.stat's
    // usage_usec, read in wait.rs, is populated regardless (confirmed for
    // real against a cgroup with none enabled) -- it just needs the
    // cgroup to exist.
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

/// The sandboxed program's environment. `clear_env(false)` (the default)
/// starts from this process's own environment, with `config.env` on top;
/// `clear_env(true)` starts empty. `TMPDIR` points at `private_tmp_path`
/// if private_tmp is on, proxy env vars are added when `proxy_active`, and
/// `PATH` gets a default if the caller didn't set one.
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
        let dir = private_tmp_path.unwrap_or(Path::new("/tmp"));
        env.entry("TMPDIR".to_string())
            .or_insert_with(|| dir.to_string_lossy().into_owned());
    }

    if proxy_active {
        env.extend(ProxiedNetwork::env_vars(SANDBOX_PROXY_PORT));
    }
    if !env.contains_key("PATH") {
        env.insert(
            "PATH".to_string(),
            "/usr/local/bin:/usr/bin:/bin".to_string(),
        );
    }
    env
}

/// Applied with raw setrlimit() in the child; built here for the same
/// no-allocation-after-clone() reason as everything in child.rs. These
/// used to be silently ignored on Linux -- confirmed for real: `ulimit -n`
/// reported 1024 under max_open_files(20), and cpu_time_limit (the
/// code_judge preset's main limit) wasn't applied at all.
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

/// Everything execve() needs in the child, built once here instead of
/// relying on nix's execve() wrapper to build a NUL-terminated pointer
/// array from scratch on every call -- an allocation that, unlike an
/// error path, sits on the ordinary success path too. Built, the child's
/// own execve call is just two pointer derefs and a raw syscall, no
/// allocation at all.
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
    /// `cmd_cstr`/`args_cstr` are built separately, before `env` (see
    /// `execute()`): they don't need it, and building them first means a
    /// NUL byte in the command or an argument is caught before private_tmp
    /// or the cgroup leaf even exist, not after.
    pub(super) fn build(
        cmd: &str,
        cmd_cstr: CString,
        args_cstr: Vec<CString>,
        env: &HashMap<String, String>,
    ) -> Result<Self> {
        // Built here, before clone(), and just used as-is in the child --
        // not with std::env::set_var/remove_var there. clone() copies this
        // whole (multi-threaded) process's memory, but only the calling
        // thread continues in the child; if another thread here happened
        // to be inside std::env's internal lock at that exact instant, the
        // child inherits it frozen "locked", and its own env mutation
        // later waits forever on a thread that doesn't exist in this
        // process. Confirmed for real under enough concurrent sandbox
        // creation: the child hangs there, or execs with a stale/corrupted
        // environment. A NUL byte in a variable is an error too; it used
        // to be dropped.
        let envp_cstr: Vec<CString> = env
            .iter()
            .map(|(k, v)| CString::new(format!("{k}={v}")))
            .collect::<std::result::Result<_, _>>()?;
        let exec_paths = exec_candidates(cmd, env.get("PATH").map(String::as_str).unwrap_or(""))?;

        // execve's own nix wrapper builds a NUL-terminated pointer array
        // from these each time it's called -- an allocation that, unlike
        // the ones above, sits on the ordinary success path too, not just
        // an error branch. Building it here instead, once, means the
        // child's own execve call is just two pointer derefs and a raw
        // syscall, no allocation at all. args_cstr/envp_cstr are kept
        // alongside these in `ChildSetup` (see child.rs) so the strings
        // they point into stay alive for the call.
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

//! Cgroup v2 management. Root writes under the real root; non-root needs a delegated
//! subtree (`ensure_own_scope`).

use crate::error::{Result, SandboxError};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

mod scope;
mod sweep;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// Shared base for per-sandbox leaves; never holds a process itself.
const NANOSANDBOX_CGROUP: &str = "nanosandbox";

static LEAF_ID: AtomicU64 = AtomicU64::new(0);

/// Per-process random value mixed into self-owned cgroup/scope names with the pid, so a
/// recycled pid's unswept leftover can never collide.
fn process_nonce() -> u32 {
    static NONCE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *NONCE.get_or_init(|| {
        use std::hash::{BuildHasher, Hasher};
        std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish() as u32
    })
}

/// A fresh, process-unique cgroup leaf id (pid not known yet at this point).
pub fn next_leaf_id() -> String {
    format!(
        "{}-{:08x}-{}",
        std::process::id(),
        process_nonce(),
        LEAF_ID.fetch_add(1, Ordering::Relaxed)
    )
}

/// Memory statistics from cgroup
#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub peak: u64,
}

/// CPU statistics from cgroup
#[derive(Debug, Clone)]
pub struct CpuStats {
    pub total_usec: u64,
}

/// Memory events from cgroup (for OOM detection)
#[derive(Debug, Clone, Default)]
pub struct MemoryEvents {
    pub oom: u64,
    pub oom_kill: u64,
    pub oom_group_kill: u64,
}

/// Cgroup v2 manager
pub struct CgroupManager {
    path: PathBuf,
}

impl CgroupManager {
    /// Creates a sandbox cgroup leaf, enabling only `needed` controllers.
    pub fn create(sandbox_id: &str, needed: &[&str]) -> Result<Self> {
        let base = ensure_base(needed)?;
        let path = base.join(sandbox_id);
        fs::create_dir_all(&path).map_err(|e| SandboxError::CgroupCreation {
            context: format!("Failed to create cgroup {sandbox_id}: {e}"),
            source: Some(Box::new(e)),
        })?;
        Ok(Self { path })
    }

    /// Dry run for `check_support()`: fails as `create()` would, but before clone().
    pub fn ensure_support(needed: &[&str]) -> Result<()> {
        ensure_base(needed).map(|_| ())
    }

    /// Set memory limit in bytes
    pub fn set_memory_limit(&self, bytes: u64) -> Result<()> {
        let path = self.path.join("memory.max");
        fs::write(&path, bytes.to_string()).map_err(|e| SandboxError::CgroupSetting {
            controller: "memory".into(),
            setting: "max".into(),
            value: bytes.to_string(),
            source: Box::new(e),
        })?;

        // No memory.high (throttles instead of OOM-killing, so overruns became timeouts) and no
        // swap (swapping would evade the limit).
        let swap = self.path.join("memory.swap.max");
        if swap.exists() {
            fs::write(&swap, "0").map_err(|e| SandboxError::CgroupSetting {
                controller: "memory".into(),
                setting: "swap.max".into(),
                value: "0".into(),
                source: Box::new(e),
            })?;
        }

        Ok(())
    }

    /// Set CPU limit (0.0 - N.0 where N is number of cores)
    pub fn set_cpu_limit(&self, cpus: f64) -> Result<()> {
        // cpu.max format: "<quota_usec> <period_usec>"
        let period = 100000u64;
        let quota = (cpus * period as f64) as u64;

        let value = format!("{} {}", quota, period);
        let path = self.path.join("cpu.max");

        fs::write(&path, &value).map_err(|e| SandboxError::CgroupSetting {
            controller: "cpu".into(),
            setting: "max".into(),
            value: value.clone(),
            source: Box::new(e),
        })?;

        Ok(())
    }

    /// Set maximum number of PIDs
    pub fn set_pids_limit(&self, max: u32) -> Result<()> {
        let path = self.path.join("pids.max");
        fs::write(&path, max.to_string()).map_err(|e| SandboxError::CgroupSetting {
            controller: "pids".into(),
            setting: "max".into(),
            value: max.to_string(),
            source: Box::new(e),
        })?;

        Ok(())
    }

    /// Add a process to this cgroup
    pub fn add_process(&self, pid: u32) -> Result<()> {
        let path = self.path.join("cgroup.procs");
        fs::write(&path, pid.to_string()).map_err(|e| SandboxError::CgroupCreation {
            context: format!("Failed to add PID {pid} to cgroup: {e}"),
            source: Some(Box::new(e)),
        })?;

        Ok(())
    }

    /// Get memory statistics
    pub fn get_memory_stats(&self) -> Result<MemoryStats> {
        let peak = fs::read_to_string(self.path.join("memory.peak"))
            .map_err(|e| SandboxError::Internal {
                context: "Failed to read memory.peak".into(),
                source: Box::new(e),
            })?
            .trim()
            .parse::<u64>()
            .unwrap_or(0);

        Ok(MemoryStats { peak })
    }

    /// Get CPU statistics
    pub fn get_cpu_stats(&self) -> Result<CpuStats> {
        let stat =
            fs::read_to_string(self.path.join("cpu.stat")).map_err(|e| SandboxError::Internal {
                context: "Failed to read cpu.stat".into(),
                source: Box::new(e),
            })?;

        let total_usec = stat
            .lines()
            .find_map(|line| line.strip_prefix("usage_usec "))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);

        Ok(CpuStats { total_usec })
    }

    /// Get memory events (for OOM detection)
    pub fn get_memory_events(&self) -> Result<MemoryEvents> {
        let events_path = self.path.join("memory.events");
        let events = fs::read_to_string(&events_path).map_err(|e| SandboxError::Internal {
            context: "Failed to read memory.events".into(),
            source: Box::new(e),
        })?;

        let mut result = MemoryEvents::default();

        for line in events.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                match parts[0] {
                    "oom" => result.oom = parts[1].parse().unwrap_or(0),
                    "oom_kill" => result.oom_kill = parts[1].parse().unwrap_or(0),
                    "oom_group_kill" => result.oom_group_kill = parts[1].parse().unwrap_or(0),
                    _ => {}
                }
            }
        }

        Ok(result)
    }

    /// Whether any process was OOM-killed. A read failure reports false, like the sibling stats reads.
    pub fn was_oom_killed(&self) -> bool {
        self.get_memory_events()
            .map(|e| e.oom_kill > 0 || e.oom_group_kill > 0)
            .unwrap_or(false)
    }

    /// All PIDs, or None if unknown (non-ENOENT read error); None is not empty, or retry loops stop early.
    fn get_pids(&self) -> Option<Vec<u32>> {
        let procs_path = self.path.join("cgroup.procs");
        match fs::read_to_string(&procs_path) {
            Ok(s) => Some(
                s.lines()
                    .filter_map(|line| line.trim().parse::<u32>().ok())
                    .collect(),
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(Vec::new()),
            Err(e) => {
                tracing::warn!("read {}: {e:?}", procs_path.display());
                None
            }
        }
    }

    /// Kills every process in the cgroup and waits until it's empty: `cgroup.kill` (kernel
    /// 5.14+, no fork race) then a poll on `cgroup.events`. Older kernels freeze and signal.
    pub fn kill_all(&self) {
        if fs::write(self.path.join("cgroup.kill"), "1").is_ok() {
            wait_until_empty(&self.path, KILL_WAIT);
            return;
        }

        self.kill_all_by_signals();
    }

    /// For kernels without `cgroup.kill`: freeze (no new forks), signal every process, and wait
    /// on `cgroup.events` for each round to land.
    fn kill_all_by_signals(&self) {
        let freeze_path = self.path.join("cgroup.freeze");
        let _ = fs::write(&freeze_path, "1"); // block new forks while killing
        for _ in 0..10 {
            match self.get_pids() {
                Some(pids) if pids.is_empty() => break,
                Some(pids) => {
                    for pid in &pids {
                        unsafe {
                            libc::kill(*pid as i32, libc::SIGKILL);
                        }
                    }
                }
                None => {}
            }
            wait_until_empty(&self.path, SIGNAL_ROUND);
        }
        let _ = fs::write(&freeze_path, "0");
        wait_until_empty(&self.path, KILL_WAIT);
    }

    /// Kills all processes and removes the cgroup directory.
    pub fn cleanup(&self) {
        self.kill_all();
        let _ = fs::remove_dir(&self.path);
    }
}

/// How long a kill may take to empty a cgroup before it's given up on.
const KILL_WAIT: Duration = Duration::from_millis(500);
/// How long one round of signals gets to empty the cgroup before the next round.
const SIGNAL_ROUND: Duration = Duration::from_millis(10);

/// Waits until `dir`'s `cgroup.events` says `populated 0` (the kernel flags the file for
/// `poll` on each change), or `timeout`. True once empty; a gone cgroup counts as empty.
pub(super) fn wait_until_empty(dir: &Path, timeout: Duration) -> bool {
    use std::io::{Read, Seek};
    use std::os::fd::AsRawFd;
    let Ok(mut events) = fs::File::open(dir.join("cgroup.events")) else {
        return true;
    };
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let mut text = String::new();
        if events.rewind().is_err() || events.read_to_string(&mut text).is_err() {
            return true;
        }
        if text.lines().any(|l| l.trim() == "populated 0") {
            return true;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return false;
        }
        let mut pfd = libc::pollfd {
            fd: events.as_raw_fd(),
            events: libc::POLLPRI,
            revents: 0,
        };
        let ms = crate::platform::checks::poll_timeout_ms(Some(deadline), now);
        unsafe {
            libc::poll(&mut pfd, 1, ms);
        }
    }
}

impl Drop for CgroupManager {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Ensures `nanosandbox/`'s shared base cgroup exists with `needed`
/// controllers enabled for its children, and returns its path.
fn ensure_base(needed: &[&str]) -> Result<PathBuf> {
    sweep::hold_instance_lock();
    let scope = scope::ensure_own_scope()?;
    let root_owned = scope == Path::new(CGROUP_ROOT);
    if !root_owned {
        sweep::sweep_scope_neighbors_if_due(&scope);
    }

    enable_subtree_control(&scope, needed)?;

    let base = scope.join(NANOSANDBOX_CGROUP);
    if base.exists() {
        if !safe_to_build_under(&base) {
            return Err(SandboxError::CgroupCreation {
                context: format!(
                    "{} already exists and holds a process we don't recognize as our own — refusing \
                     to build sandbox cgroups there in case it belongs to something else",
                    base.display()
                ),
                source: None,
            });
        }
    } else {
        fs::create_dir_all(&base).map_err(|e| SandboxError::CgroupCreation {
            context: format!("Failed to create base cgroup {}: {e}", base.display()),
            source: Some(Box::new(e)),
        })?;
    }

    let available = read_controller_list(&base.join("cgroup.controllers"))?;
    for controller in needed {
        if !available.iter().any(|c| c == controller) {
            return Err(SandboxError::CgroupCreation {
                context: if root_owned {
                    format!(
                        "the '{controller}' controller is not available under {} (available: {}); \
                         the running kernel does not expose it",
                        base.display(),
                        available.join(" ")
                    )
                } else {
                    format!(
                        "the '{controller}' controller is not available in this process's own \
                         delegated scope at {} (available: {}); its parent slice does not have it \
                         enabled in cgroup.subtree_control",
                        scope.display(),
                        available.join(" ")
                    )
                },
                source: None,
            });
        }
    }

    enable_subtree_control(&base, needed)?;

    sweep::sweep_stale_leaves(
        &base,
        |name| name.split('-').next(),
        sweep::owner_is_gone,
        sweep::kill_cgroup_atomically,
    ); // Drop doesn't run on SIGKILL/process::exit

    // Last: the sweeps above need a stale pid's lock file to confirm owner_is_gone.
    sweep::sweep_locks_if_due();

    Ok(base)
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Guards against a name collision silently sharing a cgroup with a
/// process we don't own.
fn safe_to_build_under(dir: &Path) -> bool {
    match fs::read_to_string(dir.join("cgroup.procs")) {
        Ok(procs) => only_us_or_empty(&procs),
        Err(_) => true,
    }
}

fn only_us_or_empty(procs: &str) -> bool {
    let us = std::process::id();
    procs
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .all(|pid| pid == us)
}

/// From `DelegateControllers`: `Delegate` is true for `Delegate=pids`, and
/// `cgroup.controllers` shows kernel-allowed, not delegated.
fn read_controller_list(path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(path).map_err(|e| SandboxError::CgroupCreation {
        context: format!("cannot read {}: {e}", path.display()),
        source: Some(Box::new(e)),
    })?;
    Ok(content.split_whitespace().map(str::to_string).collect())
}

/// The pids listed in `dir`'s `cgroup.procs`.
fn pids_in(dir: &Path) -> Vec<u32> {
    fs::read_to_string(dir.join("cgroup.procs"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|p| p.parse().ok())
        .collect()
}

/// Enables `controllers` in `dir`'s `cgroup.subtree_control`, idempotently.
fn enable_subtree_control(dir: &Path, controllers: &[&str]) -> Result<()> {
    if controllers.is_empty() {
        return Ok(());
    }

    // Serialize in-process callers: concurrent read-modify-write of a shared scope's
    // subtree_control kept losing the race (~half failed at 20-way).
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // Poison ignored: the lock guards no data.
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let subtree_path = dir.join("cgroup.subtree_control");
    let enabled = read_controller_list(&subtree_path)?;
    let missing: Vec<&str> = controllers
        .iter()
        .copied()
        .filter(|c| !enabled.iter().any(|e| e == c))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let value = missing
        .iter()
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ");

    // Writes to subtree_control are serialized by the kernel, so concurrent writers never fail
    // each other; an EBUSY is the no-internal-process rule, a process directly in `dir`. The
    // scope's root is emptied before its controllers are enabled (`scope::compute_own_scope`)
    // and the base never holds one, so it is reported, not retried.
    let last_err = match fs::write(&subtree_path, &value) {
        Ok(()) => return Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EBUSY) => e,
        Err(e) => {
            return Err(SandboxError::CgroupCreation {
                context: format!("cannot enable '{value}' in {}: {e}", subtree_path.display()),
                source: Some(Box::new(e)),
            });
        }
    };
    // Someone else's write may have covered us in the meantime.
    let enabled = read_controller_list(&subtree_path)?;
    if missing.iter().all(|c| enabled.iter().any(|e| e == c)) {
        return Ok(());
    }
    // EBUSY usually means the no-internal-process rule: name the process in `dir`.
    let described: Vec<String> = pids_in(dir)
        .into_iter()
        .map(|pid| {
            let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
            let field = |k: &str| {
                status
                    .lines()
                    .find_map(|l| l.strip_prefix(k))
                    .map(str::trim)
                    .unwrap_or("?")
                    .to_string()
            };
            format!("{pid}({} ppid={})", field("Name:"), field("PPid:"))
        })
        .collect();
    Err(SandboxError::CgroupCreation {
        context: format!(
            "cannot enable '{value}' in {} (busy; processes directly in it: [{}]): {}",
            subtree_path.display(),
            described.join(" "),
            last_err
        ),
        source: Some(Box::new(last_err)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_leaf_path() {
        let path = PathBuf::from(CGROUP_ROOT)
            .join(NANOSANDBOX_CGROUP)
            .join("test-sandbox");
        assert!(path.to_string_lossy().contains("nanosandbox"));
    }

    /// A leaf with `n` sleeping processes in it; None where cgroups aren't usable here.
    fn leaf_with_sleepers(n: usize) -> Option<(CgroupManager, Vec<std::process::Child>)> {
        let mgr = CgroupManager::create(&next_leaf_id(), &["memory"]).ok()?;
        let mut kids = Vec::new();
        for _ in 0..n {
            let kid = std::process::Command::new("sleep").arg("30").spawn().ok()?;
            mgr.add_process(kid.id()).ok()?;
            kids.push(kid);
        }
        Some((mgr, kids))
    }

    #[test]
    fn test_killing_by_signals_empties_the_cgroup() {
        let Some((mgr, mut kids)) = leaf_with_sleepers(5) else {
            return;
        };
        assert_eq!(mgr.get_pids().unwrap().len(), 5);
        mgr.kill_all_by_signals();
        assert!(mgr.get_pids().unwrap().is_empty());
        for kid in &mut kids {
            kid.wait().unwrap();
        }
        mgr.cleanup();
    }

    /// A domain controller (`memory`; `pids` is threaded and exempt) can't be enabled in a
    /// cgroup that holds a process.
    #[test]
    fn test_a_busy_subtree_control_names_the_process_in_the_cgroup() {
        let Some((mgr, mut kids)) = leaf_with_sleepers(1) else {
            return;
        };
        let pid = kids[0].id();
        let err = enable_subtree_control(&mgr.path, &["memory"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("busy; processes directly in it"), "{err}");
        assert!(err.contains(&pid.to_string()), "{err}");
        mgr.kill_all();
        kids[0].wait().unwrap();
        mgr.cleanup();
    }

    #[test]
    fn test_next_leaf_id_is_unique() {
        let a = next_leaf_id();
        let b = next_leaf_id();
        assert_ne!(a, b);
    }
}

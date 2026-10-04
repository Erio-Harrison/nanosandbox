//! Cgroup v2 management for Linux.
//!
//! Root writes directly under the real cgroup root. A non-root caller needs
//! a *delegated* subtree instead — see `ensure_own_scope`.

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

/// A per-process random value, mixed into every self-owned cgroup/scope name
/// alongside our pid. Names keyed on pid alone can collide with a leftover
/// from a dead process that happened to have the same (recycled) pid and
/// hasn't been swept yet -- not just a narrow timing window, since sweeping
/// is opportunistic, not continuous. Mixing in this nonce doesn't narrow
/// that race, it removes the collision as a possible outcome at all: two
/// different process lifetimes never produce the same name, regardless of
/// pid reuse or sweep timing.
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
    /// Create a new cgroup leaf for a sandbox run, enabling only `needed`
    /// controllers.
    pub fn create(sandbox_id: &str, needed: &[&str]) -> Result<Self> {
        let base = ensure_base(needed)?;
        let path = base.join(sandbox_id);
        fs::create_dir_all(&path).map_err(|e| SandboxError::CgroupCreation {
            context: format!("Failed to create cgroup {sandbox_id}: {e}"),
            source: Some(Box::new(e)),
        })?;
        Ok(Self { path })
    }

    /// Dry run for `check_support()`: fails the same way `create()` would,
    /// but before `build()` returns instead of after `clone()`.
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

        // No memory.high: it used to be set to 90% of the limit, where the
        // kernel throttles the cgroup instead of killing it, so a program
        // using too much mostly ended as a timeout, not an OOM. And no swap:
        // with it, the limit could be exceeded by swapping and the OOM kill
        // never came. Not every kernel has swap accounting; without it,
        // there's no swap to limit here either.
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

    /// Check if any process in the cgroup was killed by OOM. A read failure
    /// here is treated the same as the sibling `get_memory_stats`/
    /// `get_cpu_stats` calls at this same call site (mod.rs): reported as
    /// the "nothing happened" value rather than failing the whole run over
    /// what's normally just a best-effort stats read.
    pub fn was_oom_killed(&self) -> bool {
        self.get_memory_events()
            .map(|e| e.oom_kill > 0 || e.oom_group_kill > 0)
            .unwrap_or(false)
    }

    /// Get all PIDs in this cgroup. `kill_all`/`cleanup` read this in a
    /// retry loop and stop as soon as it's confirmed empty. `None` means
    /// unknown (a non-ENOENT read error), not empty -- a caller treating
    /// that as empty would stop retrying while processes are still alive.
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

    /// Sends SIGKILL to all processes in the cgroup and waits for them to exit.
    pub fn kill_all(&self) {
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
            std::thread::sleep(Duration::from_millis(10));
        }

        let _ = fs::write(&freeze_path, "0");
    }

    /// Kills all processes and removes the cgroup directory.
    pub fn cleanup(&self) {
        self.kill_all();
        for _ in 0..50 {
            if self.get_pids().is_some_and(|p| p.is_empty()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = fs::remove_dir(&self.path);
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

    sweep::sweep_stale_leaves(&base, |name| name.split('-').next(), sweep::owner_is_gone); // Drop doesn't run on SIGKILL/process::exit

    // Last, not first: the sweeps above still need a stale pid's lock file
    // to exist to confirm it via owner_is_gone — removing it any earlier in
    // this same pass would erase that evidence before it's used.
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

/// From `DelegateControllers`, not `Delegate` (`Delegate=pids` reports
/// `true` but only delegates `pids`) or `cgroup.controllers` (shows what
/// the kernel allows, not what was delegated).
fn read_controller_list(path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(path).map_err(|e| SandboxError::CgroupCreation {
        context: format!("cannot read {}: {e}", path.display()),
        source: Some(Box::new(e)),
    })?;
    Ok(content.split_whitespace().map(str::to_string).collect())
}

/// Enables `controllers` in `dir`'s `cgroup.subtree_control`, idempotently.
fn enable_subtree_control(dir: &Path, controllers: &[&str]) -> Result<()> {
    if controllers.is_empty() {
        return Ok(());
    }

    // Concurrent callers in this process most often target the very same
    // shared scope, each independently reading then writing
    // cgroup.subtree_control on its own. With enough of them running at
    // once there's effectively always a write in flight, so a short
    // per-call retry alone keeps losing that race -- confirmed for real:
    // under 20-way concurrency, about half the runs still failed even after
    // 5 retries each. Serializing this process's own callers removes that
    // self-inflicted contention entirely; the retry below still covers
    // genuine cross-process contention (another nanosandbox process
    // sharing this same delegated scope).
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // See sweep_due above: a panic elsewhere while holding this lock must
    // not poison every later caller -- there's no shared data here to be
    // left inconsistent by it, only serialization.
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

    // The kernel serializes subtree_control writes on this cgroup; one
    // landing while another (ours or a concurrent thread/process sharing
    // this same scope) is still being applied can transiently fail with
    // EBUSY, not because anything is actually wrong. Confirmed for real
    // under concurrent sandbox creation sharing one delegated scope. Retry
    // briefly instead of surfacing that as a hard failure.
    let mut last_err = None;
    for attempt in 0..5 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(5 * attempt as u64));
            // Someone else's write may have already covered us.
            let enabled = read_controller_list(&subtree_path)?;
            if missing.iter().all(|c| enabled.iter().any(|e| e == c)) {
                return Ok(());
            }
        }
        match fs::write(&subtree_path, &value) {
            Ok(()) => return Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => last_err = Some(e),
            Err(e) => {
                return Err(SandboxError::CgroupCreation {
                    context: format!("cannot enable '{value}' in {}: {e}", subtree_path.display()),
                    source: Some(Box::new(e)),
                });
            }
        }
    }
    // EBUSY here usually means the no-internal-process rule: something sits
    // directly in `dir` itself. Name it, so the error says who.
    let procs = fs::read_to_string(dir.join("cgroup.procs")).unwrap_or_default();
    let described: Vec<String> = procs
        .split_whitespace()
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
    let last_err = last_err.expect("loop only exits via return or after recording an EBUSY error");
    Err(SandboxError::CgroupCreation {
        context: format!(
            "cannot enable '{value}' in {} (still busy after retries; processes directly in it: [{}]): {}",
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

    #[test]
    fn test_next_leaf_id_is_unique() {
        let a = next_leaf_id();
        let b = next_leaf_id();
        assert_ne!(a, b);
    }
}

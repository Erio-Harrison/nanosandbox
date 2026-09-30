//! Cgroup v2 management for Linux.
//!
//! Root writes directly under the real cgroup root. A non-root caller needs
//! a *delegated* subtree instead — see `ensure_own_scope`.

use crate::error::{Result, SandboxError};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// Shared base for per-sandbox leaves; never holds a process itself.
const NANOSANDBOX_CGROUP: &str = "nanosandbox";

static LEAF_ID: AtomicU64 = AtomicU64::new(0);

/// A fresh, process-unique cgroup leaf id (pid not known yet at this point).
pub fn next_leaf_id() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        LEAF_ID.fetch_add(1, Ordering::Relaxed)
    )
}

/// Memory statistics from cgroup
#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub current: u64,
    pub peak: u64,
}

/// CPU statistics from cgroup
#[derive(Debug, Clone)]
pub struct CpuStats {
    pub total_usec: u64,
    pub user_usec: u64,
    pub system_usec: u64,
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
        fs::create_dir_all(&path).map_err(|e| {
            SandboxError::CgroupCreation(format!("Failed to create cgroup {}: {}", sandbox_id, e))
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
            reason: e.to_string(),
        })?;

        // Also set high limit for soft limit
        let high = (bytes as f64 * 0.9) as u64;
        let high_path = self.path.join("memory.high");
        let _ = fs::write(&high_path, high.to_string());

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
            reason: e.to_string(),
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
            reason: e.to_string(),
        })?;

        Ok(())
    }

    /// Add a process to this cgroup
    pub fn add_process(&self, pid: u32) -> Result<()> {
        let path = self.path.join("cgroup.procs");
        fs::write(&path, pid.to_string()).map_err(|e| {
            SandboxError::CgroupCreation(format!("Failed to add PID {} to cgroup: {}", pid, e))
        })?;

        Ok(())
    }

    /// Get memory statistics
    pub fn get_memory_stats(&self) -> Result<MemoryStats> {
        let current = fs::read_to_string(self.path.join("memory.current"))
            .map_err(|e| SandboxError::Internal(format!("Failed to read memory.current: {}", e)))?
            .trim()
            .parse::<u64>()
            .unwrap_or(0);

        let peak = fs::read_to_string(self.path.join("memory.peak"))
            .map_err(|e| SandboxError::Internal(format!("Failed to read memory.peak: {}", e)))?
            .trim()
            .parse::<u64>()
            .unwrap_or(0);

        Ok(MemoryStats { current, peak })
    }

    /// Get CPU statistics
    pub fn get_cpu_stats(&self) -> Result<CpuStats> {
        let stat = fs::read_to_string(self.path.join("cpu.stat"))
            .map_err(|e| SandboxError::Internal(format!("Failed to read cpu.stat: {}", e)))?;

        let mut usage_usec = 0u64;
        let mut user_usec = 0u64;
        let mut system_usec = 0u64;

        for line in stat.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                match parts[0] {
                    "usage_usec" => usage_usec = parts[1].parse().unwrap_or(0),
                    "user_usec" => user_usec = parts[1].parse().unwrap_or(0),
                    "system_usec" => system_usec = parts[1].parse().unwrap_or(0),
                    _ => {}
                }
            }
        }

        Ok(CpuStats {
            total_usec: usage_usec,
            user_usec,
            system_usec,
        })
    }

    /// Get memory events (for OOM detection)
    pub fn get_memory_events(&self) -> Result<MemoryEvents> {
        let events_path = self.path.join("memory.events");
        let events = fs::read_to_string(&events_path)
            .map_err(|e| SandboxError::Internal(format!("Failed to read memory.events: {}", e)))?;

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

    /// Check if any process in the cgroup was killed by OOM
    pub fn was_oom_killed(&self) -> bool {
        self.get_memory_events()
            .map(|e| e.oom_kill > 0 || e.oom_group_kill > 0)
            .unwrap_or(false)
    }

    /// Get all PIDs in this cgroup
    pub fn get_pids(&self) -> Vec<u32> {
        let procs_path = self.path.join("cgroup.procs");
        fs::read_to_string(&procs_path)
            .map(|s| {
                s.lines()
                    .filter_map(|line| line.trim().parse::<u32>().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Sends SIGKILL to all processes in the cgroup and waits for them to exit.
    pub fn kill_all(&self) {
        let freeze_path = self.path.join("cgroup.freeze");
        let _ = fs::write(&freeze_path, "1"); // block new forks while killing

        for _ in 0..10 {
            let pids = self.get_pids();
            if pids.is_empty() {
                break;
            }
            for pid in &pids {
                unsafe {
                    libc::kill(*pid as i32, libc::SIGKILL);
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let _ = fs::write(&freeze_path, "0");
    }

    /// Get the cgroup path
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Kills all processes and removes the cgroup directory.
    pub fn cleanup(&self) {
        self.kill_all();
        for _ in 0..50 {
            if self.get_pids().is_empty() {
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
    hold_instance_lock();
    let scope = ensure_own_scope()?;
    let root_owned = scope == Path::new(CGROUP_ROOT);

    enable_subtree_control(&scope, needed)?;

    let base = scope.join(NANOSANDBOX_CGROUP);
    if base.exists() {
        if !safe_to_build_under(&base) {
            return Err(SandboxError::CgroupCreation(format!(
                "{} already exists and holds a process we don't recognize as our own — refusing \
                 to build sandbox cgroups there in case it belongs to something else",
                base.display()
            )));
        }
    } else {
        fs::create_dir_all(&base).map_err(|e| {
            SandboxError::CgroupCreation(format!(
                "Failed to create base cgroup {}: {e}",
                base.display()
            ))
        })?;
    }

    let available = read_controller_list(&base.join("cgroup.controllers"))?;
    for controller in needed {
        if !available.iter().any(|c| c == controller) {
            return Err(SandboxError::CgroupCreation(if root_owned {
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
            }));
        }
    }

    enable_subtree_control(&base, needed)?;

    sweep_stale_leaves(&base, |name| name.split('-').next(), owner_is_gone); // Drop doesn't run on SIGKILL/process::exit

    // Last, not first: sweep_stale_scopes/sweep_stale_leaves above still need
    // a stale pid's lock file to exist to confirm it via owner_is_gone —
    // removing it any earlier in this same pass would erase that evidence
    // before it's used.
    static LOCKS_SWEPT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    LOCKS_SWEPT.get_or_init(|| {
        if let Some(dir) = lock_dir() {
            sweep_stale_locks(&dir);
        }
    });

    Ok(base)
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// The cgroup this process may build `nanosandbox/` under: the real root
/// for euid 0, or a cgroup v2 scope we're fully delegated (reused from the
/// caller, or a fresh `Delegate=true` one — see `compute_own_scope`).
/// Resolved and cached once per process.
fn ensure_own_scope() -> Result<PathBuf> {
    if is_root() {
        return Ok(PathBuf::from(CGROUP_ROOT));
    }
    static SCOPE: std::sync::OnceLock<std::result::Result<PathBuf, String>> =
        std::sync::OnceLock::new();
    SCOPE
        .get_or_init(compute_own_scope)
        .clone()
        .map_err(SandboxError::CgroupCreation)
}

/// Every controller nanosandbox might enable for a sandbox run.
const ALL_CONTROLLERS: &[&str] = &["memory", "cpu", "pids"];

/// `app.slice` is uid-writable but not delegated (`Delegate=no`), so we
/// need our own `Delegate=true` unit. If the caller already put us inside
/// one, reuse it (checked over D-Bus, not by writability) rather than
/// silently escaping whatever limits or lifecycle management they set up;
/// otherwise relocate into a fresh scope, warning if that leaves a limit
/// behind.
fn compute_own_scope() -> std::result::Result<PathBuf, String> {
    let uid = unsafe { libc::getuid() };
    let target = user_app_slice(CGROUP_ROOT, uid);
    if !target.is_dir() {
        return Err(format!(
            "{} does not exist; resource limits need an active systemd user session for uid \
             {uid} (an interactive login normally starts one; a non-interactive one — a plain \
             `su`/`sudo -u`, some containers — may not; `loginctl enable-linger` keeps a \
             session's delegation alive without an active login)",
            target.display()
        ));
    }

    // A process that never shares its scope with anyone (the common,
    // unwrapped case) has no other invocation that would ever revisit it
    // via the leaf sweeps below — only a scan of `target` itself catches a
    // killed one's own dedicated scope.
    sweep_stale_scopes(&target);

    let governing = governing_unit();

    let usable = governing.as_ref().is_some_and(|unit| {
        current_unit_is_exclusively_ours(unit)
            && current_unit_delegated_controllers(unit).is_some_and(|delegated| {
                ALL_CONTROLLERS.iter().all(|c| delegated.iter().any(|d| d == c))
            })
    });

    let own = if usable {
        governing.expect("usable implies governing.is_some()").root
    } else {
        let mut preferred_slice = None;
        if let Some(unit) = &governing {
            warn_if_leaving_resource_limits_behind(unit);
            preferred_slice = unit_property(unit, "Slice").and_then(|v| String::try_from(v).ok());
        }
        relocate_into_delegated_scope(preferred_slice.as_deref()).map_err(|e| e.to_string())?;
        own_cgroup_path().map_err(|e| e.to_string())?
    };

    sweep_stale_leaves(&own, |name| name.strip_prefix("nanosandbox-supervisor-"), owner_is_gone);

    // Pid-suffixed leaf so `own`'s own root never holds a process directly
    // (required before its subtree_control can be enabled), and two
    // processes reusing the same unit don't collide.
    let supervisor = own.join(format!("nanosandbox-supervisor-{}", std::process::id()));
    fs::create_dir_all(&supervisor)
        .map_err(|e| format!("cannot create {}: {e}", supervisor.display()))?;
    if !safe_to_build_under(&supervisor) {
        return Err(format!(
            "{} already exists and holds a process other than this one — refusing to join it \
             in case it belongs to something else",
            supervisor.display()
        ));
    }
    fs::write(supervisor.join("cgroup.procs"), std::process::id().to_string())
        .map_err(|e| format!("cannot move into {}: {e}", supervisor.display()))?;

    Ok(own)
}

/// The systemd unit (scope or service) governing this process's cgroup,
/// found via `GetUnitByPID` rather than guessed from our own cgroup path —
/// that guess breaks under `DelegateSubgroup=`, where the unit's main
/// process lives one level below its own root.
struct GoverningUnit {
    root: PathBuf,
    object_path: zbus::zvariant::OwnedObjectPath,
    interface: &'static str,
}

fn governing_unit() -> Option<GoverningUnit> {
    use zbus::blocking::connection::Builder as ConnectionBuilder;
    use zbus::blocking::Proxy;
    use zbus::zvariant::{OwnedObjectPath, OwnedValue};

    let conn = ConnectionBuilder::session()
        .ok()?
        .method_timeout(Duration::from_secs(5))
        .build()
        .ok()?;
    let manager = Proxy::new(
        &conn,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .ok()?;
    let object_path: OwnedObjectPath =
        manager.call("GetUnitByPID", &(std::process::id(),)).ok()?;

    let props = Proxy::new(
        &conn,
        "org.freedesktop.systemd1",
        &object_path,
        "org.freedesktop.DBus.Properties",
    )
    .ok()?;
    // `Id` (e.g. "foo.scope") is on the generic `Unit` interface; its
    // suffix picks the interface `ControlGroup` actually lives on below.
    let id: OwnedValue = props.call("Get", &("org.freedesktop.systemd1.Unit", "Id")).ok()?;
    let id = String::try_from(id).ok()?;
    let interface = if id.ends_with(".scope") {
        "org.freedesktop.systemd1.Scope"
    } else if id.ends_with(".service") {
        "org.freedesktop.systemd1.Service"
    } else {
        return None;
    };

    let control_group: OwnedValue = props.call("Get", &(interface, "ControlGroup")).ok()?;
    drop(props);
    let control_group = String::try_from(control_group).ok()?;

    let mut root = PathBuf::from(CGROUP_ROOT);
    root.extend(control_group.split('/').filter(|s| !s.is_empty()));

    Some(GoverningUnit { root, object_path, interface })
}

/// Required before `subtree_control` can be enabled (no-internal-process
/// rule). An empty root (e.g. `DelegateSubgroup=`) counts as fine.
fn current_unit_is_exclusively_ours(unit: &GoverningUnit) -> bool {
    let Ok(procs) = fs::read_to_string(unit.root.join("cgroup.procs")) else {
        return false;
    };
    only_us_or_empty(&procs)
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

/// Best-effort removal of entries under `dir` whose pid (from `pid_of`) is
/// confirmed gone by `owner_is_gone`. Leftovers from a kill or
/// `std::process::exit`, neither of which run our `Drop`.
fn sweep_stale_leaves(
    dir: &Path,
    pid_of: impl Fn(&str) -> Option<&str>,
    owner_is_gone: impl Fn(u32) -> bool,
) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name.to_str().and_then(&pid_of) else { continue };
        let Ok(pid) = pid_str.parse::<u32>() else { continue };
        if pid == std::process::id() || !owner_is_gone(pid) {
            continue;
        }
        let leaf = entry.path();
        kill_cgroup_atomically(&leaf);
        let _ = fs::remove_dir(&leaf);
    }
}

/// Reaps sibling `nanosandbox-<pid>.scope` units directly under `target`
/// whose owner is confirmed gone: killing empties their cgroup, and
/// systemd's own `CollectMode=inactive-or-failed` notices and removes the
/// unit — its cgroup is systemd's to manage, not ours to `rmdir`.
fn sweep_stale_scopes(target: &Path) {
    let Ok(entries) = fs::read_dir(target) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name
            .to_str()
            .and_then(|n| n.strip_prefix("nanosandbox-"))
            .and_then(|n| n.strip_suffix(".scope"))
        else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else { continue };
        if pid == std::process::id() || !owner_is_gone(pid) {
            continue;
        }
        kill_cgroup_atomically(&entry.path());
    }
}

/// Holds an exclusive `flock` on `$XDG_RUNTIME_DIR/nanosandbox-<pid>.lock`
/// for this process's entire lifetime — released, by the kernel, however
/// this process ends. Used (via `owner_is_gone`) instead of checking
/// `/proc/<pid>`: a pid can belong to an unrelated live process in another
/// pid namespace, or the original process can have legitimately exited
/// while a child it spawned keeps running — either way, killing based on
/// `/proc` alone risks killing something we don't own.
fn hold_instance_lock() {
    let Some(dir) = lock_dir() else { return };
    static LOCK: std::sync::OnceLock<Option<std::fs::File>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| lock_file(&dir, std::process::id()));
}

/// `$XDG_RUNTIME_DIR`, or — since root doesn't otherwise have one (a
/// `sudo`/cron/system-service root has no systemd user session at all) —
/// a root-owned directory under `/run` with the same boot-scoped lifetime.
fn lock_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Some(PathBuf::from(dir));
    }
    if is_root() {
        let dir = PathBuf::from("/run/nanosandbox-locks");
        fs::create_dir_all(&dir).ok()?;
        return Some(dir);
    }
    None
}

/// Opens (creating if needed) and non-blockingly `flock`s `dir`'s lock file
/// for `pid`, returning it locked on success.
fn lock_file(dir: &Path, pid: u32) -> Option<std::fs::File> {
    use std::os::unix::io::AsRawFd;
    let file = std::fs::File::create(dir.join(format!("nanosandbox-{pid}.lock"))).ok()?;
    (unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0).then_some(file)
}

/// Whether `pid`'s lock file in `dir` is confirmed released — i.e. we could
/// take it ourselves. A missing file (unknown state) conservatively counts
/// as *not* gone: better to miss a cleanup than kill something we can't
/// confirm is ours.
fn owner_is_gone_in(dir: &Path, pid: u32) -> bool {
    use std::os::unix::io::AsRawFd;
    let Ok(file) = std::fs::File::open(dir.join(format!("nanosandbox-{pid}.lock"))) else {
        return false;
    };
    let fd = file.as_raw_fd();
    let acquired = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if acquired {
        unsafe { libc::flock(fd, libc::LOCK_UN) };
    }
    acquired
}

fn owner_is_gone(pid: u32) -> bool {
    match lock_dir() {
        Some(dir) => owner_is_gone_in(&dir, pid),
        None => false,
    }
}

/// Removes lock files in `dir` whose owner is confirmed gone. A process
/// that exits cleanly leaves no leaf or scope behind for the other sweeps
/// to ever match its pid against again — without this, its lock file
/// would otherwise never be revisited or removed by anything.
fn sweep_stale_locks(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name
            .to_str()
            .and_then(|n| n.strip_prefix("nanosandbox-"))
            .and_then(|n| n.strip_suffix(".lock"))
        else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else { continue };
        if pid != std::process::id() && owner_is_gone_in(dir, pid) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Atomically kills every process in `dir` (`cgroup.kill`, kernel ≥ 5.14 —
/// avoids the read-then-kill race of a process forking in between) and
/// waits for it to take effect.
fn kill_cgroup_atomically(dir: &Path) {
    if fs::write(dir.join("cgroup.kill"), "1").is_err() {
        return;
    }
    for _ in 0..50 {
        match fs::read_to_string(dir.join("cgroup.events")) {
            Ok(events) if events.lines().any(|l| l.trim() == "populated 0") => return,
            Err(_) => return,
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

/// From `DelegateControllers`, not `Delegate` (`Delegate=pids` reports
/// `true` but only delegates `pids`) or `cgroup.controllers` (shows what
/// the kernel allows, not what was delegated).
fn current_unit_delegated_controllers(unit: &GoverningUnit) -> Option<Vec<String>> {
    Vec::<String>::try_from(unit_property(unit, "DelegateControllers")?).ok()
}

/// Warns about a `MemoryMax`/`CPUQuota` we're about to leave behind.
/// `TasksMax` isn't checked: its "unset" value is a real number, not
/// infinity, so it would warn on nearly every unit.
fn warn_if_leaving_resource_limits_behind(unit: &GoverningUnit) {
    const INFINITY: u64 = u64::MAX;
    for (prop, label) in [
        ("MemoryMax", "a MemoryMax"),
        ("CPUQuotaPerSecUSec", "a CPUQuota"),
    ] {
        if let Some(value) = unit_property(unit, prop).and_then(|v| u64::try_from(v).ok()) {
            if value != INFINITY {
                tracing::warn!(
                    "this process is inside {} ({label} of its own), but nanosandbox could \
                     not confirm that unit delegates every cgroup controller it needs (or \
                     that unit's own root cgroup holds other processes nanosandbox doesn't \
                     control) — moving into a separate scope of its own, which will no \
                     longer be subject to {label} set there. Add `Delegate=yes` to that unit \
                     (and, if it has its own main process, `DelegateSubgroup=` — see \
                     systemd.resource-control(5)) if you want the sandboxed process to \
                     remain inside it and count against its limits.",
                    unit.root.display()
                );
            }
        }
    }
}

fn unit_property(unit: &GoverningUnit, property: &str) -> Option<zbus::zvariant::OwnedValue> {
    use zbus::blocking::connection::Builder as ConnectionBuilder;
    use zbus::blocking::Proxy;

    let conn = ConnectionBuilder::session()
        .ok()?
        .method_timeout(Duration::from_secs(5))
        .build()
        .ok()?;
    let props = Proxy::new(
        &conn,
        "org.freedesktop.systemd1",
        &unit.object_path,
        "org.freedesktop.DBus.Properties",
    )
    .ok()?;
    props.call("Get", &(unit.interface, property)).ok()
}

/// systemd's conventional cgroup for `--user` scopes and services.
fn user_app_slice(cgroup_root: &str, uid: u32) -> PathBuf {
    PathBuf::from(cgroup_root)
        .join("user.slice")
        .join(format!("user-{uid}.slice"))
        .join(format!("user@{uid}.service"))
        .join("app.slice")
}

/// Reads this process's own cgroup v2 path from `/proc/self/cgroup`.
fn own_cgroup_path() -> Result<PathBuf> {
    let raw = fs::read_to_string("/proc/self/cgroup")
        .map_err(|e| SandboxError::CgroupCreation(format!("cannot read /proc/self/cgroup: {e}")))?;
    let rel = raw
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            SandboxError::CgroupCreation(
                "not a unified cgroup v2 hierarchy (no '0::' line in /proc/self/cgroup)".into(),
            )
        })?
        .trim();
    let mut acc = PathBuf::from(CGROUP_ROOT);
    acc.extend(rel.split('/').filter(|s| !s.is_empty()));
    Ok(acc)
}

/// Asks systemd, over D-Bus, to move this process into a fresh
/// `Delegate=true` scope — only the delegater can place the first process
/// into a delegated subtree. Attempted once per process; cached.
fn relocate_into_delegated_scope(preferred_slice: Option<&str>) -> Result<()> {
    static RESULT: std::sync::OnceLock<std::result::Result<(), String>> =
        std::sync::OnceLock::new();
    RESULT
        .get_or_init(|| try_relocate_into_delegated_scope(preferred_slice))
        .clone()
        .map_err(SandboxError::CgroupCreation)
}

fn try_relocate_into_delegated_scope(preferred_slice: Option<&str>) -> std::result::Result<(), String> {
    use zbus::blocking::connection::Builder as ConnectionBuilder;
    use zbus::blocking::Proxy;
    use zbus::zvariant::{OwnedObjectPath, Value};

    // Bounded: a wedged systemd manager can otherwise block this forever.
    let conn = ConnectionBuilder::session()
        .and_then(|b| b.method_timeout(Duration::from_secs(5)).build())
        .map_err(|e| format!("cannot reach session D-Bus: {e}"))?;
    let proxy = Proxy::new(
        &conn,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .map_err(|e| format!("cannot reach systemd over D-Bus: {e}"))?;

    let pid = std::process::id();
    let scope_name = format!("nanosandbox-{pid}.scope");
    let pids: &[u32] = &[pid];
    let mut properties: Vec<(&str, Value)> = vec![
        ("PIDs", Value::new(pids)),
        ("Delegate", Value::new(true)),
        ("CollectMode", Value::new("inactive-or-failed")),
    ];
    if let Some(slice) = preferred_slice {
        properties.push(("Slice", Value::new(slice)));
    }
    let properties = properties.as_slice();
    let aux: &[(&str, &[(&str, Value)])] = &[];

    let call_result = proxy.call::<_, _, OwnedObjectPath>(
        "StartTransientUnit",
        &(scope_name.as_str(), "fail", properties, aux),
    );

    // Poll regardless of call success: systemd's job may still complete
    // after our own wait for a reply timed out.
    for _ in 0..50 {
        if let Ok(rel) = own_cgroup_path() {
            if rel.ends_with(&scope_name) {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    match call_result {
        Ok(_) => Err(format!(
            "StartTransientUnit for {scope_name} returned but this process never moved into it"
        )),
        Err(e) => Err(format!("StartTransientUnit failed: {e}")),
    }
}

fn read_controller_list(path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)
        .map_err(|e| SandboxError::CgroupCreation(format!("cannot read {}: {e}", path.display())))?;
    Ok(content.split_whitespace().map(str::to_string).collect())
}

/// Enables `controllers` in `dir`'s `cgroup.subtree_control`, idempotently.
fn enable_subtree_control(dir: &Path, controllers: &[&str]) -> Result<()> {
    if controllers.is_empty() {
        return Ok(());
    }
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
    fs::write(&subtree_path, &value).map_err(|e| {
        SandboxError::CgroupCreation(format!(
            "cannot enable '{value}' in {}: {e}",
            subtree_path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Makes a plain test directory reject new files, standing in for a
    /// real cgroup leaf with no `cgroup.kill` to write (a real cgroup
    /// directory's write there never adds a dirent; a tempdir's would).
    fn make_readonly(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o555)).unwrap();
    }

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

    #[test]
    fn builds_the_conventional_systemd_delegation_path() {
        let path = user_app_slice("/sys/fs/cgroup", 1000);
        assert_eq!(
            path,
            PathBuf::from(
                "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice"
            )
        );
    }

    #[test]
    fn uid_appears_in_both_slice_segments() {
        let path = user_app_slice("/sys/fs/cgroup", 501);
        let s = path.to_string_lossy();
        assert!(s.contains("user-501.slice"), "{s}");
        assert!(s.contains("user@501.service"), "{s}");
    }

    #[test]
    fn owner_is_gone_reflects_whether_the_lock_is_held() {
        let locks = tempfile::tempdir().unwrap();
        let pid = 424_242;

        assert!(!owner_is_gone_in(locks.path(), pid), "no lock file at all -> unknown, not gone");

        let held = lock_file(locks.path(), pid).unwrap();
        assert!(!owner_is_gone_in(locks.path(), pid), "lock held -> not gone");

        drop(held);
        assert!(owner_is_gone_in(locks.path(), pid), "lock released -> gone");
    }

    #[test]
    fn sweep_stale_locks_removes_only_released_locks() {
        let locks = tempfile::tempdir().unwrap();
        let (alive_pid, dead_pid) = (555_555, 424_242);

        let _held = lock_file(locks.path(), alive_pid).unwrap();
        drop(lock_file(locks.path(), dead_pid).unwrap());

        sweep_stale_locks(locks.path());

        assert!(locks.path().join(format!("nanosandbox-{alive_pid}.lock")).exists());
        assert!(!locks.path().join(format!("nanosandbox-{dead_pid}.lock")).exists());
    }

    #[test]
    fn sweep_removes_only_leaves_whose_owner_lock_is_released() {
        let dir = tempfile::tempdir().unwrap();
        let locks = tempfile::tempdir().unwrap();
        let (alive_pid, dead_pid, unknown_pid) = (555_555, 424_242, 999_999);

        let _held = lock_file(locks.path(), alive_pid).unwrap();
        drop(lock_file(locks.path(), dead_pid).unwrap()); // acquired then released

        let our_leaf = dir.path().join(format!("nanosandbox-supervisor-{}", std::process::id()));
        let alive_leaf = dir.path().join(format!("nanosandbox-supervisor-{alive_pid}"));
        let dead_leaf = dir.path().join(format!("nanosandbox-supervisor-{dead_pid}"));
        let unknown_leaf = dir.path().join(format!("nanosandbox-supervisor-{unknown_pid}"));
        let unrelated = dir.path().join("something-else");
        for p in [&our_leaf, &alive_leaf, &dead_leaf, &unknown_leaf, &unrelated] {
            fs::create_dir(p).unwrap();
        }
        make_readonly(&dead_leaf); // no real cgroup.kill here to write instead

        sweep_stale_leaves(
            dir.path(),
            |name| name.strip_prefix("nanosandbox-supervisor-"),
            |pid| owner_is_gone_in(locks.path(), pid),
        );

        assert!(our_leaf.exists(), "must not remove our own leaf");
        assert!(alive_leaf.exists(), "must not remove a leaf whose owner still holds its lock");
        assert!(unknown_leaf.exists(), "no lock file at all must not be removed");
        assert!(unrelated.exists(), "must not touch unrelated entries");
        assert!(!dead_leaf.exists(), "must remove a leaf whose owner's lock is released");
    }

    #[test]
    fn sweep_matches_the_sandbox_leaf_naming_scheme_too() {
        let dir = tempfile::tempdir().unwrap();
        let locks = tempfile::tempdir().unwrap();
        let dead_pid = 424_242;
        drop(lock_file(locks.path(), dead_pid).unwrap());

        let our_leaf = dir.path().join(format!("{}-0", std::process::id()));
        let dead_leaf = dir.path().join(format!("{dead_pid}-0"));
        for p in [&our_leaf, &dead_leaf] {
            fs::create_dir(p).unwrap();
        }
        make_readonly(&dead_leaf);

        sweep_stale_leaves(
            dir.path(),
            |name| name.split('-').next(),
            |pid| owner_is_gone_in(locks.path(), pid),
        );

        assert!(our_leaf.exists());
        assert!(!dead_leaf.exists());
    }
}

//! Finds or builds the cgroup v2 scope to put `nanosandbox/` under: the real root for euid 0,
//! else a systemd-delegated subtree (over D-Bus).

use crate::error::{Result, SandboxError};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use super::CGROUP_ROOT;

/// The cgroup we may build `nanosandbox/` under: real root for euid 0, or a delegated scope
/// (reused or fresh; see `compute_own_scope`). Resolved once per process.
pub(super) fn ensure_own_scope() -> Result<PathBuf> {
    if super::is_root() {
        return Ok(PathBuf::from(CGROUP_ROOT));
    }
    static SCOPE: std::sync::OnceLock<std::result::Result<PathBuf, String>> =
        std::sync::OnceLock::new();
    SCOPE
        .get_or_init(compute_own_scope)
        .clone()
        .map_err(|context| SandboxError::CgroupCreation {
            context,
            source: None,
        })
}

/// Every controller nanosandbox might enable for a sandbox run.
const ALL_CONTROLLERS: &[&str] = &["memory", "cpu", "pids"];

/// `app.slice` isn't delegated, so we need our own `Delegate=true` unit. A scope the caller
/// put us in is reused (checked over D-Bus) to keep their limits; else relocate into a fresh
/// one, warning if that leaves a limit behind.
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

    let governing = governing_unit();

    let usable = governing.as_ref().is_some_and(|unit| {
        current_unit_is_exclusively_ours(unit)
            && current_unit_delegated_controllers(unit).is_some_and(|delegated| {
                ALL_CONTROLLERS
                    .iter()
                    .all(|c| delegated.iter().any(|d| d == c))
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
        // Flattened to String: the result is cached in SCOPE and cloned, and SandboxError's
        // trait-object source can't be Clone. Only the .source() chain is lost.
        relocate_into_delegated_scope(preferred_slice.as_deref()).map_err(|e| e.to_string())?;
        own_cgroup_path().map_err(|e| e.to_string())?
    };

    // Pid- and nonce-suffixed leaf so `own`'s root holds no process (required for
    // subtree_control) and reused units/pids don't collide. Swept from ensure_base, not here.
    let supervisor = own.join(format!(
        "nanosandbox-supervisor-{}-{:08x}",
        std::process::id(),
        super::process_nonce()
    ));
    fs::create_dir_all(&supervisor)
        .map_err(|e| format!("cannot create {}: {e}", supervisor.display()))?;
    if !super::safe_to_build_under(&supervisor) {
        return Err(format!(
            "{} already exists and holds a process other than this one — refusing to join it \
             in case it belongs to something else",
            supervisor.display()
        ));
    }
    fs::write(
        supervisor.join("cgroup.procs"),
        std::process::id().to_string(),
    )
    .map_err(|e| format!("cannot move into {}: {e}", supervisor.display()))?;

    // Children forked between landing in `own` and the move above stay behind and block
    // enabling `own`'s controllers (EBUSY). Later children inherit `supervisor`, so one pass suffices.
    let leftovers = fs::read_to_string(own.join("cgroup.procs")).unwrap_or_default();
    for pid in leftovers.split_whitespace() {
        // Already exited between the read and the write is fine.
        let _ = fs::write(supervisor.join("cgroup.procs"), pid);
    }

    Ok(own)
}

/// The systemd unit governing this process's cgroup, via `GetUnitByPID`: guessing from our
/// cgroup path breaks under `DelegateSubgroup=`.
struct GoverningUnit {
    root: PathBuf,
    object_path: zbus::zvariant::OwnedObjectPath,
    interface: &'static str,
}

fn governing_unit() -> Option<GoverningUnit> {
    use zbus::blocking::Proxy;
    use zbus::blocking::connection::Builder as ConnectionBuilder;
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
    let object_path: OwnedObjectPath = manager.call("GetUnitByPID", &(std::process::id(),)).ok()?;

    let props = Proxy::new(
        &conn,
        "org.freedesktop.systemd1",
        &object_path,
        "org.freedesktop.DBus.Properties",
    )
    .ok()?;
    // `Id` is on the generic `Unit` interface; its suffix picks the interface for `ControlGroup`.
    let id: OwnedValue = props
        .call("Get", &("org.freedesktop.systemd1.Unit", "Id"))
        .ok()?;
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

    Some(GoverningUnit {
        root,
        object_path,
        interface,
    })
}

/// Required before `subtree_control` can be enabled (no-internal-process rule). Empty root is fine.
fn current_unit_is_exclusively_ours(unit: &GoverningUnit) -> bool {
    let Ok(procs) = fs::read_to_string(unit.root.join("cgroup.procs")) else {
        return false;
    };
    super::only_us_or_empty(&procs)
}

/// From `DelegateControllers`: `Delegate` is true for `Delegate=pids`, and
/// `cgroup.controllers` shows kernel-allowed, not delegated.
fn current_unit_delegated_controllers(unit: &GoverningUnit) -> Option<Vec<String>> {
    Vec::<String>::try_from(unit_property(unit, "DelegateControllers")?).ok()
}

/// Warns about a `MemoryMax`/`CPUQuota` we'd leave behind. `TasksMax` isn't checked: its
/// unset value is a real number, so it would warn on nearly every unit.
fn warn_if_leaving_resource_limits_behind(unit: &GoverningUnit) {
    const INFINITY: u64 = u64::MAX;
    for (prop, label) in [
        ("MemoryMax", "a MemoryMax"),
        ("CPUQuotaPerSecUSec", "a CPUQuota"),
    ] {
        if let Some(value) = unit_property(unit, prop).and_then(|v| u64::try_from(v).ok())
            && value != INFINITY
        {
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

fn unit_property(unit: &GoverningUnit, property: &str) -> Option<zbus::zvariant::OwnedValue> {
    use zbus::blocking::Proxy;
    use zbus::blocking::connection::Builder as ConnectionBuilder;

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
pub(super) fn user_app_slice(cgroup_root: &str, uid: u32) -> PathBuf {
    PathBuf::from(cgroup_root)
        .join("user.slice")
        .join(format!("user-{uid}.slice"))
        .join(format!("user@{uid}.service"))
        .join("app.slice")
}

/// Reads this process's own cgroup v2 path from `/proc/self/cgroup`.
fn own_cgroup_path() -> Result<PathBuf> {
    let raw =
        fs::read_to_string("/proc/self/cgroup").map_err(|e| SandboxError::CgroupCreation {
            context: format!("cannot read /proc/self/cgroup: {e}"),
            source: Some(Box::new(e)),
        })?;
    let rel = raw
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| SandboxError::CgroupCreation {
            context: "not a unified cgroup v2 hierarchy (no '0::' line in /proc/self/cgroup)"
                .into(),
            source: None,
        })?
        .trim();
    let mut acc = PathBuf::from(CGROUP_ROOT);
    acc.extend(rel.split('/').filter(|s| !s.is_empty()));
    Ok(acc)
}

/// Asks systemd over D-Bus to move us into a fresh `Delegate=true` scope (only the delegater
/// can place the first process). Once per process; cached.
fn relocate_into_delegated_scope(preferred_slice: Option<&str>) -> Result<()> {
    static RESULT: std::sync::OnceLock<std::result::Result<(), String>> =
        std::sync::OnceLock::new();
    RESULT
        .get_or_init(|| try_relocate_into_delegated_scope(preferred_slice))
        .clone()
        .map_err(|context| SandboxError::CgroupCreation {
            context,
            source: None,
        })
}

fn try_relocate_into_delegated_scope(
    preferred_slice: Option<&str>,
) -> std::result::Result<(), String> {
    use zbus::blocking::Proxy;
    use zbus::blocking::connection::Builder as ConnectionBuilder;
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
    // Nonce-suffixed (see process_nonce()) so a stale same-pid scope can't fail StartTransientUnit.
    let scope_name = format!("nanosandbox-{pid}-{:08x}.scope", super::process_nonce());
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

    // Poll regardless: the job may complete after our reply wait timed out.
    for _ in 0..50 {
        if let Ok(rel) = own_cgroup_path()
            && rel.ends_with(&scope_name)
        {
            return Ok(());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_conventional_systemd_delegation_path() {
        let path = user_app_slice("/sys/fs/cgroup", 1000);
        assert_eq!(
            path,
            PathBuf::from("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice")
        );
    }

    #[test]
    fn uid_appears_in_both_slice_segments() {
        let path = user_app_slice("/sys/fs/cgroup", 501);
        let s = path.to_string_lossy();
        assert!(s.contains("user-501.slice"), "{s}");
        assert!(s.contains("user@501.service"), "{s}");
    }
}

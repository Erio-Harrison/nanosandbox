//! Finding, or building, the cgroup v2 scope this process may write
//! `nanosandbox/` under: the real root for euid 0, or (via systemd, over
//! D-Bus) a delegated subtree for everyone else.

use crate::error::{Result, SandboxError};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use super::CGROUP_ROOT;

/// The cgroup this process may build `nanosandbox/` under: the real root
/// for euid 0, or a cgroup v2 scope we're fully delegated (reused from the
/// caller, or a fresh `Delegate=true` one — see `compute_own_scope`).
/// Resolved and cached once per process.
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
        // Flattened to a String here, not kept as the SandboxError these
        // return: this whole function's result is cached in SCOPE (above)
        // and `.clone()`d on every call, and a trait-object source inside
        // SandboxError can't be Clone. The message text survives intact;
        // only the structured .source() chain is lost at this one boundary.
        relocate_into_delegated_scope(preferred_slice.as_deref()).map_err(|e| e.to_string())?;
        own_cgroup_path().map_err(|e| e.to_string())?
    };

    // Pid- and nonce-suffixed leaf so `own`'s own root never holds a process
    // directly (required before its subtree_control can be enabled), and
    // two processes reusing the same unit — or the same recycled pid —
    // don't collide. Swept periodically from ensure_base, not here: this
    // runs on every call, not just the first, so a stale sibling doesn't
    // wait for this process to restart before it's noticed.
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

    // Anything still directly in `own` is a child this process forked
    // between landing in `own` (StartTransientUnit, or already there) and
    // the move above -- e.g. a sandbox run that needs no cgroup and so never
    // waits on this function. Such a child stays put after we move, and
    // blocks enabling `own`'s controllers (EBUSY) until it exits. Confirmed
    // for real: a `sleep` child of this process, sitting in `own`'s root.
    // Children forked after our own move inherit `supervisor`, so one pass
    // here is enough.
    let leftovers = fs::read_to_string(own.join("cgroup.procs")).unwrap_or_default();
    for pid in leftovers.split_whitespace() {
        // Already exited between the read and the write is fine.
        let _ = fs::write(supervisor.join("cgroup.procs"), pid);
    }

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
    // `Id` (e.g. "foo.scope") is on the generic `Unit` interface; its
    // suffix picks the interface `ControlGroup` actually lives on below.
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

/// Required before `subtree_control` can be enabled (no-internal-process
/// rule). An empty root (e.g. `DelegateSubgroup=`) counts as fine.
fn current_unit_is_exclusively_ours(unit: &GoverningUnit) -> bool {
    let Ok(procs) = fs::read_to_string(unit.root.join("cgroup.procs")) else {
        return false;
    };
    super::only_us_or_empty(&procs)
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

/// Asks systemd, over D-Bus, to move this process into a fresh
/// `Delegate=true` scope — only the delegater can place the first process
/// into a delegated subtree. Attempted once per process; cached.
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
    // Nonce-suffixed (see process_nonce()) so a name collision with a
    // not-yet-swept scope from a dead process that had the same recycled
    // pid can't make this StartTransientUnit call fail.
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

    // Poll regardless of call success: systemd's job may still complete
    // after our own wait for a reply timed out.
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

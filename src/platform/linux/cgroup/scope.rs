//! Finds or builds the cgroup v2 scope to put `nanosandbox/` under: the real root for euid 0,
//! else a systemd-delegated subtree (over D-Bus).

use crate::error::{Result, SandboxError};
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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

/// `app.slice` isn't delegated, so we need our own `Delegate=true` unit: always a fresh scope,
/// in the slice of the unit we're in, with that unit's own limits copied to it.
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

    // Never the unit we're in, even when it is delegated: this process sits in its root, and
    // its controllers can be enabled only once no process is directly in it. A process of ours
    // forked there just before we left may still be exiting, which a newer kernel (7.0) neither
    // lists nor tells the end of, yet counts. A fresh scope's root never holds this process, so
    // the question doesn't arise (see `relocate_into_delegated_scope`).
    let governing = governing_unit();
    let (slice, limits) = match &governing {
        Some(unit) => (
            unit_property(unit, "Slice").and_then(|v| String::try_from(v).ok()),
            inherited_limits(unit),
        ),
        None => (None, Vec::new()),
    };
    relocate_into_delegated_scope(slice.as_deref(), &limits)
}

/// Enables what `own` offers of every controller a run may need, while its root is known to be
/// empty, rather than when some later run first needs one.
fn enable_root_controllers(own: &Path) -> std::result::Result<(), String> {
    let offered = fs::read_to_string(own.join("cgroup.controllers")).unwrap_or_default();
    let enable: Vec<&str> = ALL_CONTROLLERS
        .iter()
        .copied()
        .filter(|c| offered.split_whitespace().any(|o| o == *c))
        .collect();
    super::enable_subtree_control(own, &enable).map_err(|e| e.to_string())
}

/// Pid- and nonce-suffixed leaf of `own` for this process, so `own`'s root can hold none and
/// reused units/pids don't collide. Swept from ensure_base, not here.
fn make_supervisor(own: &Path) -> std::result::Result<PathBuf, String> {
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
    Ok(supervisor)
}

/// The longest the placeholder's exit may take: a bound for a broken kernel state, not part of
/// the normal order (it exits as soon as its pipe closes).
const EXIT_GUARD: Duration = Duration::from_secs(5);

/// Whether `fd` turns readable by `deadline`.
fn readable_by(fd: &OwnedFd, deadline: Instant) -> bool {
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let ms = crate::platform::checks::poll_timeout_ms(Some(deadline), Instant::now());
        let n = unsafe { libc::poll(&mut pfd, 1, ms) };
        if n > 0 {
            return true;
        }
        if n == 0 || unsafe { *libc::__errno_location() } != libc::EINTR {
            return false;
        }
    }
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

/// The unit's own `MemoryMax`, `CPUQuota` and `TasksMax`, for the fresh scope: the sandboxes
/// stay under the limits the caller set, though as the scope's own budget, no longer shared
/// with the unit's other processes. Unset ones (infinity) are left out.
fn inherited_limits(unit: &GoverningUnit) -> Vec<(&'static str, u64)> {
    const INFINITY: u64 = u64::MAX;
    let limits: Vec<(&'static str, u64)> = ["MemoryMax", "CPUQuotaPerSecUSec", "TasksMax"]
        .into_iter()
        .filter_map(|prop| {
            let value = u64::try_from(unit_property(unit, prop)?).ok()?;
            (value != INFINITY).then_some((prop, value))
        })
        .collect();
    if !limits.is_empty() {
        tracing::info!(
            "nanosandbox runs in a scope of its own; the limits of {} ({}) are copied to it, \
             as its own budget rather than a share of that unit's",
            unit.root.display(),
            limits
                .iter()
                .map(|(p, v)| format!("{p}={v}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    limits
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

/// A process of ours that the fresh scope is made with, so that this process never sits in
/// the scope's root: it goes straight into its leaf (`AttachProcessesToUnit`). Single-threaded
/// and never forking, it only waits for its pipe to close. Made by a raw clone() of this
/// (multi-threaded) process, so it runs nothing but raw syscalls (see `child.rs`).
struct Placeholder {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    release: Option<OwnedFd>,
}

impl Placeholder {
    fn start() -> std::result::Result<Self, String> {
        let (hold, release) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
            .map_err(|e| format!("cannot make the placeholder's pipe: {e}"))?;
        let hold_fd = hold.as_raw_fd();
        let pid = unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD as libc::c_long, 0i64) };
        if pid == 0 {
            // The placeholder. Its first act: drop every descriptor but its end of the pipe, or
            // it would hold other runs' pipes open (a reader would never see EOF).
            unsafe {
                if hold_fd > 0 {
                    libc::syscall(libc::SYS_close_range, 0u32, (hold_fd - 1) as u32, 0i32);
                }
                libc::syscall(libc::SYS_close_range, (hold_fd + 1) as u32, u32::MAX, 0i32);
                let mut byte = 0u8;
                libc::syscall(libc::SYS_read, hold_fd, &mut byte as *mut u8, 1usize);
                // Async-signal-safe: straight to exit_group, no atexit, no lock.
                libc::_exit(0);
            }
        }
        if pid < 0 {
            return Err(format!(
                "cannot start the scope's placeholder process: {}",
                std::io::Error::last_os_error()
            ));
        }
        drop(hold);
        let pid = pid as libc::pid_t;
        let fd =
            unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0 as libc::c_long) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            drop(release); // it exits
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
            return Err(format!("cannot open the placeholder's pidfd: {err}"));
        }
        Ok(Self {
            pid,
            pidfd: unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) },
            release: Some(release),
        })
    }
}

impl Drop for Placeholder {
    /// It exits as its pipe closes; its pidfd says when it is gone, whatever this process does
    /// with SIGCHLD, and then it is reaped unless something else already did.
    fn drop(&mut self) {
        self.release.take();
        readable_by(&self.pidfd, Instant::now() + EXIT_GUARD);
        unsafe {
            libc::waitpid(self.pid, std::ptr::null_mut(), libc::WNOHANG);
        }
    }
}

/// The cgroup v2 path of `pid` (`self` for this process), from `/proc/<pid>/cgroup`.
fn cgroup_path_of(pid: &str) -> std::result::Result<PathBuf, String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|e| format!("cannot read /proc/{pid}/cgroup: {e}"))?;
    let rel = raw
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or("not a unified cgroup v2 hierarchy (no '0::' line in /proc/<pid>/cgroup)")?
        .trim();
    let mut acc = PathBuf::from(CGROUP_ROOT);
    acc.extend(rel.split('/').filter(|s| !s.is_empty()));
    Ok(acc)
}

/// Asks systemd over D-Bus for a fresh `Delegate=true` scope (only the delegater can place the
/// first process in it) and moves this process into a leaf of it, never into its root: the
/// scope is made with a placeholder process, and this one is attached straight to the leaf.
/// The root's controllers are enabled while it is empty. Returns the scope's root; the
/// placeholder exits, in the leaf, when this returns.
fn relocate_into_delegated_scope(
    preferred_slice: Option<&str>,
    limits: &[(&'static str, u64)],
) -> std::result::Result<PathBuf, String> {
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

    let placeholder = Placeholder::start()?;
    // Nonce-suffixed (see process_nonce()) so a stale same-pid scope can't fail StartTransientUnit.
    let scope_name = format!(
        "nanosandbox-{}-{:08x}.scope",
        std::process::id(),
        super::process_nonce()
    );
    let pids: &[u32] = &[placeholder.pid as u32];
    let mut properties: Vec<(&str, Value)> = vec![
        ("PIDs", Value::new(pids)),
        ("Delegate", Value::new(true)),
        ("CollectMode", Value::new("inactive-or-failed")),
    ];
    if let Some(slice) = preferred_slice {
        properties.push(("Slice", Value::new(slice)));
    }
    for (prop, value) in limits {
        properties.push((prop, Value::new(*value)));
    }
    let properties = properties.as_slice();
    let aux: &[(&str, &[(&str, Value)])] = &[];

    // Subscribed before the call, so the job's end can't be missed (systemd sends job signals
    // only to clients that subscribed). `StartTransientUnit` returns once the job is queued,
    // not once this process is in the scope.
    let _ = proxy.call::<_, _, ()>("Subscribe", &());
    let jobs = proxy
        .receive_signal_with_args("JobRemoved", &[(2, scope_name.as_str())])
        .map_err(|e| format!("cannot listen for systemd's job signals: {e}"))?;
    let (ended_tx, ended_rx) = std::sync::mpsc::channel::<String>();
    // A thread, as the signal iterator can't wait with a deadline. It ends with the job's
    // signal; if none ever comes it stays parked on the bus, once per process.
    let _ = std::thread::Builder::new()
        .name("nanosandbox-scope-job".into())
        .spawn(move || {
            for message in jobs {
                if let Ok((_, _, _, result)) = message
                    .body()
                    .deserialize::<(u32, OwnedObjectPath, String, String)>()
                {
                    let _ = ended_tx.send(result);
                    return;
                }
            }
        });

    let call_result = proxy.call::<_, _, OwnedObjectPath>(
        "StartTransientUnit",
        &(scope_name.as_str(), "fail", properties, aux),
    );

    let placeholder_pid = placeholder.pid.to_string();
    let in_scope = || cgroup_path_of(&placeholder_pid).is_ok_and(|p| p.ends_with(&scope_name));
    // The job may complete after our reply wait timed out, so a failed call is waited on too,
    // but not for long: there may be no job at all.
    let wait = if call_result.is_ok() {
        JOB_WAIT
    } else {
        FAILED_CALL_WAIT
    };
    if !in_scope() {
        match ended_rx.recv_timeout(wait) {
            Ok(result) if result != "done" => {
                return Err(format!(
                    "StartTransientUnit for {scope_name}: systemd's job ended '{result}'"
                ));
            }
            _ => {}
        }
    }
    if !in_scope() {
        return Err(match call_result {
            Ok(_) => format!(
                "StartTransientUnit for {scope_name} returned but its placeholder never moved into it"
            ),
            Err(e) => format!("StartTransientUnit failed: {e}"),
        });
    }

    let own = cgroup_path_of(&placeholder_pid)?;
    let supervisor = make_supervisor(&own)?;
    // The root's only process is the placeholder, alive: moved, it is out at once (a moving
    // task can't be half there, unlike an exiting one, which a newer kernel no longer lists but
    // still counts). The empty root then takes its controllers, before this process arrives.
    fs::write(supervisor.join("cgroup.procs"), &placeholder_pid).map_err(|e| {
        format!(
            "cannot move the placeholder into {}: {e}",
            supervisor.display()
        )
    })?;
    if cgroup_path_of(&placeholder_pid)? != supervisor {
        return Err(format!(
            "the placeholder did not move into {}",
            supervisor.display()
        ));
    }
    enable_root_controllers(&own)?;
    let leaf = format!(
        "/{}",
        supervisor
            .file_name()
            .expect("the supervisor is a leaf of own")
            .to_string_lossy()
    );
    // The whole thread group moves at once: a fork racing it is born either where this process
    // was, or in the leaf; never in the root.
    let this: &[u32] = &[std::process::id()];
    proxy
        .call::<_, _, ()>(
            "AttachProcessesToUnit",
            &(scope_name.as_str(), leaf.as_str(), this),
        )
        .map_err(|e| format!("cannot attach this process to {scope_name}{leaf}: {e}"))?;
    if cgroup_path_of("self")? != supervisor {
        return Err(format!(
            "AttachProcessesToUnit returned but this process is not in {}",
            supervisor.display()
        ));
    }
    Ok(own)
}

/// How long to wait for systemd's signal that the scope's job ended, once the call returned.
/// It comes within milliseconds; this only bounds a systemd that never sends it.
const JOB_WAIT: Duration = Duration::from_secs(5);
/// The same after a call that failed (its job, if any, is one the reply wait timed out on).
const FAILED_CALL_WAIT: Duration = Duration::from_millis(500);

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

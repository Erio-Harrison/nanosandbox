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

    // Controllers can be enabled in `own`'s root only once no process is directly in it, and a
    // process is born where its parent is. A fresh scope never holds this process in its root
    // (see `relocate_into_delegated_scope`); a reused unit does, so this process moves out and
    // whatever it forked meanwhile is moved or waited for (`empty_the_root`).
    let (own, supervisor) = if usable {
        let own = governing.expect("usable implies governing.is_some()").root;
        let supervisor = make_supervisor(&own)?;
        fs::write(
            supervisor.join("cgroup.procs"),
            std::process::id().to_string(),
        )
        .map_err(|e| format!("cannot move into {}: {e}", supervisor.display()))?;
        (own, supervisor)
    } else {
        let mut preferred_slice = None;
        if let Some(unit) = &governing {
            warn_if_leaving_resource_limits_behind(unit);
            preferred_slice = unit_property(unit, "Slice").and_then(|v| String::try_from(v).ok());
        }
        relocate_into_delegated_scope(preferred_slice.as_deref())?
    };
    empty_the_root(&own, &supervisor)?;

    // Enable what `own` offers of every controller a run may need, while its root is known to
    // be empty, rather than when some later run first needs one.
    let offered = fs::read_to_string(own.join("cgroup.controllers")).unwrap_or_default();
    let enable: Vec<&str> = ALL_CONTROLLERS
        .iter()
        .copied()
        .filter(|c| offered.split_whitespace().any(|o| o == *c))
        .collect();
    super::enable_subtree_control(&own, &enable).map_err(|e| e.to_string())?;

    Ok(own)
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

/// The longest a process stuck in its own exit (uninterruptible, a sick filesystem) may hold
/// up emptying a root: a bound for a broken kernel state, not part of the normal order.
const EXIT_GUARD: Duration = Duration::from_secs(5);

/// Moves every process out of `root` into `into`. The kernel moves a live process at once but
/// skips one in its exit (it is still counted in `root`); that one is waited for on its pidfd,
/// which turns readable only once it has left its cgroup.
fn empty_the_root(root: &Path, into: &Path) -> std::result::Result<(), String> {
    let deadline = Instant::now() + EXIT_GUARD;
    loop {
        let pids = super::pids_in(root);
        if pids.is_empty() {
            return Ok(());
        }
        for pid in &pids {
            match fs::write(into.join("cgroup.procs"), pid.to_string()) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {} // gone
                Err(e) => {
                    return Err(format!(
                        "cannot move process {pid} out of {} into {}: {e}",
                        root.display(),
                        into.display()
                    ));
                }
            }
        }
        for pid in super::pids_in(root) {
            if !wait_until_exited(pid, deadline) {
                return Err(format!(
                    "process {pid} in {} could not be moved and did not finish exiting",
                    root.display()
                ));
            }
        }
    }
}

/// Whether `pid` has exited by `deadline`, waiting on its pidfd. One already gone counts.
fn wait_until_exited(pid: u32, deadline: Instant) -> bool {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0 as libc::c_long) };
    if fd < 0 {
        return unsafe { *libc::__errno_location() } == libc::ESRCH;
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
    readable_by(&fd, deadline)
}

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
/// Returns the scope's root and the leaf; the root's only process is the placeholder, which
/// exits when this returns.
fn relocate_into_delegated_scope(
    preferred_slice: Option<&str>,
) -> std::result::Result<(PathBuf, PathBuf), String> {
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
    drop(placeholder); // exits; `empty_the_root` finds nothing else to wait for
    Ok((own, supervisor))
}

/// How long to wait for systemd's signal that the scope's job ended, once the call returned.
/// It comes within milliseconds; this only bounds a systemd that never sends it.
const JOB_WAIT: Duration = Duration::from_secs(5);
/// The same after a call that failed (its job, if any, is one the reply wait timed out on).
const FAILED_CALL_WAIT: Duration = Duration::from_millis(500);

#[cfg(test)]
mod tests {
    use super::*;

    /// Live processes are moved out; one killed just before (a big one, so its exit takes a
    /// while) can't be, and is waited for until it has left. Then the root takes controllers.
    #[test]
    fn test_emptying_a_root_moves_the_live_and_waits_for_the_exiting() {
        use std::process::Command;
        let leaf = |name: &str| super::super::CgroupManager::create(name, &["memory"]).ok();
        let id = super::super::next_leaf_id();
        let (Some(root), Some(into)) = (leaf(&format!("{id}-root")), leaf(&format!("{id}-into")))
        else {
            return;
        };
        let mut live: Vec<_> = (0..3)
            .map(|_| Command::new("sleep").arg("30").spawn().unwrap())
            .collect();
        let mut dying = Command::new("python3")
            .args(["-c", "b = bytearray(1 << 30)\nfor i in range(0, len(b), 4096): b[i] = 1\nprint(flush=True)\nimport time; time.sleep(30)"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        for kid in live.iter().chain(std::iter::once(&dying)) {
            root.add_process(kid.id()).unwrap();
        }
        // Wait until it has touched its gigabyte, then kill it: its exit frees that memory.
        let mut line = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(dying.stdout.take().unwrap()),
            &mut line,
        )
        .unwrap();
        unsafe { libc::kill(dying.id() as libc::pid_t, libc::SIGKILL) };

        let emptied = empty_the_root(&root.path, &into.path);
        let left = super::super::pids_in(&root.path);
        let takes = fs::write(root.path.join("cgroup.subtree_control"), "+memory");

        for kid in &mut live {
            let _ = kid.kill();
            let _ = kid.wait();
        }
        let _ = dying.wait();
        let _ = fs::write(root.path.join("cgroup.subtree_control"), "-memory");
        into.cleanup();
        root.cleanup();
        assert_eq!(emptied, Ok(()));
        assert!(left.is_empty(), "{left:?}");
        assert!(takes.is_ok(), "{takes:?}");
    }

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

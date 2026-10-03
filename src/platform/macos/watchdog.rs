//! Kills a run's process group if the host process dies before the run
//! finishes. macOS has nothing like Linux's `PR_SET_PDEATHSIG`; this is the
//! substitute.
//!
//! A pipe's write end, held open only by this process (`O_CLOEXEC`, so
//! nothing we spawn gets a copy). The kernel closes it, with every other fd
//! this process holds, the moment this process exits for any reason --
//! crash or `SIGKILL` included. A plain `/bin/sh`, given the read end as its
//! stdin, blocks reading a line from it; losing the write end unblocks that
//! with EOF, and it kills the run's process group and exits. `Drop` closes
//! the write end on an ordinary run end too (indistinguishable from the host
//! dying), so the same kill fires then -- harmless, since the group is
//! already gone.
//!
//! The shell is reached by fork then immediate exec, no code of ours in
//! between: a child running our code first, instead of exec'ing right away,
//! could hang on a lock another thread held at the moment of the fork (see
//! `envp_cstr` in `platform/linux/mod.rs`). That's also why this doesn't use
//! `run_marker`'s `sandbox_check`-based search: that needs calls between
//! fork and exec that aren't known to be safe there.

use crate::error::{Result, SandboxError};
use std::os::unix::io::{FromRawFd, OwnedFd};
use std::process::{Child, Command, Stdio};

/// Guards one run. Dropping it (on every path out of `execute()`, success or
/// error) closes its pipe and waits for the shell to act on that and exit,
/// so it's never left as a zombie.
pub(super) struct Watchdog {
    write_end: Option<OwnedFd>,
    shell: Child,
}

impl Watchdog {
    /// `pgid`: the run's process group -- its first process is its own
    /// leader (`setpgid(0, 0)` in `pre_exec`), so this is that process's pid.
    pub(super) fn spawn(pgid: i32) -> Result<Self> {
        let (read_end, write_end) = cloexec_pipe()?;

        // `read` returns on EOF too, so either way the script moves on to
        // the kill -- a no-op if the group's already gone.
        let script = format!("read -r _; kill -KILL -- -{pgid} 2>/dev/null; exit 0");
        let shell = {
            // Held for the fork; see super::FORK_LOCK.
            let _fork = super::FORK_LOCK.read().unwrap_or_else(|e| e.into_inner());
            Command::new("/bin/sh")
                .arg("-c")
                .arg(&script)
                .stdin(Stdio::from(read_end))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| SandboxError::ExecutionFailed(format!("spawn watchdog: {e}")))?
        };
        Ok(Self {
            write_end: Some(write_end),
            shell,
        })
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        // Closing this is what the shell is waiting on; it wakes and exits
        // right away, so the wait() below is a short, bounded block, not an
        // open-ended one, and leaves no zombie.
        self.write_end.take();
        let _ = self.shell.wait();
    }
}

/// A pipe whose fds are `O_CLOEXEC`, so neither leaks into a child spawned
/// after this call -- including the watchdog shell, which only keeps its
/// `dup2`'d stdin copy (dup2 never carries the flag) across its own exec.
/// No `pipe2` on macOS, so the flag is set right after `pipe()` instead,
/// with `FORK_LOCK` held for writing so no other fork in this crate can
/// land in that gap (see its doc comment).
fn cloexec_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let _fork = super::FORK_LOCK.write().unwrap_or_else(|e| e.into_inner());
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(SandboxError::Internal(format!(
            "create watchdog pipe: {}",
            std::io::Error::last_os_error()
        )));
    }
    for fd in fds {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(SandboxError::Internal(format!(
                "set close-on-exec on watchdog pipe: {err}"
            )));
        }
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    /// Whether a process is still there. Only ever called on pids this test
    /// itself spawned, never on a shared or guessed one.
    fn alive(pid: i32) -> bool {
        unsafe { libc::kill(pid, 0) == 0 }
    }

    /// A child that is its own process group leader, the way `execute()`'s
    /// `pre_exec` makes the sandboxed process -- so its pid doubles as its
    /// pgid, and killing `-pid` reaches only it (and anything it forks),
    /// never the test process's own group.
    fn own_group(script: &str) -> Child {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(script).stdout(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn().unwrap()
    }

    /// Dropping the Watchdog kills only the pgid it was given, never
    /// anything else, including a reused pid: a process in an unrelated
    /// group, spawned after the Watchdog's target has already exited and
    /// been reaped, survives the drop.
    #[test]
    fn test_drop_touches_only_its_own_pgid() {
        let mut dead_target = own_group("true");
        let pgid = dead_target.id() as i32;
        dead_target.wait().unwrap(); // exited and reaped: pgid is free

        let mut unrelated = own_group("sleep 5");
        let watchdog = Watchdog::spawn(pgid).unwrap();
        drop(watchdog);

        assert!(
            alive(unrelated.id() as i32),
            "an unrelated process was killed"
        );
        let _ = unrelated.kill();
        let _ = unrelated.wait();
    }

    /// The host process dying is simulated here by dropping the write end
    /// directly, which is exactly what losing the host does to the shell's
    /// end of the pipe: it can't tell the two apart.
    #[test]
    fn test_losing_the_write_end_kills_the_group() {
        let mut group = own_group("echo ready; sleep 30");
        let pgid = group.id() as i32;

        let mut watchdog = Watchdog::spawn(pgid).unwrap();
        // Wait for the group's process to be running before pulling the
        // rug out from under it.
        use std::io::Read;
        let mut line = [0u8; 6]; // "ready\n"
        group.stdout.take().unwrap().read_exact(&mut line).unwrap();

        watchdog.write_end.take();
        // try_wait() reaps it as soon as it's dead; kill(pid, 0) can't tell
        // a zombie from one still running, so it wouldn't do here.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut dead = false;
        while std::time::Instant::now() < deadline {
            if matches!(group.try_wait(), Ok(Some(_))) {
                dead = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let _ = group.wait();
        let _ = watchdog.shell.wait();
        assert!(dead, "the group outlived the watchdog's pipe closing");
    }

    /// cloexec_pipe()'s pipe()+fcntl() gap, raced tightly against another
    /// fork from a different thread that takes FORK_LOCK for reading the
    /// same way the two production spawn sites do: without that read lock
    /// in the way, a fork landing in the gap gets a non-cloexec copy of the
    /// pipe, leaking it into the other process and silently defeating that
    /// run's watchdog (confirmed separately: about 1 in 5 tries, tight
    /// loop). Each "other" child reports, via its own stdout, any pipe fd
    /// in its own `/dev/fd` outside the standard three -- never acting on
    /// what it finds beyond that.
    ///
    /// The racer needs a `pre_exec`: without one, `Command::spawn()` can
    /// take a `posix_spawn` fast path on macOS that this race doesn't reach.
    /// `execute()`'s own sandboxed-command spawn always has one (`setpgid`),
    /// so this matches the real risk, not a weaker one. And the pipe side
    /// has to keep going for as long as the racer does, not run its own
    /// fixed count: it's so much cheaper per iteration (no fork at all)
    /// that a fixed count finished before the racer was even a few forks in,
    /// leaving almost nothing to actually overlap with.
    #[test]
    fn test_fork_lock_closes_the_pipe_leak() {
        let iterations = 300;
        let leaks = std::sync::atomic::AtomicUsize::new(0);
        let done = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Ok((r, w)) = cloexec_pipe() {
                        drop(r);
                        drop(w);
                    }
                }
            });
            for _ in 0..iterations {
                let out = {
                    let _fork = super::super::FORK_LOCK
                        .read()
                        .unwrap_or_else(|e| e.into_inner());
                    let mut command = Command::new("/bin/sh");
                    command.arg("-c").arg(
                        "for f in /dev/fd/*; do \
                           case \"$f\" in */0|*/1|*/2) continue;; esac; \
                           [ -p \"$f\" ] && echo LEAK; \
                         done",
                    );
                    unsafe {
                        command.pre_exec(|| Ok(()));
                    }
                    command.output().unwrap()
                };
                if !out.stdout.is_empty() {
                    leaks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            done.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        assert_eq!(leaks.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}

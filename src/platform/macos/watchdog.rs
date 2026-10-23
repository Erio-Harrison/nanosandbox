//! Kills a run's process group if the host dies first (macOS has no `PR_SET_PDEATHSIG`).
//!
//! The host holds a `O_CLOEXEC` pipe's write end; a `/bin/sh` reading the other end gets EOF
//! when the host exits for any reason (including SIGKILL) or `Drop` closes it, then kills the group.
//! The shell is spawned fork+exec with no code in between: running our code after fork could
//! hang on a lock another thread held (see `envp_cstr` in `platform/linux/mod.rs`), which is
//! also why this doesn't use `run_marker`.

use crate::error::{Result, SandboxError};
use std::os::unix::io::OwnedFd;
use std::process::{Child, Command, Stdio};

/// Guards one run; dropping it closes the pipe and reaps the shell.
pub(super) struct Watchdog {
    write_end: Option<OwnedFd>,
    shell: Child,
}

impl Watchdog {
    /// `pgid`: the run's process group, i.e. its first process's pid (`setsid()` in `pre_exec`).
    pub(super) fn spawn(pgid: i32) -> Result<Self> {
        let (read_end, write_end) = super::cloexec_pipe("watchdog")?;

        // `read` returns on EOF too; the kill is a no-op if the group is already gone.
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
                .map_err(|e| SandboxError::ExecutionFailed {
                    context: "spawn watchdog".into(),
                    source: Box::new(e),
                })?
        };
        Ok(Self {
            write_end: Some(write_end),
            shell,
        })
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        // Wakes the shell, so the wait() below is short and leaves no zombie.
        self.write_end.take();
        let _ = self.shell.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    /// Only called on pids this test spawned.
    fn alive(pid: i32) -> bool {
        unsafe { libc::kill(pid, 0) == 0 }
    }

    /// A child that is its own group leader, so killing `-pid` reaches only it.
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

    /// Dropping kills only the given pgid, not an unrelated group (e.g. a reused pid).
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

    /// Dropping the write end simulates host death; the shell can't tell them apart.
    #[test]
    fn test_losing_the_write_end_kills_the_group() {
        let mut group = own_group("echo ready; sleep 30");
        let pgid = group.id() as i32;

        let mut watchdog = Watchdog::spawn(pgid).unwrap();
        // Wait until the group's process is running.
        use std::io::Read;
        let mut line = [0u8; 6]; // "ready\n"
        group.stdout.take().unwrap().read_exact(&mut line).unwrap();

        watchdog.write_end.take();
        // try_wait() reaps; kill(pid, 0) can't tell a zombie from a live process.
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

    // Races cloexec_pipe()'s pipe()+fcntl() gap against another thread's fork under FORK_LOCK
    // (read side, as the production spawn sites take it); without the lock a fork in the gap leaks
    // the pipe into another run (seen ~1 in 5). The racer needs a `pre_exec`, else spawn() may take
    // a posix_spawn fast path the race doesn't reach. The pipe side loops as long as the racer.
    /// Pipe fds (other than 0/1/2) open in a fresh `/bin/sh`: some CI runners (GitHub Actions
    /// macOS) leak an ambient one, which isn't a watchdog leak.
    fn open_pipe_fds() -> std::collections::HashSet<String> {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(
            "for f in /dev/fd/*; do \
               case \"$f\" in */0|*/1|*/2) continue;; esac; \
               [ -p \"$f\" ] && basename \"$f\"; \
             done",
        );
        unsafe {
            command.pre_exec(|| Ok(()));
        }
        let out = command.output().unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn test_fork_lock_closes_the_pipe_leak() {
        let iterations = 300;
        let baseline = open_pipe_fds();
        let leaks = std::sync::atomic::AtomicUsize::new(0);
        let done = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Ok((r, w)) = super::super::cloexec_pipe("watchdog") {
                        drop(r);
                        drop(w);
                    }
                }
            });
            for _ in 0..iterations {
                let fds = {
                    let _fork = super::super::FORK_LOCK
                        .read()
                        .unwrap_or_else(|e| e.into_inner());
                    open_pipe_fds()
                };
                if fds.difference(&baseline).next().is_some() {
                    leaks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            done.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        assert_eq!(leaks.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}

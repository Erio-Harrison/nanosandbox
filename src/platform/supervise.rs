//! One supervisor thread per run: it starts the command, enforces its limits, kills and cleans
//! up, and reports how it ended. The caller keeps only the I/O ends (`Launched`) and reads them
//! at its own pace; `collect` is how `run()` does that.
//!
//! The command is started on the thread, not just watched by it: Linux ties the parent-death
//! signal to the thread that cloned the child, and this one lives exactly as long as the run.

use crate::error::{Result, SandboxError};
use crate::platform::output::Captured;
use crate::result::ExecutionResult;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How a run ended, from its supervisor.
pub(crate) struct Outcome {
    pub(crate) exit_code: i32,
    pub(crate) signal: Option<i32>,
    pub(crate) killed_by_timeout: bool,
    pub(crate) killed_by_oom: bool,
    pub(crate) killed_by_tmp_limit: bool,
    pub(crate) killed_by_cpu_limit: bool,
    pub(crate) peak_memory: Option<u64>,
    pub(crate) cpu_time: Option<Duration>,
    pub(crate) proc_isolated: bool,
    pub(crate) network_refusals: Vec<crate::result::NetworkRefusal>,
}

/// The caller's ends of a started command.
pub(crate) struct Handles {
    pub(crate) stdin: Option<OwnedFd>,
    pub(crate) stdout: Option<OwnedFd>,
    pub(crate) stderr: Option<OwnedFd>,
    /// Host pid of the run's first process.
    pub(crate) pid: u32,
    /// With a PTY: a handle on its master, for resizing.
    pub(crate) pty: Option<OwnedFd>,
}

/// What `launch` is asked to connect the command to.
#[derive(Clone, Copy)]
pub(crate) struct Io {
    /// A pipe for stdin (else `/dev/null`).
    pub(crate) stdin: bool,
    /// A pseudo-terminal of this many rows and columns as stdin, stdout and stderr.
    pub(crate) pty: Option<(u16, u16)>,
}

/// A started run: its I/O ends and its supervisor.
pub(crate) struct Launched {
    pub(crate) stdin: Option<OwnedFd>,
    pub(crate) stdout: Option<OwnedFd>,
    pub(crate) stderr: Option<OwnedFd>,
    pub(crate) pid: u32,
    pub(crate) pty: Option<OwnedFd>,
    pub(crate) supervisor: Supervisor,
    pub(crate) start: Instant,
}

/// The thread watching a run. Dropping it kills the run and waits for the cleanup.
pub(crate) struct Supervisor {
    pid: u32,
    /// Read end of a pipe the thread holds: EOF once the outcome is in, so it can be polled.
    done: OwnedFd,
    /// `None` inside: the launch failed (its error went to the caller).
    thread: Option<JoinHandle<Option<Result<Outcome>>>>,
}

impl Supervisor {
    /// Runs `launch` on a new thread; it returns the handles to hand back and the closure that
    /// then supervises the run to its end on that same thread.
    pub(crate) fn start<L, S>(launch: L) -> Result<Launched>
    where
        L: FnOnce() -> Result<(Handles, S)> + Send + 'static,
        S: FnOnce() -> Result<Outcome>,
    {
        let start = Instant::now();
        let (done_read, done_write) = crate::platform::cloexec_pipe("run done")?;
        let (tx, rx) = mpsc::sync_channel::<Result<Handles>>(1);
        let thread = std::thread::Builder::new()
            .name("nanosandbox-run".into())
            .spawn(move || {
                let _done = done_write; // closed however this thread ends
                match launch() {
                    Ok((handles, supervise)) => {
                        let _ = tx.send(Ok(handles));
                        Some(supervise())
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        None
                    }
                }
            })
            .map_err(|e| SandboxError::Internal {
                context: "spawn the run's supervisor thread".into(),
                source: Box::new(e),
            })?;
        let handles = match rx.recv() {
            Ok(Ok(handles)) => handles,
            Ok(Err(e)) => {
                let _ = thread.join();
                return Err(e);
            }
            // Panicked before reporting.
            Err(_) => {
                return Err(SandboxError::Internal {
                    context: "start the command".into(),
                    source: Box::new(std::io::Error::other(panic_message(thread.join()))),
                });
            }
        };
        Ok(Launched {
            stdin: handles.stdin,
            stdout: handles.stdout,
            stderr: handles.stderr,
            pid: handles.pid,
            pty: handles.pty,
            supervisor: Supervisor {
                pid: handles.pid,
                done: done_read,
                thread: Some(thread),
            },
            start,
        })
    }

    /// Readable (EOF) once the run has ended and been cleaned up.
    pub(crate) fn done_fd(&self) -> RawFd {
        self.done.as_raw_fd()
    }

    /// SIGKILL to the run's first process and its group; the supervisor sees the exit and does
    /// the rest (on Linux the first process is PID-ns init, so its death takes everything).
    pub(crate) fn kill(&self) {
        let pid = self.pid as libc::pid_t;
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::kill(-pid, libc::SIGKILL);
        }
    }

    /// Whether the run has ended and been cleaned up.
    pub(crate) fn is_done(&self) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.done.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&mut pfd, 1, 0) > 0 }
    }

    /// Blocks until the run has ended and been cleaned up.
    pub(crate) fn wait(mut self) -> Result<Outcome> {
        self.join()
    }

    fn join(&mut self) -> Result<Outcome> {
        let Some(thread) = self.thread.take() else {
            return Err(SandboxError::Internal {
                context: "wait for the run".into(),
                source: Box::new(std::io::Error::other("already waited for")),
            });
        };
        match thread.join() {
            Ok(Some(outcome)) => outcome,
            Ok(None) => Err(SandboxError::Internal {
                context: "wait for the run".into(),
                source: Box::new(std::io::Error::other("the command never started")),
            }),
            Err(panic) => Err(SandboxError::Internal {
                context: "supervise the run".into(),
                source: Box::new(std::io::Error::other(panic_message::<()>(Err(panic)))),
            }),
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.kill();
            let _ = self.join();
        }
    }
}

fn panic_message<T>(joined: std::thread::Result<T>) -> String {
    match joined {
        Ok(_) => "the supervisor thread ended early".into(),
        Err(payload) => payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "the supervisor thread panicked".into()),
    }
}

/// An `ExecutionResult` from what was captured and how the run ended.
pub(crate) fn finish(
    outcome: Outcome,
    [stdout, stderr]: [Captured; 2],
    duration: Duration,
) -> ExecutionResult {
    ExecutionResult {
        output_truncated: stdout.truncated() || stderr.truncated(),
        stdout: stdout.into_string(),
        stderr: stderr.into_string(),
        exit_code: outcome.exit_code,
        duration,
        killed_by_timeout: outcome.killed_by_timeout,
        killed_by_oom: outcome.killed_by_oom,
        killed_by_tmp_limit: outcome.killed_by_tmp_limit,
        killed_by_cpu_limit: outcome.killed_by_cpu_limit,
        signal: outcome.signal,
        peak_memory: outcome.peak_memory,
        cpu_time: outcome.cpu_time,
        blocked_hosts: crate::result::NetworkRefusal::blocked_hosts(&outcome.network_refusals),
        network_refusals: outcome.network_refusals,
        proc_isolated: outcome.proc_isolated,
    }
}

pub(crate) fn set_nonblocking(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

/// Reads from a non-blocking `fd` until it would block. False on EOF or error.
pub(crate) fn drain(fd: RawFd, out: &mut Captured) -> bool {
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n > 0 {
            out.push(&buf[..n as usize]);
            continue;
        }
        if n == 0 {
            return false;
        }
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EAGAIN) => true,
            Some(libc::EINTR) => continue,
            _ => false,
        };
    }
}

/// `run()`'s consumer: feeds `stdin`, captures both streams up to `max_output` each, and
/// returns once the supervisor is done. Nothing here wakes on a timer: the supervisor's `done`
/// pipe ends the loop.
pub(crate) fn collect(
    launched: Launched,
    stdin: Option<&[u8]>,
    max_output: u64,
) -> Result<ExecutionResult> {
    let Launched {
        stdin: stdin_fd,
        stdout,
        stderr,
        supervisor,
        start,
        ..
    } = launched;
    let mut streams = [stdout, stderr];
    let mut captured = [Captured::new(max_output), Captured::new(max_output)];
    // No data for a stdin pipe: closed right away, EOF for the program.
    let mut stdin = stdin_fd.zip(stdin).filter(|(_, data)| !data.is_empty());

    let mut poller = Poller::new()?;
    for fd in streams.iter().flatten() {
        set_nonblocking(fd.as_raw_fd());
        poller.watch_read(fd.as_raw_fd())?;
    }
    if let Some((fd, _)) = &stdin {
        set_nonblocking(fd.as_raw_fd());
        poller.watch_write(fd.as_raw_fd())?;
    }
    let done = supervisor.done_fd();
    poller.watch_read(done)?;

    loop {
        let (readable, writable) = poller.wait(None)?;

        // Interleaved with draining: writing all stdin first deadlocks against a program (e.g.
        // `cat`) blocked on its full output pipe.
        if let Some((fd, data)) = &mut stdin
            && writable.contains(&fd.as_raw_fd())
        {
            let n = unsafe { libc::write(fd.as_raw_fd(), data.as_ptr() as *const _, data.len()) };
            match n {
                n if n > 0 => *data = &data[n as usize..],
                _ if matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EAGAIN | libc::EINTR)
                ) => {}
                // Wrote 0 or reader gone (EPIPE): stop.
                _ => *data = &[],
            }
            if data.is_empty() {
                poller.unwatch(fd.as_raw_fd());
                stdin = None; // dropping it closes the pipe: EOF for the program
            }
        }

        for (stream, out) in streams.iter_mut().zip(captured.iter_mut()) {
            if let Some(fd) = stream
                && readable.contains(&fd.as_raw_fd())
                && !drain(fd.as_raw_fd(), out)
            {
                poller.unwatch(fd.as_raw_fd());
                *stream = None;
            }
        }

        if readable.contains(&done) {
            // Whatever is buffered now; a leftover the cleanup gave up on may hold a pipe open,
            // so not to EOF.
            for (stream, out) in streams.iter().zip(captured.iter_mut()) {
                if let Some(fd) = stream {
                    drain(fd.as_raw_fd(), out);
                }
            }
            break;
        }
    }
    let outcome = supervisor.wait()?;
    Ok(finish(outcome, captured, start.elapsed()))
}

/// Readiness of a few fds: `poll` on Linux, kqueue on macOS (whose `poll` can't take a pty).
#[cfg(target_os = "linux")]
pub(crate) struct Poller {
    read: Vec<RawFd>,
    write: Vec<RawFd>,
}

#[cfg(target_os = "linux")]
impl Poller {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            read: Vec::new(),
            write: Vec::new(),
        })
    }

    pub(crate) fn watch_read(&mut self, fd: RawFd) -> Result<()> {
        self.read.push(fd);
        Ok(())
    }

    pub(crate) fn watch_write(&mut self, fd: RawFd) -> Result<()> {
        self.write.push(fd);
        Ok(())
    }

    pub(crate) fn unwatch(&mut self, fd: RawFd) {
        self.read.retain(|&f| f != fd);
        self.write.retain(|&f| f != fd);
    }

    /// Fds ready to read and to write. An EOF or error counts as readable.
    pub(crate) fn wait(&self, timeout: Option<Duration>) -> Result<(Vec<RawFd>, Vec<RawFd>)> {
        let mut polled: Vec<libc::pollfd> = self
            .read
            .iter()
            .map(|&fd| (fd, libc::POLLIN))
            .chain(self.write.iter().map(|&fd| (fd, libc::POLLOUT)))
            .map(|(fd, events)| libc::pollfd {
                fd,
                events,
                revents: 0,
            })
            .collect();
        let now = Instant::now();
        let ms = crate::platform::checks::poll_timeout_ms(timeout.map(|t| now + t), now);
        let ret = unsafe { libc::poll(polled.as_mut_ptr(), polled.len() as libc::nfds_t, ms) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                return Ok((Vec::new(), Vec::new()));
            }
            return Err(SandboxError::Internal {
                context: "poll the run's pipes".into(),
                source: Box::new(err),
            });
        }
        let mut readable = Vec::new();
        let mut writable = Vec::new();
        for p in &polled {
            if p.revents == 0 {
                continue;
            }
            if p.events == libc::POLLIN {
                readable.push(p.fd);
            } else {
                writable.push(p.fd);
            }
        }
        Ok((readable, writable))
    }
}

#[cfg(target_os = "macos")]
pub(crate) struct Poller(crate::platform::macos::kqueue::Kqueue);

#[cfg(target_os = "macos")]
impl Poller {
    fn io_err(context: &str, e: std::io::Error) -> SandboxError {
        SandboxError::Internal {
            context: context.into(),
            source: Box::new(e),
        }
    }

    pub(crate) fn new() -> Result<Self> {
        crate::platform::macos::kqueue::Kqueue::new()
            .map(Self)
            .map_err(|e| Self::io_err("create kqueue", e))
    }

    pub(crate) fn watch_read(&mut self, fd: RawFd) -> Result<()> {
        self.0
            .watch_readable(fd)
            .map_err(|e| Self::io_err("watch a pipe", e))
    }

    pub(crate) fn watch_write(&mut self, fd: RawFd) -> Result<()> {
        self.0
            .watch_writable(fd)
            .map_err(|e| Self::io_err("watch a pipe", e))
    }

    /// Closing an fd removes its events; this is for one that stays open.
    pub(crate) fn unwatch(&mut self, fd: RawFd) {
        self.0.unwatch(fd);
    }

    pub(crate) fn wait(&self, timeout: Option<Duration>) -> Result<(Vec<RawFd>, Vec<RawFd>)> {
        use crate::platform::macos::kqueue::Event;
        let events = self
            .0
            .wait(timeout)
            .map_err(|e| Self::io_err("wait on the run's pipes", e))?;
        let mut readable = Vec::new();
        let mut writable = Vec::new();
        for e in events {
            match e {
                Event::Readable(fd) => readable.push(fd),
                Event::Writable(fd) => writable.push(fd),
                Event::Exited(_) => {}
            }
        }
        Ok((readable, writable))
    }
}

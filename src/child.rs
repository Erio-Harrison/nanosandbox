//! A command started with [`Sandbox::spawn`](crate::Sandbox::spawn) or
//! [`Sandbox::spawn_pty`](crate::Sandbox::spawn_pty): its streams while it runs, and its
//! [`ExecutionResult`] once it ends.

use crate::audit::AuditHook;
use crate::error::{Result, SandboxError};
use crate::platform::output::Captured;
use crate::platform::supervise::{self, Launched, Supervisor};
use crate::result::ExecutionResult;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::time::Instant;

fn read_fd(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            // A pty master once the terminal is gone: end of output, not an error.
            Some(libc::EIO) => return Ok(0),
            _ => return Err(err),
        }
    }
}

fn write_fd(fd: RawFd, buf: &[u8]) -> std::io::Result<usize> {
    loop {
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err);
        }
    }
}

macro_rules! stream {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub struct $name(OwnedFd);

        impl AsFd for $name {
            fn as_fd(&self) -> BorrowedFd<'_> {
                self.0.as_fd()
            }
        }

        impl AsRawFd for $name {
            fn as_raw_fd(&self) -> RawFd {
                self.0.as_raw_fd()
            }
        }

        impl From<$name> for OwnedFd {
            fn from(s: $name) -> OwnedFd {
                s.0
            }
        }
    };
}

stream! {
    /// The command's stdin. Dropping it is EOF for a piped command; a PTY has no EOF to
    /// send, so write the terminal's end-of-file character (`0x04`) instead.
    ChildStdin
}
stream! {
    /// The command's stdout, or with a PTY everything the terminal shows (input echo
    /// included, lines ending `\r\n`).
    ChildStdout
}
stream! {
    /// The command's stderr (`None` with a PTY, where it's part of [`ChildStdout`]).
    ChildStderr
}

impl Write for ChildStdin {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        write_fd(self.0.as_raw_fd(), buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Read for ChildStdout {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        read_fd(self.0.as_raw_fd(), buf)
    }
}

impl Read for ChildStderr {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        read_fd(self.0.as_raw_fd(), buf)
    }
}

/// A running sandboxed command. Its limits are enforced and its processes cleaned up exactly
/// as for [`run`](crate::Sandbox::run); the difference is that the caller reads and writes the
/// streams itself, as they happen. Output is never cut at `max_output`: a command that writes
/// faster than the caller reads waits on its pipe. Dropping a `Child` kills the command and
/// waits for its cleanup.
pub struct Child {
    /// `None` after [`take`](Option::take); `Some` from the start.
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    /// `None` with a PTY.
    pub stderr: Option<ChildStderr>,
    pid: u32,
    pty: Option<OwnedFd>,
    supervisor: Option<Supervisor>,
    finished: Option<ExecutionResult>,
    start: Instant,
    max_output: u64,
    audit: Option<(AuditHook, String, u64)>,
}

impl Child {
    pub(crate) fn new(
        launched: Launched,
        max_output: u64,
        audit: Option<(AuditHook, String, u64)>,
    ) -> Self {
        Self {
            stdin: launched.stdin.map(ChildStdin),
            stdout: launched.stdout.map(ChildStdout),
            stderr: launched.stderr.map(ChildStderr),
            pid: launched.pid,
            pty: launched.pty,
            supervisor: Some(launched.supervisor),
            finished: None,
            start: launched.start,
            max_output,
            audit,
        }
    }

    /// Host pid of the command's first process (on Linux the sandbox's init, whose death ends
    /// everything in it).
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// `SIGKILL`s the command. Its result then has `signal` 9; the limits' `killed_by_*`
    /// flags stay false. A no-op once it has ended.
    pub fn kill(&mut self) -> Result<()> {
        if let Some(supervisor) = &self.supervisor {
            supervisor.kill();
        }
        Ok(())
    }

    /// Sets the terminal's size, for a command started with
    /// [`spawn_pty`](crate::Sandbox::spawn_pty); the command gets `SIGWINCH`.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        let Some(pty) = &self.pty else {
            return Err(SandboxError::Io(std::io::Error::from_raw_os_error(
                libc::ENOTTY,
            )));
        };
        crate::platform::pty::resize(pty.as_raw_fd(), rows, cols)?;
        Ok(())
    }

    /// Whether the command has ended; its result, with empty `stdout`/`stderr` (they're the
    /// caller's to read), once it has. Unread output stays readable.
    pub fn try_wait(&mut self) -> Result<Option<ExecutionResult>> {
        if let Some(result) = &self.finished {
            return Ok(Some(result.clone()));
        }
        match &self.supervisor {
            Some(s) if s.is_done() => {}
            _ => return Ok(None),
        }
        let outcome = self.supervisor.take().expect("checked above").wait();
        let result = outcome.map(|o| {
            supervise::finish(
                o,
                [Captured::new(0), Captured::new(0)],
                self.start.elapsed(),
            )
        });
        self.record(result).map(Some)
    }

    /// Waits for the command to end. Output it writes meanwhile to the streams this `Child`
    /// still holds is read and dropped, so it can't block on them; a stream the caller took
    /// is the caller's to drain (a program blocked writing to it waits, as does a shell
    /// restoring its terminal on exit). The result's `stdout`/`stderr` are empty.
    pub fn wait(self) -> Result<ExecutionResult> {
        self.end(0).map(|mut r| {
            r.output_truncated = false;
            r
        })
    }

    /// Waits for the command to end, collecting what it still writes to the streams this
    /// `Child` holds (up to `max_output` each, like `run`) into the result.
    pub fn wait_with_output(self) -> Result<ExecutionResult> {
        let limit = self.max_output;
        self.end(limit)
    }

    fn end(mut self, max_output: u64) -> Result<ExecutionResult> {
        if let Some(result) = self.finished.take() {
            return Ok(result);
        }
        let Some(supervisor) = self.supervisor.take() else {
            return Err(SandboxError::Internal {
                context: "wait for the command".into(),
                source: Box::new(std::io::Error::other("already waited for")),
            });
        };
        // Closing a piped stdin is EOF for the command.
        self.stdin = None;
        let launched = Launched {
            stdin: None,
            stdout: self.stdout.take().map(OwnedFd::from),
            stderr: self.stderr.take().map(OwnedFd::from),
            pid: self.pid,
            pty: None,
            supervisor,
            start: self.start,
        };
        let result = supervise::collect(launched, None, max_output);
        self.record(result)
    }

    /// Keeps the result for later calls and ends the audit record.
    fn record(&mut self, result: Result<ExecutionResult>) -> Result<ExecutionResult> {
        if let Some((hook, id, run)) = self.audit.take() {
            crate::audit::end(&hook, &id, run, &result);
        }
        if let Ok(result) = &result {
            self.finished = Some(result.clone());
        }
        result
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if let Some(supervisor) = self.supervisor.take() {
            supervisor.kill();
            self.stdin = None;
            let launched = Launched {
                stdin: None,
                stdout: self.stdout.take().map(OwnedFd::from),
                stderr: self.stderr.take().map(OwnedFd::from),
                pid: self.pid,
                pty: None,
                supervisor,
                start: self.start,
            };
            let result = supervise::collect(launched, None, 0);
            let _ = self.record(result);
        }
    }
}

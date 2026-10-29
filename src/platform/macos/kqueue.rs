//! A kqueue the wait loop sleeps on: pipe readiness, process exit and a deadline, instead of a
//! fixed-interval sleep.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

pub(super) struct Kqueue(OwnedFd);

/// What `wait` reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Event {
    Readable(RawFd),
    Writable(RawFd),
    Exited(libc::pid_t),
}

impl Kqueue {
    pub(super) fn new() -> std::io::Result<Self> {
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    fn change(&self, ident: usize, filter: i16, flags: u16, fflags: u32) -> std::io::Result<()> {
        let change = libc::kevent {
            ident,
            filter,
            flags,
            fflags,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        let ret = unsafe {
            libc::kevent(
                self.0.as_raw_fd(),
                &change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Level-triggered; closing `fd` removes it.
    pub(super) fn watch_readable(&self, fd: RawFd) -> std::io::Result<()> {
        self.change(fd as usize, libc::EVFILT_READ, libc::EV_ADD, 0)
    }

    pub(super) fn watch_writable(&self, fd: RawFd) -> std::io::Result<()> {
        self.change(fd as usize, libc::EVFILT_WRITE, libc::EV_ADD, 0)
    }

    /// Fires once when `pid` exits. False if it already has (`ESRCH`), so the caller doesn't
    /// wait for an event that never comes.
    pub(super) fn watch_exit(&self, pid: libc::pid_t) -> std::io::Result<bool> {
        match self.change(
            pid as usize,
            libc::EVFILT_PROC,
            libc::EV_ADD | libc::EV_ONESHOT,
            libc::NOTE_EXIT,
        ) {
            Ok(()) => Ok(true),
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Blocks until something fires or `timeout` passes (`None`: no limit).
    pub(super) fn wait(&self, timeout: Option<Duration>) -> std::io::Result<Vec<Event>> {
        let ts = timeout.map(|t| libc::timespec {
            tv_sec: t.as_secs() as libc::time_t,
            tv_nsec: libc::c_long::from(t.subsec_nanos()),
        });
        let mut events: [libc::kevent; 8] = unsafe { std::mem::zeroed() };
        let n = loop {
            let n = unsafe {
                libc::kevent(
                    self.0.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    events.as_mut_ptr(),
                    events.len() as libc::c_int,
                    ts.as_ref().map_or(std::ptr::null(), |t| t as *const _),
                )
            };
            if n >= 0 {
                break n as usize;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(err);
            }
        };
        Ok(events[..n]
            .iter()
            .filter_map(|e| match e.filter {
                libc::EVFILT_READ => Some(Event::Readable(e.ident as RawFd)),
                libc::EVFILT_WRITE => Some(Event::Writable(e.ident as RawFd)),
                libc::EVFILT_PROC => Some(Event::Exited(e.ident as libc::pid_t)),
                _ => None,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_wakes_on_exit_not_on_the_timeout() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 0.05"])
            .spawn()
            .unwrap();
        let kq = Kqueue::new().unwrap();
        assert!(kq.watch_exit(child.id() as libc::pid_t).unwrap());
        let start = Instant::now();
        let events = kq.wait(Some(Duration::from_secs(5))).unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(events, vec![Event::Exited(child.id() as libc::pid_t)]);
        child.wait().unwrap();
    }

    #[test]
    fn test_an_exited_process_cannot_be_watched() {
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        child.wait().unwrap();
        let kq = Kqueue::new().unwrap();
        assert!(!kq.watch_exit(child.id() as libc::pid_t).unwrap());
    }

    #[test]
    fn test_pipe_readiness() {
        let (r, w) = nix::unistd::pipe().unwrap();
        let kq = Kqueue::new().unwrap();
        kq.watch_readable(r.as_raw_fd()).unwrap();
        assert!(kq.wait(Some(Duration::ZERO)).unwrap().is_empty());
        nix::unistd::write(&w, b"x").unwrap();
        assert_eq!(
            kq.wait(Some(Duration::from_secs(1))).unwrap(),
            vec![Event::Readable(r.as_raw_fd())]
        );
    }
}

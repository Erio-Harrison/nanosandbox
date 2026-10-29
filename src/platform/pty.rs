//! A pseudo-terminal for `spawn_pty`: the master stays with the caller; the slave becomes the
//! command's controlling terminal and its stdin, stdout and stderr. Both ends are close-on-exec
//! from the start, so no concurrently started program inherits a terminal that isn't its own.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};

pub(crate) struct Pty {
    pub(crate) master: OwnedFd,
    pub(crate) slave: OwnedFd,
    /// The slave's device path (Linux), for a child to open its own handle on it: one opened
    /// here belongs to this mount namespace, which AppArmor's userns profile treats as a
    /// disconnected path in the child's (`fstat` fails, so `ttyname` and `tty` do).
    #[cfg(target_os = "linux")]
    pub(crate) slave_path: std::ffi::CString,
}

fn winsize(rows: u16, cols: u16) -> libc::winsize {
    libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

/// Sets the terminal's size; `master` is either end.
pub(crate) fn resize(master: RawFd, rows: u16, cols: u16) -> std::io::Result<()> {
    let size = winsize(rows, cols);
    if unsafe { libc::ioctl(master, libc::TIOCSWINSZ as _, &size) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn open(rows: u16, cols: u16) -> std::io::Result<Pty> {
    // posix_openpt passes the flags to open(2), so the master is CLOEXEC atomically.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if master < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let mut name = [0 as libc::c_char; 64];
    let ok = unsafe {
        use std::os::fd::AsRawFd;
        libc::grantpt(master.as_raw_fd()) == 0
            && libc::unlockpt(master.as_raw_fd()) == 0
            && libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()) == 0
    };
    if !ok {
        return Err(std::io::Error::last_os_error());
    }
    let slave = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if slave < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    {
        use std::os::fd::AsRawFd;
        resize(master.as_raw_fd(), rows, cols)?;
    }
    let slave_path = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }.to_owned();
    Ok(Pty {
        master,
        slave,
        slave_path,
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn open(rows: u16, cols: u16) -> std::io::Result<Pty> {
    // No O_CLOEXEC in openpty: under FORK_LOCK, like cloexec_pipe, so no fork sees the gap.
    let _fork = crate::platform::macos::FORK_LOCK
        .write()
        .unwrap_or_else(|e| e.into_inner());
    let (mut master, mut slave) = (0 as libc::c_int, 0 as libc::c_int);
    let mut size = winsize(rows, cols);
    let ret = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    for fd in [&master, &slave] {
        use std::os::fd::AsRawFd;
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(Pty { master, slave })
}

/// A second handle on `fd` (close-on-exec), sharing its open file description.
pub(crate) fn dup_cloexec(fd: RawFd) -> std::io::Result<OwnedFd> {
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(dup) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn test_both_ends_are_close_on_exec_and_sized() {
        let pty = open(30, 90).unwrap();
        for fd in [&pty.master, &pty.slave] {
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::ioctl(pty.slave.as_raw_fd(), libc::TIOCGWINSZ as _, &mut size) },
            0
        );
        assert_eq!((size.ws_row, size.ws_col), (30, 90));
        resize(pty.master.as_raw_fd(), 10, 20).unwrap();
        unsafe { libc::ioctl(pty.slave.as_raw_fd(), libc::TIOCGWINSZ as _, &mut size) };
        assert_eq!((size.ws_row, size.ws_col), (10, 20));
    }
}

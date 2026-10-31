//! Hands the proxy a listener bound inside the sandbox's netns, via a socketpair made before clone().

use crate::builder::{NetworkMode, SandboxConfig};
use crate::error::{Result, SandboxError};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Refuses mount setups that can only fail or misbehave at run time.
pub(super) fn check_network(config: &SandboxConfig) -> Result<()> {
    if matches!(config.network_mode, NetworkMode::Proxied { .. })
        && super::userns_restricted_by_apparmor()
    {
        // Host-network fallback would make the whitelist advisory.
        return Err(SandboxError::Unsupported {
            setting: "allow_network()".into(),
            reason: "it needs to bring up loopback in the sandbox's own network namespace, \
                     which AppArmor denies here (kernel.apparmor_restrict_unprivileged_userns=1 \
                     for an unprivileged, unconfined process). Run as root, set that sysctl to \
                     0, or give this executable an AppArmor profile that allows userns"
                .into(),
        });
    }
    Ok(())
}

/// Gets the proxy into a Proxied sandbox's netns. The child binds the listener there (the
/// parent lacks CAP_SYS_ADMIN in it) and returns it over a socketpair made before clone().
pub(super) struct ProxyLink {
    port: u16,
    parent: OwnedFd,
    child: Option<OwnedFd>,
}

/// The child's half of a `ProxyLink`, copied into the clone() closure.
#[derive(Clone, Copy)]
pub(super) struct ProxyLinkChild {
    port: u16,
    fd: RawFd,
}

/// One cmsghdr carrying a single fd (24 bytes on 64-bit Linux); stack buffer, no allocation.
#[repr(C, align(8))]
struct FdControl([u8; 32]);

impl ProxyLink {
    pub(super) fn new(port: u16) -> Result<Self> {
        let mut fds = [0; 2];
        let flags = libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC;
        if unsafe { libc::socketpair(libc::AF_UNIX, flags, 0, fds.as_mut_ptr()) } != 0 {
            return Err(SandboxError::Internal {
                context: "create proxy socketpair".into(),
                source: Box::new(std::io::Error::last_os_error()),
            });
        }
        let [parent, child] = fds.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
        Ok(Self {
            port,
            parent,
            child: Some(child),
        })
    }

    pub(super) fn child_side(&self) -> ProxyLinkChild {
        ProxyLinkChild {
            port: self.port,
            fd: self
                .child
                .as_ref()
                .expect("taken only after clone")
                .as_raw_fd(),
        }
    }

    /// Parent, after clone(): drops the child's end so `receive` sees EOF if the child dies silently.
    pub(super) fn close_child_end(&mut self) {
        self.child = None;
    }

    /// The child's listener, or None if it never sent one (see its stderr). `Err` when nothing
    /// arrived within `timeout`: the child is stuck in its setup, before any limit watches it.
    pub(super) fn receive_within(
        &self,
        timeout: std::time::Duration,
    ) -> std::io::Result<Option<std::net::TcpListener>> {
        let mut pfd = libc::pollfd {
            fd: self.parent.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let n =
                unsafe { libc::poll(&mut pfd, 1, left.as_millis().min(i32::MAX as u128) as i32) };
            if n > 0 {
                return Ok(self.receive());
            }
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("no listener within {timeout:?}"),
                ));
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(err);
            }
        }
    }

    fn receive(&self) -> Option<std::net::TcpListener> {
        let mut byte = 0u8;
        let mut iov = libc::iovec {
            iov_base: &mut byte as *mut u8 as *mut libc::c_void,
            iov_len: 1,
        };
        let mut control = FdControl([0; 32]);
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control.0.len() as _;
        loop {
            let n =
                unsafe { libc::recvmsg(self.parent.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
            if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if n <= 0 {
                return None;
            }
            break;
        }
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null()
                || (*cmsg).cmsg_level != libc::SOL_SOCKET
                || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            {
                return None;
            }
            let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const libc::c_int);
            Some(std::net::TcpListener::from_raw_fd(fd))
        }
    }
}

impl ProxyLinkChild {
    /// Child, between clone() and exec(): raw syscalls only.
    pub(super) fn bind_and_send(self) -> std::result::Result<(), &'static str> {
        unsafe {
            // A new network namespace's loopback starts down.
            let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
            if s < 0 {
                return Err("open a socket to configure loopback");
            }
            let mut ifr: libc::ifreq = std::mem::zeroed();
            ifr.ifr_name[0] = b'l' as libc::c_char;
            ifr.ifr_name[1] = b'o' as libc::c_char;
            let up = libc::ioctl(s, libc::SIOCGIFFLAGS as _, &mut ifr) == 0 && {
                ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
                libc::ioctl(s, libc::SIOCSIFFLAGS as _, &ifr) == 0
            };
            libc::close(s);
            if !up {
                return Err("bring up loopback");
            }

            let listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            if listener < 0 {
                return Err("open the proxy listener");
            }
            let addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: self.port.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
                },
                sin_zero: [0; 8],
            };
            let addr_len = std::mem::size_of_val(&addr) as libc::socklen_t;
            if libc::bind(
                listener,
                &addr as *const _ as *const libc::sockaddr,
                addr_len,
            ) != 0
                || libc::listen(listener, 128) != 0
            {
                libc::close(listener);
                return Err("listen for the proxy");
            }

            let mut byte = 0u8;
            let mut iov = libc::iovec {
                iov_base: &mut byte as *mut u8 as *mut libc::c_void,
                iov_len: 1,
            };
            let mut control = FdControl([0; 32]);
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut libc::c_int, listener);
            let sent = libc::sendmsg(self.fd, &msg, 0);
            libc::close(listener);
            if sent != 1 {
                return Err("hand the proxy listener to the parent");
            }
        }
        Ok(())
    }
}

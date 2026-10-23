//! Seccomp-BPF syscall filter, on unless `seccomp(false)`.
//!
//! Denies local-privilege-escalation entry points: new namespaces (`clone`/`unshare` with
//! `CLONE_NEW*`, `setns`), mounting, bpf, perf_event_open, userfaultfd, io_uring, keyring,
//! kernel modules, kexec. These fail with `EPERM`. `clone3` and syscalls newer than
//! [`LAST_KNOWN_SYSCALL`] get `ENOSYS` (clone3's flags can't be inspected; libc falls back
//! to `clone`). Other ABIs (32-bit, x32) kill the process.

/// `AUDIT_ARCH_*` of supported architectures; `None` elsewhere (`check_support` refuses).
#[cfg(target_arch = "x86_64")]
const NATIVE_ARCH: Option<u32> = Some(0xC000_003E);
#[cfg(target_arch = "aarch64")]
const NATIVE_ARCH: Option<u32> = Some(0xC000_00B7);
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const NATIVE_ARCH: Option<u32> = None;

/// `mseal`, Linux 6.10. Newer syscalls get `ENOSYS`; raise after reviewing them.
const LAST_KNOWN_SYSCALL: u32 = 462;

/// Denied outright, with `EPERM`.
const DENIED: &[libc::c_long] = &[
    libc::SYS_setns,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_open_tree,
    libc::SYS_move_mount,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_mount_setattr,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
];

/// `CLONE_NEW*` as `clone` takes them. `CLONE_NEWTIME` (0x80) isn't here:
/// in `clone`'s flags that bit belongs to the exit signal.
const CLONE_NAMESPACE_FLAGS: u32 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET) as u32;
const UNSHARE_NAMESPACE_FLAGS: u32 = CLONE_NAMESPACE_FLAGS | libc::CLONE_NEWTIME as u32;

// Offsets into `struct seccomp_data`; both architectures are little-endian, flags fit in 32 bits.
const DATA_NR: u32 = 0;
const DATA_ARCH: u32 = 4;
const DATA_ARG0_LOW: u32 = 16;

/// Where a jump goes, resolved to an offset once the program is laid out.
#[derive(Clone, Copy, PartialEq)]
enum Label {
    Next,
    CheckClone,
    CheckUnshare,
    CheckSocket,
    Allow,
    Deny,
    NoSys,
    Kill,
}

/// The compiled filter. Built in the parent; the child only installs it.
pub(crate) struct SyscallFilter {
    program: Vec<libc::sock_filter>,
}

impl SyscallFilter {
    /// Whether this architecture has a filter.
    pub(crate) fn supported() -> bool {
        NATIVE_ARCH.is_some()
    }

    /// `None` where [`supported`](Self::supported) is false.
    pub(crate) fn new() -> Option<Self> {
        let arch = NATIVE_ARCH?;
        let load = |offset| {
            (
                libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
                Label::Next,
                Label::Next,
                offset,
            )
        };
        let jeq = |k, to| {
            (
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                to,
                Label::Next,
                k,
            )
        };
        let ret = |k| (libc::BPF_RET | libc::BPF_K, Label::Next, Label::Next, k);

        let mut code = vec![
            load(DATA_ARCH),
            (
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                Label::Next,
                Label::Kill,
                arch,
            ),
            load(DATA_NR),
            (
                libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K,
                Label::NoSys,
                Label::Next,
                LAST_KNOWN_SYSCALL,
            ),
            jeq(libc::SYS_clone3 as u32, Label::NoSys),
            jeq(libc::SYS_clone as u32, Label::CheckClone),
            jeq(libc::SYS_unshare as u32, Label::CheckUnshare),
            jeq(libc::SYS_socket as u32, Label::CheckSocket),
        ];
        code.extend(DENIED.iter().map(|&nr| jeq(nr as u32, Label::Deny)));
        code.push(ret(libc::SECCOMP_RET_ALLOW));

        let mut targets = Vec::new();
        for (label, flags) in [
            (Label::CheckClone, CLONE_NAMESPACE_FLAGS),
            (Label::CheckUnshare, UNSHARE_NAMESPACE_FLAGS),
        ] {
            targets.push((label, code.len()));
            code.push(load(DATA_ARG0_LOW));
            code.push((
                libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K,
                Label::Deny,
                Label::Allow,
                flags,
            ));
        }
        // Families are values, not flags: jeq, not jset. socketpair() is a separate syscall,
        // so proxy_link is unaffected. AF_VSOCK reaches the hypervisor host, past the netns.
        {
            targets.push((Label::CheckSocket, code.len()));
            code.push(load(DATA_ARG0_LOW));
            code.push(jeq(libc::AF_UNIX as u32, Label::Deny));
            code.push(jeq(libc::AF_VSOCK as u32, Label::Deny));
            code.push(ret(libc::SECCOMP_RET_ALLOW));
        }
        for (label, action) in [
            (Label::Allow, libc::SECCOMP_RET_ALLOW),
            (Label::Deny, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
            (Label::NoSys, libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
            (Label::Kill, libc::SECCOMP_RET_KILL_PROCESS),
        ] {
            targets.push((label, code.len()));
            code.push(ret(action));
        }

        let offset = |from: usize, to: Label| -> u8 {
            if to == Label::Next {
                return 0;
            }
            let (_, at) = targets.iter().find(|(l, _)| *l == to).unwrap();
            u8::try_from(at - from - 1).expect("seccomp jump out of range")
        };
        let program = code
            .iter()
            .enumerate()
            .map(|(i, &(op, jt, jf, k))| libc::sock_filter {
                code: op as u16,
                jt: offset(i, jt),
                jf: offset(i, jf),
                k,
            })
            .collect();
        Some(Self { program })
    }

    /// Installs the filter; runs in the child between clone() and exec().
    pub(crate) fn install(&self) -> bool {
        let prog = libc::sock_fprog {
            len: self.program.len() as libc::c_ushort,
            filter: self.program.as_ptr() as *mut libc::sock_filter,
        };
        unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                && libc::syscall(
                    libc::SYS_seccomp,
                    libc::SECCOMP_SET_MODE_FILTER,
                    0,
                    &prog as *const libc::sock_fprog,
                ) == 0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_builds_within_limits() {
        let Some(filter) = SyscallFilter::new() else {
            return;
        };
        // BPF_MAXINSNS is 4096; jumps are 8-bit, checked when building.
        assert!(filter.program.len() < 256);
        assert_eq!(
            filter.program.last().unwrap().k,
            libc::SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn test_denied_syscalls_are_known() {
        for &nr in DENIED {
            assert!(
                (nr as u32) <= LAST_KNOWN_SYSCALL,
                "{nr} is past LAST_KNOWN_SYSCALL"
            );
        }
    }
}

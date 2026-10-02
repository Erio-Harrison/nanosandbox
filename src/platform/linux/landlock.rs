//! Landlock rules that keep a sandbox without a rootfs from writing to the
//! host's files.
//!
//! Without a rootfs the sandbox sees the host's file system, and used to be
//! able to write anything the calling user can: `~/.bashrc`, `~/.ssh`, the
//! code next to it. Landlock is the kernel's unprivileged access control:
//! it needs no mounts and no capabilities, so it also works where AppArmor
//! denies those in user namespaces (Ubuntu's default).
//!
//! Reading stays allowed everywhere. Writing (creating, removing, renaming,
//! truncating, opening for writing) is allowed only under:
//!
//! - `ReadWrite` mounts and `tmpfs` mounts,
//! - `/tmp`, `/var/tmp` and `/dev/shm`, which programs expect to write to,
//! - `/dev`, for writing to existing devices like `/dev/null` only.

use crate::builder::{Permission, SandboxConfig};
use crate::error::{Result, SandboxError};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const CREATE_RULESET_VERSION: u32 = 1 << 0;
const RULE_PATH_BENEATH: libc::c_int = 1;

const ACCESS_FS_EXECUTE: u64 = 1 << 0;
const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_FS_READ_FILE: u64 = 1 << 2;
const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
/// ABI 2: renaming or linking a file into another directory. Unless handled,
/// Landlock always denies that.
const ACCESS_FS_REFER: u64 = 1 << 13;
/// ABI 3: truncate(2) and friends. Before that, only opening for writing
/// could be denied.
const ACCESS_FS_TRUNCATE: u64 = 1 << 14;

/// The rights that apply to a file, as opposed to a directory. A rule on a
/// file may only grant these.
const FILE_RIGHTS: u64 =
    ACCESS_FS_EXECUTE | ACCESS_FS_WRITE_FILE | ACCESS_FS_READ_FILE | ACCESS_FS_TRUNCATE;

/// Writable for programs whatever the config says, as on macOS.
const DEFAULT_WRITABLE: [&str; 3] = ["/tmp", "/var/tmp", "/dev/shm"];

/// Where the sandbox may create, change and remove files: the default
/// places, `writable` paths and tmpfs mounts. (Plus existing files under
/// `/dev`, and private_tmp's directory where it isn't a tmpfs.)
pub(crate) fn writable_areas(config: &SandboxConfig) -> impl Iterator<Item = &Path> {
    DEFAULT_WRITABLE
        .iter()
        .map(Path::new)
        .chain(
            config
                .mounts
                .iter()
                .filter(|m| m.permission == Permission::ReadWrite)
                .map(|m| m.target.as_path()),
        )
        .chain(config.tmpfs_mounts.iter().map(|(p, _)| p.as_path()))
}

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// The Landlock ABI version this kernel supports, or 0 without Landlock.
pub(crate) fn abi() -> i32 {
    static ABI: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
    *ABI.get_or_init(|| {
        let v = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<RulesetAttr>(),
                0usize,
                CREATE_RULESET_VERSION,
            )
        };
        v.max(0) as i32
    })
}

/// Refuses a config these rules apply to on a kernel without Landlock.
pub(crate) fn check(config: &SandboxConfig) -> Result<()> {
    if config.rootfs.is_none() && abi() < 1 {
        return Err(SandboxError::Unsupported {
            setting: "a sandbox without a rootfs".into(),
            reason: "it needs Landlock (Linux 5.13+, with the landlock LSM enabled) to keep it \
                     from writing to the host's files; give it a rootfs to run without Landlock"
                .into(),
        });
    }
    Ok(())
}

/// The rules, with every path already built. Built in the parent; the child
/// only applies them.
pub(crate) struct WriteRules {
    handled: u64,
    /// (path, rights to grant beneath it)
    paths: Vec<(CString, u64)>,
}

impl WriteRules {
    /// `None` with a rootfs: the sandbox then only sees the rootfs, which is
    /// the caller's own directory to write to. `check` already refused a
    /// kernel without Landlock.
    /// `private_tmp`: this run's stand-in for tmpfs("/tmp"), if it has one.
    pub(crate) fn new(config: &SandboxConfig, private_tmp: Option<&Path>) -> Result<Option<Self>> {
        if config.rootfs.is_some() {
            return Ok(None);
        }
        let abi = abi();
        let mut handled = ACCESS_FS_WRITE_FILE
            | ACCESS_FS_REMOVE_DIR
            | ACCESS_FS_REMOVE_FILE
            | ACCESS_FS_MAKE_CHAR
            | ACCESS_FS_MAKE_DIR
            | ACCESS_FS_MAKE_REG
            | ACCESS_FS_MAKE_SOCK
            | ACCESS_FS_MAKE_FIFO
            | ACCESS_FS_MAKE_BLOCK
            | ACCESS_FS_MAKE_SYM;
        if abi >= 2 {
            handled |= ACCESS_FS_REFER;
        }
        if abi >= 3 {
            handled |= ACCESS_FS_TRUNCATE;
        }

        let path = |p: &Path| {
            CString::new(p.as_os_str().as_bytes())
                .map_err(|_| SandboxError::Config(format!("path contains NUL: {}", p.display())))
        };
        let mut paths = vec![(c"/dev".to_owned(), handled & FILE_RIGHTS)];
        for area in writable_areas(config).chain(private_tmp) {
            paths.push((path(area)?, handled));
        }
        Ok(Some(Self { handled, paths }))
    }

    /// Runs in the child between clone() and exec(): raw syscalls only. The
    /// error names the step that failed, as a static string.
    pub(crate) fn apply(&self) -> std::result::Result<(), &'static str> {
        let attr = RulesetAttr {
            handled_access_fs: self.handled,
        };
        unsafe {
            let ruleset = libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                std::mem::size_of::<RulesetAttr>(),
                0u32,
            ) as libc::c_int;
            if ruleset < 0 {
                return Err("create ruleset");
            }
            for (path, rights) in &self.paths {
                let fd = libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
                if fd < 0 {
                    // /var/tmp or /dev/shm may not exist on this system.
                    if *libc::__errno_location() == libc::ENOENT {
                        continue;
                    }
                    libc::close(ruleset);
                    return Err("open a writable path");
                }
                let mut st: libc::stat = std::mem::zeroed();
                let is_dir =
                    libc::fstat(fd, &mut st) == 0 && st.st_mode & libc::S_IFMT == libc::S_IFDIR;
                let allowed = if is_dir {
                    *rights
                } else {
                    rights & FILE_RIGHTS
                };
                if allowed == 0 {
                    libc::close(fd);
                    continue;
                }
                let rule = PathBeneathAttr {
                    allowed_access: allowed,
                    parent_fd: fd,
                };
                let added = libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset,
                    RULE_PATH_BENEATH,
                    &rule as *const PathBeneathAttr,
                    0u32,
                );
                libc::close(fd);
                if added != 0 {
                    libc::close(ruleset);
                    return Err("add a rule");
                }
            }
            let restricted = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                && libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) == 0;
            libc::close(ruleset);
            if !restricted {
                return Err("restrict self");
            }
        }
        Ok(())
    }
}

//! Landlock rules that stop a rootfs-less sandbox writing host files or reading credentials
//! (see platform/read_rules.rs).
//!
//! Landlock needs no mounts or capabilities, so it works where AppArmor denies those in user
//! namespaces (Ubuntu default). Reads are allowed except read_rules paths; directory listing
//! everywhere (rules cover whole subtrees). Writes only under:
//!
//! - `ReadWrite` and `tmpfs` mounts,
//! - `/tmp`, `/var/tmp`, `/dev/shm`,
//! - `/dev`, existing devices only.

use crate::builder::{Permission, SandboxConfig};
use crate::error::{Result, SandboxError};
use crate::platform::read_rules;
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
/// ABI 2: rename/link across directories; always denied unless handled.
const ACCESS_FS_REFER: u64 = 1 << 13;
/// ABI 3: truncate(2); before that only open-for-write could be denied.
const ACCESS_FS_TRUNCATE: u64 = 1 << 14;

/// Rights that apply to a file rather than a directory; a file rule may grant only these.
const FILE_RIGHTS: u64 =
    ACCESS_FS_EXECUTE | ACCESS_FS_WRITE_FILE | ACCESS_FS_READ_FILE | ACCESS_FS_TRUNCATE;

/// Writable for programs whatever the config says, as on macOS.
const DEFAULT_WRITABLE: [&str; 3] = ["/tmp", "/var/tmp", "/dev/shm"];

/// Where writes are allowed: default places, `writable` paths, tmpfs mounts (plus existing
/// `/dev` files, and private_tmp's directory where it isn't a tmpfs).
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

/// The rules, paths prebuilt in the parent; the child only applies them.
pub(crate) struct WriteRules {
    handled: u64,
    /// (where, rights to grant beneath it)
    paths: Vec<(Target, u64)>,
}

/// Where a rule is attached.
enum Target {
    /// Opened by the child, by path.
    Path(CString),
    /// Opened in the parent and checked to be where the sandbox was built to put it; the rule
    /// goes on this descriptor, so path swaps can't move it. Directory-ness is found here too:
    /// `fstat` on an inherited fd can be refused in the child (AppArmor).
    Fd(std::os::fd::OwnedFd, bool),
}

/// Opens `given`, refusing it unless it is `real`. A writable dir swapped for a symlink
/// would otherwise be followed; checking the descriptor leaves no check-to-rule gap.
fn open_checked(given: &Path, real: &Path) -> Result<(std::os::fd::OwnedFd, bool)> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let c = CString::new(given.as_os_str().as_bytes()).map_err(|e| SandboxError::Config {
        context: format!("path contains NUL: {}", given.display()),
        source: Some(Box::new(e)),
    })?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(SandboxError::Config {
            context: format!(
                "{} is no longer there ({}); not running",
                given.display(),
                std::io::Error::last_os_error()
            ),
            source: None,
        });
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    match std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())) {
        Ok(now) if now == real => {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let is_dir = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } == 0
                && st.st_mode & libc::S_IFMT == libc::S_IFDIR;
            Ok((fd, is_dir))
        }
        Ok(now) => Err(SandboxError::Config {
            context: format!(
                "{} led to {} when the sandbox was built and now leads to {}: it, or a \
                 directory above it, was replaced. Not running; build the sandbox (or restart \
                 the server) again to use the new one",
                given.display(),
                real.display(),
                now.display()
            ),
            source: None,
        }),
        Err(e) => Err(SandboxError::Config {
            context: format!(
                "could not check where {} leads ({e}); not running",
                given.display()
            ),
            source: None,
        }),
    }
}

impl WriteRules {
    /// `None` with a rootfs (it's the caller's own directory); `check` already refused kernels
    /// without Landlock. `private_tmp` is this run's stand-in for tmpfs("/tmp").
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

        // Reading is handled only when something is denied; then the rest must be allowed explicitly.
        let denied = read_rules::denied(config);
        let read = if denied.is_empty() {
            0
        } else {
            ACCESS_FS_READ_FILE
        };
        handled |= read;

        let path = |p: &Path| {
            CString::new(p.as_os_str().as_bytes()).map_err(|e| SandboxError::Config {
                context: format!("path contains NUL: {}", p.display()),
                source: Some(Box::new(e)),
            })
        };
        let mut paths = vec![(Target::Path(c"/dev".to_owned()), handled & FILE_RIGHTS)];
        // Caller-named dirs are held by descriptor. Not /tmp, /var/tmp, /dev/shm or tmpfs: the
        // child may mount a fresh one over them, so the rule goes on what it sees there.
        let named = |area: &Path| {
            config.mounts.iter().any(|m| {
                m.permission == Permission::ReadWrite && m.source == m.target && m.target == area
            }) && !DEFAULT_WRITABLE.iter().any(|d| Path::new(d) == area)
                && !config.tmpfs_mounts.iter().any(|(t, _)| t == area)
        };
        for area in writable_areas(config).chain(private_tmp) {
            let target = match config.pinned_path(area) {
                Some(real) if named(area) => {
                    let (fd, is_dir) = open_checked(area, real)?;
                    Target::Fd(fd, is_dir)
                }
                _ => Target::Path(path(area)?),
            };
            paths.push((target, handled));
        }
        if read != 0 {
            let readable = read_rules::allowed_roots(&denied)
                .into_iter()
                .chain(read_rules::granted(config, &denied));
            for p in readable {
                paths.push((Target::Path(path(&p)?), read));
            }
        }
        Ok(Some(Self { handled, paths }))
    }

    /// Child, between clone() and exec(): raw syscalls only.
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
            for (target, rights) in &self.paths {
                let (fd, ours, known_dir) = match target {
                    Target::Fd(fd, is_dir) => {
                        (std::os::fd::AsRawFd::as_raw_fd(fd), false, Some(*is_dir))
                    }
                    Target::Path(path) => {
                        let fd = libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
                        if fd < 0 {
                            // /var/tmp or /dev/shm may not exist; what we can't reach we can't use.
                            if matches!(*libc::__errno_location(), libc::ENOENT | libc::EACCES) {
                                continue;
                            }
                            libc::close(ruleset);
                            return Err("open a writable path");
                        }
                        (fd, true, None)
                    }
                };
                let is_dir = match known_dir {
                    Some(is_dir) => is_dir,
                    None => {
                        let mut st: libc::stat = std::mem::zeroed();
                        libc::fstat(fd, &mut st) == 0 && st.st_mode & libc::S_IFMT == libc::S_IFDIR
                    }
                };
                let allowed = if is_dir {
                    *rights
                } else {
                    rights & FILE_RIGHTS
                };
                if allowed == 0 {
                    if ours {
                        libc::close(fd);
                    }
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
                if ours {
                    libc::close(fd);
                }
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

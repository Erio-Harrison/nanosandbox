//! Mount namespace plan, built before clone() so the child issues only raw syscalls.

use crate::builder::{Mount, Permission, SandboxConfig};
use crate::error::{Result, SandboxError};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

/// Whether uid/gid (no other groups) could write `path` by its owner/group/other mode bits.
/// Not a full simulation (no ACLs, no parent traversal); catches a root caller's writable/bind
/// target that a root-owned directory would fail on at run time with only `EACCES`.
fn can_write(path: &Path, uid: u32, gid: u32) -> std::io::Result<bool> {
    let meta = std::fs::metadata(path)?;
    let mode = meta.mode();
    Ok(if meta.uid() == uid {
        mode & 0o200 != 0
    } else if meta.gid() == gid {
        mode & 0o020 != 0
    } else {
        mode & 0o002 != 0
    })
}

/// Which cgroup v2 controllers this config's limits actually need.
pub(super) fn needed_cgroup_controllers(config: &SandboxConfig) -> Vec<&'static str> {
    let mut needed = Vec::new();
    if config.memory_limit.is_some() {
        needed.push("memory");
    }
    if config.cpu_limit.is_some() {
        needed.push("cpu");
    }
    if config.max_pids.is_some() {
        needed.push("pids");
    }
    needed
}

/// One mount-ns setup step with all paths/options prebuilt (see `MountPlan`).
enum MountStep {
    /// `mkdir`, EEXIST ignored. Issued per component in order with the mounts, so a target nested
    /// in an earlier mount is created inside it.
    Mkdir(CString),
    /// Create an empty file to bind a file onto, if absent.
    Touch(CString),
    /// `readonly` holds the source's locked flags (nosuid/nodev/noexec) to repeat on the read-only
    /// remount (dropping one fails with EPERM in a userns). `tree` is the detached copy of `source`
    /// taken before any mounting, so sources under a later tmpfs (e.g. /tmp) are still bindable.
    Bind {
        source: CString,
        target: CString,
        readonly: Option<libc::c_ulong>,
        tree: std::cell::Cell<RawFd>,
    },
    Tmpfs {
        target: CString,
        options: CString,
        flags: libc::c_ulong,
    },
}

/// open_tree(2): a detached, non-recursive copy of the mount at a path (like MS_BIND without MS_REC).
const OPEN_TREE_CLONE: libc::c_uint = 1;
/// move_mount(2): the source is the fd itself.
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;

/// Everything the child needs to set up its mount ns, built before clone() (no allocation after).
///
/// With a rootfs, targets are created under it and the child pivots into it. Without one, mounts
/// go over the host's paths inside the child's private mount ns; targets must already exist
/// (`check_mounts` enforces it at build()).
pub(super) struct MountPlan {
    rootfs: Option<CString>,
    steps: Vec<MountStep>,
    /// Where a fresh procfs goes, so `/proc` shows the sandbox's own pid namespace.
    proc_target: CString,
}

impl MountPlan {
    /// `restricted`: AppArmor denies mounting (see `userns_restricted_by_apparmor`), so private_tmp isn't a tmpfs.
    pub(super) fn new(config: &SandboxConfig, restricted: bool) -> Result<Self> {
        let rootfs = config.rootfs.as_deref();
        let tmpfs = Self::tmpfs_mounts(config, restricted);
        // `.git/hooks` in a writable area, made read-only so a hook can't be planted for the
        // host's git. Needs a mount, so only where one is possible (not under the AppArmor
        // restriction, and not with a rootfs, where the area is the caller's own tree).
        let vcs_ro: Vec<Mount> = if rootfs.is_none() && !restricted {
            crate::platform::read_rules::vcs_protected_paths(config)
                .into_iter()
                .map(|p| Mount {
                    source: p.clone(),
                    target: p,
                    permission: Permission::ReadOnly,
                })
                .collect()
        } else {
            Vec::new()
        };
        let binds: Vec<&Mount> = config
            .mounts
            .iter()
            .chain(vcs_ro.iter())
            .filter(|m| Self::needs_bind(config, &tmpfs, m))
            .collect();

        let masks = Self::masks(config, &tmpfs)?;

        // A read-only mount (or a mask) in a writable area protects the path but not its parents:
        // `mv dir dir.bak` then a new `dir` is writable. Mount points can't be renamed, so each
        // movable parent directory (the area's own directory included) is mounted onto itself too.
        let mut pins: Vec<Mount> = Vec::new();
        if rootfs.is_none() {
            let areas: Vec<PathBuf> = super::landlock::writable_areas(config)
                .map(Path::to_path_buf)
                .collect();
            let protected = binds
                .iter()
                .filter(|m| m.permission == Permission::ReadOnly)
                .map(|m| m.target.as_path())
                .chain(masks.iter().map(|(p, _)| p.as_path()));
            for target in protected {
                if !areas
                    .iter()
                    .any(|a| a.as_path() != target && target.starts_with(a))
                {
                    continue;
                }
                for dir in target.ancestors().skip(1) {
                    if dir == Path::new("/") || !areas.iter().any(|a| dir.starts_with(a)) {
                        break;
                    }
                    let taken = binds.iter().any(|b| b.target == dir)
                        || pins.iter().any(|p| p.target == dir)
                        || masks.iter().any(|(p, _)| p == dir);
                    if !taken {
                        pins.push(Mount {
                            source: dir.to_path_buf(),
                            target: dir.to_path_buf(),
                            permission: Permission::ReadWrite,
                        });
                    }
                }
            }
        }

        // One order, shallowest target first: a mount must exist before anything mounts under it.
        // Grouping tmpfs before binds shadowed a tmpfs nested in a bind target.
        enum Item<'a> {
            Tmpfs(&'a Path, u64),
            Bind(&'a Mount),
            Mask(&'a Path, bool),
        }
        let mut items: Vec<Item> = tmpfs
            .iter()
            .map(|(p, s)| Item::Tmpfs(p, *s))
            .chain(binds.iter().map(|&m| Item::Bind(m)))
            .chain(pins.iter().map(Item::Bind))
            .chain(masks.iter().map(|(p, dir)| Item::Mask(p, *dir)))
            .collect();
        items.sort_by_key(|item| {
            match item {
                Item::Tmpfs(p, _) | Item::Mask(p, _) => *p,
                Item::Bind(m) => m.target.as_path(),
            }
            .components()
            .count()
        });

        let mut steps = Vec::new();
        for item in items {
            match item {
                Item::Tmpfs(path, size) => {
                    let target = Self::target(&mut steps, rootfs, path, &tmpfs, true)?;
                    let options = CString::new(format!("size={size}")).expect("no NUL in a number");
                    steps.push(MountStep::Tmpfs {
                        target,
                        options,
                        flags: 0,
                    });
                }
                // An empty, read-only directory or file over the denied path.
                Item::Mask(path, true) => steps.push(MountStep::Tmpfs {
                    target: path_cstring(path)?,
                    options: c"size=4k,nr_inodes=1,mode=000".to_owned(),
                    flags: libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                }),
                Item::Mask(path, false) => {
                    let source = c"/dev/null".to_owned();
                    let readonly = Some(locked_flags(&source));
                    steps.push(MountStep::Bind {
                        source,
                        target: path_cstring(path)?,
                        readonly,
                        tree: std::cell::Cell::new(-1),
                    });
                }
                Item::Bind(m) => {
                    let is_dir = m.source.is_dir();
                    let target = Self::target(&mut steps, rootfs, &m.target, &tmpfs, is_dir)?;
                    let source = path_cstring(&m.source)?;
                    let readonly =
                        (m.permission == Permission::ReadOnly).then(|| locked_flags(&source));
                    steps.push(MountStep::Bind {
                        source,
                        target,
                        readonly,
                        tree: std::cell::Cell::new(-1),
                    });
                }
            }
        }
        let proc_target = match rootfs {
            Some(rootfs) => path_cstring(&rootfs.join("proc"))?,
            None => c"/proc".to_owned(),
        };
        Ok(Self {
            rootfs: rootfs.map(path_cstring).transpose()?,
            steps,
            proc_target,
        })
    }

    /// Denied paths (`read_rules::denied`) inside a writable area, and whether each is a directory.
    /// Landlock only adds access, so the area's rule would make them readable; they're mounted
    /// over instead. Ones under a tmpfs are hidden by it already.
    fn masks(config: &SandboxConfig, tmpfs: &[(PathBuf, u64)]) -> Result<Vec<(PathBuf, bool)>> {
        if config.rootfs.is_some() {
            return Ok(Vec::new());
        }
        let areas: Vec<PathBuf> = super::landlock::writable_areas(config)
            .filter_map(|a| std::fs::canonicalize(a).ok())
            .collect();
        let mut masks = Vec::new();
        for denied in crate::platform::read_rules::denied(config) {
            let inside = areas.iter().any(|a| *a != denied && denied.starts_with(a));
            if !inside || tmpfs.iter().any(|(t, _)| denied.starts_with(t)) {
                continue;
            }
            if let Some(granted) =
                crate::platform::read_rules::granted(config, std::slice::from_ref(&denied)).first()
            {
                return Err(SandboxError::Config {
                    context: format!(
                        "{} is denied reading inside a writable directory, so it's hidden by a \
                         mount; {} inside it can't be shown through that",
                        denied.display(),
                        granted.display()
                    ),
                    source: None,
                });
            }
            let is_dir = denied.is_dir();
            masks.push((denied, is_dir));
        }
        Ok(masks)
    }

    /// Caller tmpfs mounts, private_tmp's at /tmp where mountable, and private tmpfs over
    /// `/var/tmp` and `/dev/shm`: both are unconditionally in `landlock::DEFAULT_WRITABLE`, so
    /// unscoped they'd be the host's shared paths. Skipped where `restricted` rules out mounting
    /// (same residual gap as private_tmp).
    pub(super) fn tmpfs_mounts(config: &SandboxConfig, restricted: bool) -> Vec<(PathBuf, u64)> {
        let mut tmpfs = config.tmpfs_mounts.clone();
        if let Some(size) = config.private_tmp.filter(|_| !restricted) {
            tmpfs.insert(0, (PathBuf::from("/tmp"), size));
        }
        if !restricted {
            for path in ["/var/tmp", "/dev/shm"] {
                let path = Path::new(path);
                // An explicit read_only/writable/bind of this path means the caller wants the host's: that wins.
                let explicitly_mounted = config.mounts.iter().any(|m| m.target == path);
                // Not caller-chosen, so a minimal system missing the target mustn't fail unrelated sandboxes.
                if path.is_dir() && !explicitly_mounted && !tmpfs.iter().any(|(p, _)| p == path) {
                    tmpfs.push((path.to_path_buf(), crate::DEFAULT_PRIVATE_TMP_SIZE));
                }
            }
        }
        tmpfs
    }

    /// Whether a read_only/writable/bind path needs a real bind mount. Without a rootfs a host path
    /// at its own path needs none (Landlock decides), unless it's elsewhere, under a hiding tmpfs,
    /// or read-only inside a writable area (Landlock can't take writing away).
    fn needs_bind(config: &SandboxConfig, tmpfs: &[(PathBuf, u64)], m: &Mount) -> bool {
        if config.rootfs.is_some() {
            return true;
        }
        let canonical = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        if canonical(&m.source) != canonical(&m.target) {
            return true;
        }
        if tmpfs.iter().any(|(t, _)| m.target.starts_with(t)) {
            return true;
        }
        m.permission == Permission::ReadOnly
            && super::landlock::writable_areas(config)
                .any(|area| area != m.target.as_path() && m.target.starts_with(area))
    }

    /// The path to mount at. Under a rootfs also queues a mkdir per component; without one the
    /// target must exist unless inside a `tmpfs` (empty; created in it). `is_dir`: last component
    /// is a directory rather than a file to bind onto.
    fn target(
        steps: &mut Vec<MountStep>,
        rootfs: Option<&Path>,
        target: &Path,
        tmpfs: &[(PathBuf, u64)],
        is_dir: bool,
    ) -> Result<CString> {
        let (mut path, below) = match rootfs {
            Some(rootfs) => (
                rootfs.to_path_buf(),
                target.strip_prefix("/").unwrap_or(target),
            ),
            None => match tmpfs
                .iter()
                .filter(|(t, _)| t != target && target.starts_with(t))
                .max_by_key(|(t, _)| t.components().count())
            {
                Some((t, _)) => (t.clone(), target.strip_prefix(t).expect("checked above")),
                None => return path_cstring(target),
            },
        };
        let components: Vec<_> = below.components().collect();
        for (i, component) in components.iter().enumerate() {
            path.push(component);
            let last = i + 1 == components.len();
            steps.push(if last && !is_dir {
                MountStep::Touch(path_cstring(&path)?)
            } else {
                MountStep::Mkdir(path_cstring(&path)?)
            });
        }
        path_cstring(&path)
    }

    /// Whether there's anything to mount besides the `/proc` always added.
    pub(super) fn requested(&self) -> bool {
        self.rootfs.is_some() || !self.steps.is_empty()
    }

    /// Child, between clone() and exec(): raw syscalls only.
    pub(super) fn apply(&self) -> std::result::Result<(), &'static str> {
        let null = std::ptr::null();
        unsafe {
            if libc::mount(
                null,
                c"/".as_ptr(),
                null,
                libc::MS_REC | libc::MS_PRIVATE,
                null as _,
            ) != 0
            {
                return Err("mark all mounts as private");
            }
            if let Some(rootfs) = &self.rootfs {
                let rootfs = rootfs.as_ptr();
                if libc::mount(
                    rootfs,
                    rootfs,
                    null,
                    libc::MS_BIND | libc::MS_REC,
                    null as _,
                ) != 0
                {
                    return Err("bind mount rootfs");
                }
            }
            // Take every bind's source now, before any tmpfs can cover it.
            for step in &self.steps {
                if let MountStep::Bind { source, tree, .. } = step {
                    let fd = libc::syscall(
                        libc::SYS_open_tree,
                        libc::AT_FDCWD,
                        source.as_ptr(),
                        OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint,
                    );
                    if fd < 0 {
                        return Err("open bind source");
                    }
                    tree.set(fd as RawFd);
                }
            }
            for step in &self.steps {
                match step {
                    MountStep::Mkdir(path) => {
                        if libc::mkdir(path.as_ptr(), 0o755) != 0
                            && *libc::__errno_location() != libc::EEXIST
                        {
                            return Err("create mount target");
                        }
                    }
                    MountStep::Touch(path) => {
                        let fd = libc::open(
                            path.as_ptr(),
                            libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC,
                            0o644,
                        );
                        if fd < 0 {
                            return Err("create mount target");
                        }
                        libc::close(fd);
                    }
                    MountStep::Bind {
                        target,
                        readonly,
                        tree,
                        ..
                    } => {
                        let moved = libc::syscall(
                            libc::SYS_move_mount,
                            tree.get(),
                            c"".as_ptr(),
                            libc::AT_FDCWD,
                            target.as_ptr(),
                            MOVE_MOUNT_F_EMPTY_PATH,
                        );
                        libc::close(tree.get());
                        if moved != 0 {
                            return Err("bind mount");
                        }
                        // MS_RDONLY is ignored at bind creation, only taking effect on remount (a ReadOnly mount
                        // without it was writable on the host).
                        if let Some(locked) = readonly {
                            let flags = libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | locked;
                            if libc::mount(null, target.as_ptr(), null, flags, null as _) != 0 {
                                return Err("remount bind mount read-only");
                            }
                        }
                    }
                    MountStep::Tmpfs {
                        target,
                        options,
                        flags,
                    } => {
                        let tmpfs = c"tmpfs".as_ptr();
                        let options = options.as_ptr() as _;
                        if libc::mount(tmpfs, target.as_ptr(), tmpfs, *flags, options) != 0 {
                            return Err("mount tmpfs");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Mounts a fresh procfs; best effort. Must precede `enter_rootfs`: the kernel needs a fully
    /// visible proc in the mount ns, and pivoting drops the host's.
    pub(super) fn mount_proc(&self) -> bool {
        let target = self.proc_target.as_ptr();
        unsafe {
            if libc::mkdir(target, 0o555) != 0 && *libc::__errno_location() != libc::EEXIST {
                return false;
            }
            let proc = c"proc".as_ptr();
            let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
            libc::mount(proc, target, proc, flags, std::ptr::null()) == 0
        }
    }

    /// Pivots into the rootfs, if there is one.
    pub(super) fn enter_rootfs(&self) -> std::result::Result<(), &'static str> {
        let Some(rootfs) = &self.rootfs else {
            return Ok(());
        };
        let rootfs = rootfs.as_ptr();
        unsafe {
            // pivot_root(".", ".") then detaching stacks and drops the old root with no put_old dir; a
            // shared `<rootfs>/old_root` raced under concurrent runs. Same approach as runc.
            if libc::chdir(rootfs) != 0 {
                return Err("chdir into rootfs");
            }
            if libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) != 0 {
                return Err("pivot_root");
            }
            if libc::umount2(c".".as_ptr(), libc::MNT_DETACH) != 0 {
                return Err("detach old root");
            }
            if libc::chdir(c"/".as_ptr()) != 0 {
                return Err("chdir to new root");
            }
        }
        Ok(())
    }
}

/// A root caller's sandbox runs as nobody or the chosen ids (see namespace::runs_as_root), so a
/// writable grant needs that user to be able to write there. Catch it at build(), not as EACCES
/// in the program. The source's permissions count: the bind brings the host directory along.
fn check_writable_by_sandbox(config: &SandboxConfig) -> Result<()> {
    if !super::namespace::runs_as_root() {
        return Ok(());
    }
    let (uid, gid) = super::namespace::UserNamespace::new(None, None)
        .with_host_ids(config.host_uid, config.host_gid)
        .host_ids();
    let chosen = config.host_uid.is_some() || config.host_gid.is_some();
    for m in &config.mounts {
        if m.permission == Permission::ReadWrite && !can_write(&m.source, uid, gid).unwrap_or(true)
        {
            let who = if chosen {
                format!("uid {uid}/gid {gid} (host_uid/host_gid)")
            } else {
                format!("uid {uid}/gid {gid} (nobody; host_uid/host_gid choose another user)")
            };
            return Err(SandboxError::Config {
                context: format!(
                    "writable {}: the sandbox runs as {who}, which can't write here. chmod it \
                     to allow group or other write, change its owner, or set host_uid/host_gid \
                     to its owner",
                    m.source.display(),
                ),
                source: None,
            });
        }
    }
    Ok(())
}

/// Refuses mount setups that can only fail or misbehave at run time.
pub(super) fn check_mounts(config: &SandboxConfig) -> Result<()> {
    let restricted = super::userns_restricted_by_apparmor();
    let plan = MountPlan::new(config, restricted)?;
    if plan.requested() && restricted {
        return Err(SandboxError::Unsupported {
            setting: "rootfs, tmpfs, bind, or read_only inside a writable directory (or a \
                      deny_read path inside one)"
                .into(),
            reason: "these need to mount inside the sandbox's user namespace, which AppArmor \
                     denies here (kernel.apparmor_restrict_unprivileged_userns=1 for an \
                     unprivileged, unconfined process). Run as root, set that sysctl to 0, or \
                     give this executable an AppArmor profile that allows userns"
                .into(),
        });
    }
    if config.rootfs.is_some() {
        return check_writable_by_sandbox(config);
    }
    let tmpfs = MountPlan::tmpfs_mounts(config, restricted);
    let in_tmpfs = |path: &Path| tmpfs.iter().any(|(t, _)| t != path && path.starts_with(t));
    for (path, _) in &config.tmpfs_mounts {
        if !path.exists() {
            return Err(SandboxError::Config {
                context: format!(
                    "tmpfs path {} does not exist; without a rootfs, it's mounted over the \
                     host's own path, which must already exist",
                    path.display()
                ),
                source: None,
            });
        }
    }
    for m in &config.mounts {
        if !in_tmpfs(&m.target) && !m.target.exists() {
            return Err(SandboxError::Config {
                context: format!(
                    "bind target {} does not exist; without a rootfs, binds go over the host's \
                     own paths, so it must already exist",
                    m.target.display()
                ),
                source: None,
            });
        }
    }
    check_writable_by_sandbox(config)?;
    // A tmpfs starts empty: only what's bound into it is there.
    let wd = &config.working_dir;
    if in_tmpfs(wd) && !config.mounts.iter().any(|m| wd.starts_with(&m.target)) {
        return Err(SandboxError::Config {
            context: format!(
                "working_dir {} is inside a tmpfs, which starts empty; make it readable or \
                 writable to have it there",
                wd.display()
            ),
            source: None,
        });
    }
    Ok(())
}

fn path_cstring(path: &std::path::Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|e| SandboxError::Config {
        context: format!("path contains a NUL byte: {}", path.display()),
        source: Some(Box::new(e)),
    })
}

/// nosuid/nodev/noexec currently set on the mount holding `path`.
fn locked_flags(path: &CString) -> libc::c_ulong {
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 {
        return 0;
    }
    let mut flags = 0;
    for (st_flag, ms_flag) in [
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
    ] {
        if st.f_flag & st_flag != 0 {
            flags |= ms_flag;
        }
    }
    flags
}

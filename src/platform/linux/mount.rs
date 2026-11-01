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

/// Where a step acts. `Host` is an absolute host path (no rootfs). `InRoot` is resolved inside
/// the rootfs with `open_in_root`, so a symlink planted in it can't lead the mkdir, file creation
/// or mount out onto the host; `rel` is the whole path, `parent`/`name` its split for `mkdirat`.
enum Target {
    Host(CString),
    InRoot {
        rel: CString,
        parent: CString,
        name: CString,
    },
}

/// One mount-ns setup step with all paths/options prebuilt (see `MountPlan`).
enum MountStep {
    /// `mkdir`, EEXIST ignored. Issued per component in order with the mounts, so a target nested
    /// in an earlier mount is created inside it.
    Mkdir(Target),
    /// Create an empty file to bind a file onto, if absent.
    Touch(Target),
    /// `readonly` holds the source's locked flags (nosuid/nodev/noexec) to repeat on the read-only
    /// remount (dropping one fails with EPERM in a userns). `tree` is the detached copy of `source`
    /// taken before any mounting, so sources under a later tmpfs (e.g. /tmp) are still bindable.
    Bind {
        source: CString,
        target: Target,
        readonly: Option<libc::c_ulong>,
        tree: std::cell::Cell<RawFd>,
    },
    Tmpfs {
        target: Target,
        options: CString,
        flags: libc::c_ulong,
    },
}

/// open_tree(2): a detached, non-recursive copy of the mount at a path (like MS_BIND without MS_REC).
const OPEN_TREE_CLONE: libc::c_uint = 1;
/// move_mount(2): the source is the fd itself.
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;
/// move_mount(2): the target is the fd itself.
const MOVE_MOUNT_T_EMPTY_PATH: libc::c_uint = 0x40;
/// openat2(2) resolve flags: scope every lookup to the dirfd as `/`, so an absolute or `..`
/// symlink can't escape it, and refuse magic links (/proc/*/fd).
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// `openat2(dirfd, path, { flags|O_CLOEXEC, mode, RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS })`.
/// The fd, or -1 with errno set. With `dirfd` the rootfs, the path resolves as if the rootfs were
/// `/`, so a symlink planted in it can't redirect the lookup onto the host.
unsafe fn open_in_root(dirfd: RawFd, path: &CString, flags: libc::c_int, mode: u32) -> RawFd {
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: u64::from(mode),
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    };
    unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        ) as RawFd
    }
}

/// `/proc/self/fd/<fd>` into `buf`, for the few syscalls that take only a path. No allocation.
fn fd_path(fd: RawFd, buf: &mut [u8; 32]) -> *const libc::c_char {
    let prefix = b"/proc/self/fd/";
    buf[..prefix.len()].copy_from_slice(prefix);
    let mut digits = [0u8; 10];
    let (mut len, mut n) = (0usize, fd.max(0) as u32);
    loop {
        digits[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    for i in 0..len {
        buf[prefix.len() + i] = digits[len - 1 - i];
    }
    buf[prefix.len() + len] = 0;
    buf.as_ptr().cast()
}

/// Everything the child needs to set up its mount ns, built before clone() (no allocation after).
///
/// With a rootfs, targets are created under it and the child pivots into it. Without one, mounts
/// go over the host's paths inside the child's private mount ns; targets must already exist
/// (`check_mounts` enforces it at build()).
pub(super) struct MountPlan {
    rootfs: Option<CString>,
    /// The rootfs, opened once it's bound onto itself; `InRoot` targets resolve below it.
    root_fd: std::cell::Cell<RawFd>,
    steps: Vec<MountStep>,
    /// Where a fresh procfs goes, so `/proc` shows the sandbox's own pid namespace.
    proc_target: Target,
}

impl MountPlan {
    /// `restricted`: AppArmor denies mounting (see `userns_restricted_by_apparmor`), so private_tmp isn't a tmpfs.
    pub(super) fn new(config: &SandboxConfig, restricted: bool) -> Result<Self> {
        let rootfs = config.rootfs.as_deref();
        let tmpfs = Self::tmpfs_mounts(config, restricted);
        let binds: Vec<&Mount> = config
            .mounts
            .iter()
            .filter(|m| Self::needs_bind(config, &tmpfs, m))
            .collect();

        let masks = Self::masks(config, &tmpfs, &binds)?;

        // A read-only mount (or a mask) in a writable area protects the path but not its parents:
        // `mv dir dir.bak` then a new `dir` is writable. Mount points can't be renamed, so each
        // movable parent directory (the area's own directory included) is mounted onto itself too.
        let mut pins: Vec<Mount> = Vec::new();
        if rootfs.is_none() {
            // Resolved, like the masks: a symlink spelling on either side mustn't skip a pin.
            let canonical = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
            let areas: Vec<PathBuf> = super::landlock::writable_areas(config)
                .map(canonical)
                .collect();
            let protected: Vec<PathBuf> = binds
                .iter()
                .filter(|m| m.permission == Permission::ReadOnly)
                .map(|m| canonical(&m.target))
                .chain(masks.iter().map(|(p, _)| p.clone()))
                .collect();
            for target in protected.iter().map(PathBuf::as_path) {
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
                    target: Target::Host(path_cstring(path)?),
                    options: c"size=4k,nr_inodes=1,mode=000".to_owned(),
                    flags: libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                }),
                Item::Mask(path, false) => {
                    let source = c"/dev/null".to_owned();
                    let readonly = Some(locked_flags(&source));
                    steps.push(MountStep::Bind {
                        source,
                        target: Target::Host(path_cstring(path)?),
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
            Some(_) => Target::InRoot {
                rel: c"proc".to_owned(),
                parent: c".".to_owned(),
                name: c"proc".to_owned(),
            },
            None => Target::Host(c"/proc".to_owned()),
        };
        Ok(Self {
            rootfs: rootfs.map(path_cstring).transpose()?,
            root_fd: std::cell::Cell::new(-1),
            steps,
            proc_target,
        })
    }

    /// Denied paths (`read_rules::denied`) inside a writable area, and whether each is a directory.
    /// Landlock only adds access, so the area's rule would make them readable; they're mounted
    /// over instead. Ones under a tmpfs are hidden by it already, unless a bind mount brings
    /// them back (a workspace under `/tmp` is bound into the tmpfs over it).
    fn masks(
        config: &SandboxConfig,
        tmpfs: &[(PathBuf, u64)],
        binds: &[&Mount],
    ) -> Result<Vec<(PathBuf, bool)>> {
        if config.rootfs.is_some() {
            return Ok(Vec::new());
        }
        let areas: Vec<PathBuf> = super::landlock::writable_areas(config)
            .filter_map(|a| std::fs::canonicalize(a).ok())
            .collect();
        let mut masks = Vec::new();
        for denied in crate::platform::read_rules::denied(config) {
            let inside = areas.iter().any(|a| *a != denied && denied.starts_with(a));
            let hidden = tmpfs.iter().any(|(t, _)| denied.starts_with(t))
                && !binds.iter().any(|b| {
                    let target =
                        std::fs::canonicalize(&b.target).unwrap_or_else(|_| b.target.clone());
                    denied.starts_with(target)
                });
            if !inside || hidden {
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
        // Resolved on both sides: a writable area named through a symlink still contains
        // the read_only path named by its real path.
        let target = canonical(&m.target);
        let inside = |p: &Path| p != target && target.starts_with(p);
        match m.permission {
            Permission::ReadOnly => super::landlock::writable_areas(config)
                .map(canonical)
                .any(|area| inside(&area)),
            // A writable under a read-only mount is read-only with it unless remounted on top.
            Permission::ReadWrite => config
                .mounts
                .iter()
                .filter(|o| o.permission == Permission::ReadOnly)
                .any(|o| inside(&canonical(&o.target))),
        }
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
    ) -> Result<Target> {
        // With a rootfs, targets are relative to it and resolved in it (open_in_root), so each
        // component's mkdir/touch runs through the resolved parent, never a host path.
        if rootfs.is_some() {
            let below = target.strip_prefix("/").unwrap_or(target);
            let components: Vec<_> = below.components().collect();
            let mut rel = PathBuf::from(".");
            let mut last_target = Target::InRoot {
                rel: c".".to_owned(),
                parent: c".".to_owned(),
                name: c".".to_owned(),
            };
            for (i, component) in components.iter().enumerate() {
                let parent = path_cstring(&rel)?;
                rel.push(component);
                let name = path_cstring(Path::new(component.as_os_str()))?;
                let at = Target::InRoot {
                    rel: path_cstring(&rel)?,
                    parent: parent.clone(),
                    name: name.clone(),
                };
                steps.push(if i + 1 == components.len() && !is_dir {
                    MountStep::Touch(at)
                } else {
                    MountStep::Mkdir(at)
                });
                last_target = Target::InRoot {
                    rel: path_cstring(&rel)?,
                    parent,
                    name,
                };
            }
            return Ok(last_target);
        }
        let (mut path, below) = match tmpfs
            .iter()
            .filter(|(t, _)| t != target && target.starts_with(t))
            .max_by_key(|(t, _)| t.components().count())
        {
            Some((t, _)) => (t.clone(), target.strip_prefix(t).expect("checked above")),
            None => return Ok(Target::Host(path_cstring(target)?)),
        };
        let components: Vec<_> = below.components().collect();
        for (i, component) in components.iter().enumerate() {
            path.push(component);
            let last = i + 1 == components.len();
            let at = Target::Host(path_cstring(&path)?);
            steps.push(if last && !is_dir {
                MountStep::Touch(at)
            } else {
                MountStep::Mkdir(at)
            });
        }
        Ok(Target::Host(path_cstring(&path)?))
    }

    /// `mkdir`, EEXIST counting as success.
    unsafe fn mkdir(&self, at: &Target, mode: u32) -> bool {
        let made = |r: libc::c_int| r == 0 || unsafe { *libc::__errno_location() } == libc::EEXIST;
        unsafe {
            match at {
                Target::Host(path) => made(libc::mkdir(path.as_ptr(), mode)),
                Target::InRoot { parent, name, .. } => {
                    let dir = open_in_root(
                        self.root_fd.get(),
                        parent,
                        libc::O_PATH | libc::O_DIRECTORY,
                        0,
                    );
                    if dir < 0 {
                        return false;
                    }
                    let ok = made(libc::mkdirat(dir, name.as_ptr(), mode));
                    libc::close(dir);
                    ok
                }
            }
        }
    }

    /// Creates an empty file if absent. Only a regular file will do: a FIFO a previous run left
    /// at the target would block the open (O_NONBLOCK: ENXIO instead), a device would be bound over.
    unsafe fn touch(&self, at: &Target) -> bool {
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NONBLOCK;
        unsafe {
            let fd = match at {
                Target::Host(path) => libc::open(path.as_ptr(), flags, 0o644),
                Target::InRoot { rel, .. } => open_in_root(self.root_fd.get(), rel, flags, 0o644),
            };
            if fd < 0 {
                return false;
            }
            let mut st: libc::stat = std::mem::zeroed();
            let regular =
                libc::fstat(fd, &mut st) == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFREG;
            libc::close(fd);
            regular
        }
    }

    /// Attaches the detached mount `tree` at `at`.
    unsafe fn move_mount_to(&self, tree: RawFd, at: &Target) -> bool {
        unsafe {
            match at {
                Target::Host(path) => {
                    libc::syscall(
                        libc::SYS_move_mount,
                        tree,
                        c"".as_ptr(),
                        libc::AT_FDCWD,
                        path.as_ptr(),
                        MOVE_MOUNT_F_EMPTY_PATH,
                    ) == 0
                }
                Target::InRoot { rel, .. } => {
                    let fd = open_in_root(self.root_fd.get(), rel, libc::O_PATH, 0);
                    if fd < 0 {
                        return false;
                    }
                    let ok = libc::syscall(
                        libc::SYS_move_mount,
                        tree,
                        c"".as_ptr(),
                        fd,
                        c"".as_ptr(),
                        MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
                    ) == 0;
                    libc::close(fd);
                    ok
                }
            }
        }
    }

    /// Runs `f` with a path for `at`: the host path, or `/proc/self/fd/N` of it resolved inside
    /// the rootfs (opened afresh, so it reflects mounts made on it since).
    unsafe fn with_path(&self, at: &Target, f: impl FnOnce(*const libc::c_char) -> bool) -> bool {
        match at {
            Target::Host(path) => f(path.as_ptr()),
            Target::InRoot { rel, .. } => unsafe {
                let fd = open_in_root(self.root_fd.get(), rel, libc::O_PATH, 0);
                if fd < 0 {
                    return false;
                }
                let mut buf = [0u8; 32];
                let ok = f(fd_path(fd, &mut buf));
                libc::close(fd);
                ok
            },
        }
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
                let fd = libc::open(rootfs, libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC);
                if fd < 0 {
                    return Err("open rootfs");
                }
                self.root_fd.set(fd);
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
                    MountStep::Mkdir(at) => {
                        if !self.mkdir(at, 0o755) {
                            return Err("create mount target");
                        }
                    }
                    MountStep::Touch(at) => {
                        if !self.touch(at) {
                            return Err("create mount target");
                        }
                    }
                    MountStep::Bind {
                        target,
                        readonly,
                        tree,
                        ..
                    } => {
                        let moved = self.move_mount_to(tree.get(), target);
                        libc::close(tree.get());
                        if !moved {
                            return Err("bind mount");
                        }
                        // MS_RDONLY is ignored at bind creation, only taking effect on remount (a ReadOnly mount
                        // without it was writable on the host).
                        if let Some(locked) = readonly {
                            let flags = libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | locked;
                            let remounted = self.with_path(target, |path| {
                                libc::mount(null, path, null, flags, null as _) == 0
                            });
                            if !remounted {
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
                        let mounted = self.with_path(target, |path| {
                            libc::mount(tmpfs, path, tmpfs, *flags, options) == 0
                        });
                        if !mounted {
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
        unsafe {
            if !self.mkdir(&self.proc_target, 0o555) {
                return false;
            }
            let proc = c"proc".as_ptr();
            let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
            self.with_path(&self.proc_target, |path| {
                libc::mount(proc, path, proc, flags, std::ptr::null()) == 0
            })
        }
    }

    /// Pivots into the rootfs, if there is one.
    pub(super) fn enter_rootfs(&self) -> std::result::Result<(), &'static str> {
        let Some(rootfs) = &self.rootfs else {
            return Ok(());
        };
        let rootfs = rootfs.as_ptr();
        unsafe {
            libc::close(self.root_fd.get());
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
        let probe = unsafe { open_in_root(libc::AT_FDCWD, &c"/".to_owned(), libc::O_PATH, 0) };
        if probe < 0 {
            return Err(SandboxError::Unsupported {
                setting: "rootfs".into(),
                reason: "setting it up safely needs openat2(2), Linux 5.6+".into(),
            });
        }
        unsafe { libc::close(probe) };
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    /// open_in_root keeps an absolute symlink planted in the root from escaping it.
    #[test]
    fn test_open_in_root_contains_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(outside.path().join("exists")).unwrap();
        // data -> /abs/outside; RESOLVE_IN_ROOT must read it as <root>/abs/outside.
        std::os::unix::fs::symlink(outside.path(), root.path().join("data")).unwrap();
        std::fs::create_dir(root.path().join("real")).unwrap();

        let rfd = std::fs::File::open(root.path()).unwrap();
        let open = |rel: &str| unsafe {
            let p = CString::new(rel).unwrap();
            open_in_root(rfd.as_raw_fd(), &p, libc::O_PATH, 0)
        };
        // A path through the escaping symlink resolves inside the root, where it doesn't exist.
        let escaped = open("data/exists");
        assert!(escaped < 0, "symlink escaped the root");
        // A real path inside the root still opens.
        let inside = open("real");
        assert!(inside >= 0, "a real in-root path failed");
        unsafe { libc::close(inside) };
    }
}

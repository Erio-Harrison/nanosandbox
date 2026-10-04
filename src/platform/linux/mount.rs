//! Mount namespace planning: what to mount where, built before clone() so
//! the child (which applies the plan) only issues raw syscalls.

use crate::builder::{Mount, Permission, SandboxConfig};
use crate::error::{Result, SandboxError};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

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

/// One mount-namespace setup step, with every path and option string
/// already built -- see `MountPlan`.
enum MountStep {
    /// `mkdir`, EEXIST ignored. Issued per path component, in order with the
    /// mounts, so a target nested inside an earlier mount is created inside
    /// that mount, same as `create_dir_all` right before each mount was.
    Mkdir(CString),
    /// Create an empty file to bind a file onto, if there's nothing there.
    Touch(CString),
    /// `readonly` holds the source's locked flags (nosuid/nodev/noexec) to
    /// repeat on the read-only remount: in a user namespace, a remount that
    /// drops a locked flag fails with EPERM.
    /// `tree` is the detached copy of `source` that `apply` takes before
    /// mounting anything, so a source inside a path a tmpfs then covers
    /// (anything under /tmp, with private_tmp) is still there to bind.
    Bind {
        source: CString,
        target: CString,
        readonly: Option<libc::c_ulong>,
        tree: std::cell::Cell<RawFd>,
    },
    Tmpfs {
        target: CString,
        options: CString,
    },
}

/// open_tree(2): a detached copy of the mount at a path (non-recursive, like
/// MS_BIND without MS_REC).
const OPEN_TREE_CLONE: libc::c_uint = 1;
/// move_mount(2): the source is the fd itself.
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;

/// Everything the child needs to set up its mount namespace, built before
/// clone() so the child only issues raw syscalls -- the same
/// no-allocation-after-clone() rule as envp_cstr/working_dir_cstr.
///
/// With a rootfs, targets are created under it and the child pivots into it.
/// Without one, mounts go straight over the host's own paths, inside the
/// child's private mount namespace, so the host never sees them. Such a
/// target must already exist (an unprivileged child can't create one in a
/// host directory like `/`), which `check_mounts` enforces at build() time.
/// Without a rootfs these used to be silently ignored.
pub(super) struct MountPlan {
    rootfs: Option<CString>,
    steps: Vec<MountStep>,
    /// Where a fresh procfs goes, so `/proc` shows the sandbox's own pid
    /// namespace instead of every host process. Confirmed for real:
    /// `ps aux` listed host processes before.
    proc_target: CString,
}

impl MountPlan {
    /// `restricted`: AppArmor denies mounting (see
    /// `userns_restricted_by_apparmor`), so private_tmp isn't a tmpfs.
    pub(super) fn new(config: &SandboxConfig, restricted: bool) -> Result<Self> {
        let rootfs = config.rootfs.as_deref();
        let tmpfs = Self::tmpfs_mounts(config, restricted);
        let binds: Vec<&Mount> = config
            .mounts
            .iter()
            .filter(|m| Self::needs_bind(config, &tmpfs, m))
            .collect();

        // One combined order, shallowest target first: a mount has to be in
        // place before anything mounts under it, whichever kind either one
        // is. Grouping "all tmpfs, then all binds" instead used to shadow a
        // tmpfs nested inside a bind's target, while fixing the opposite,
        // bind-inside-a-tmpfs case -- confirmed for real.
        enum Item<'a> {
            Tmpfs(&'a Path, u64),
            Bind(&'a Mount),
        }
        let mut items: Vec<Item> = tmpfs
            .iter()
            .map(|(p, s)| Item::Tmpfs(p, *s))
            .chain(binds.iter().map(|&m| Item::Bind(m)))
            .collect();
        items.sort_by_key(|item| {
            match item {
                Item::Tmpfs(p, _) => *p,
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
                    steps.push(MountStep::Tmpfs { target, options });
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

    /// The caller's tmpfs mounts, plus private_tmp's at /tmp where it can be
    /// mounted.
    pub(super) fn tmpfs_mounts(config: &SandboxConfig, restricted: bool) -> Vec<(PathBuf, u64)> {
        let mut tmpfs = config.tmpfs_mounts.clone();
        if let Some(size) = config.private_tmp.filter(|_| !restricted) {
            tmpfs.insert(0, (PathBuf::from("/tmp"), size));
        }
        tmpfs
    }

    /// Whether a read_only/writable/bind path needs an actual bind mount.
    /// Without a rootfs, a host path at its own path is already there, and
    /// Landlock decides whether it's writable (see landlock.rs), with no
    /// mount at all. It still needs one if it's elsewhere (bind()), under a
    /// tmpfs that would hide it, or read-only inside a writable area, where
    /// Landlock can't take writing away again.
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

    /// The full path to mount at. Under a rootfs, also queues a mkdir for
    /// each component of it. Without one, the target must already exist,
    /// unless it's inside one of `tmpfs`: those start empty, so the part
    /// below the tmpfs is created in it. `is_dir`: whether the last
    /// component is a directory, or a file to bind a file onto.
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

    /// Whether there's anything to mount here (a rootfs, a bind, a tmpfs),
    /// as opposed to just the `/proc` this plan always adds.
    pub(super) fn requested(&self) -> bool {
        self.rootfs.is_some() || !self.steps.is_empty()
    }

    /// Runs in the child between clone() and exec(): raw syscalls only.
    /// The error names the step that failed, as a static string.
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
                        // MS_RDONLY is ignored when a bind mount is created;
                        // it only takes effect on a remount. Confirmed for
                        // real: a ReadOnly mount without this was writable,
                        // and the write landed on the host directory.
                        if let Some(locked) = readonly {
                            let flags = libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | locked;
                            if libc::mount(null, target.as_ptr(), null, flags, null as _) != 0 {
                                return Err("remount bind mount read-only");
                            }
                        }
                    }
                    MountStep::Tmpfs { target, options } => {
                        let tmpfs = c"tmpfs".as_ptr();
                        if libc::mount(tmpfs, target.as_ptr(), tmpfs, 0, options.as_ptr() as _) != 0
                        {
                            return Err("mount tmpfs");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Mounts the fresh procfs. Best effort: a failure here is logged by the
    /// child but doesn't stop the run. Must happen before `enter_rootfs`: the
    /// kernel only allows a new proc mount while a fully visible one is still
    /// in the mount namespace, and pivoting drops the host's.
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
            // pivot_root(".", ".") then detaching "." stacks the old root on
            // the new one and drops it, with no put_old directory. Every
            // sandbox used to share one `<rootfs>/old_root`, so concurrent
            // runs on the same rootfs raced creating, pivoting into, and
            // removing it -- confirmed for real as "Mount setup failed" under
            // 20 concurrent runs. Same approach as runc.
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

/// Refuses, at build() time, mount setups that can only fail or silently do
/// something other than asked once the sandbox runs.
pub(super) fn check_mounts(config: &SandboxConfig) -> Result<()> {
    let restricted = super::userns_restricted_by_apparmor();
    let plan = MountPlan::new(config, restricted)?;
    if plan.requested() && restricted {
        return Err(SandboxError::Unsupported {
            setting: "rootfs, tmpfs, bind, or read_only inside a writable directory".into(),
            reason: "these need to mount inside the sandbox's user namespace, which AppArmor \
                     denies here (kernel.apparmor_restrict_unprivileged_userns=1 for an \
                     unprivileged, unconfined process). Run as root, set that sysctl to 0, or \
                     give this executable an AppArmor profile that allows userns"
                .into(),
        });
    }
    if config.rootfs.is_some() {
        return Ok(());
    }
    let tmpfs = MountPlan::tmpfs_mounts(config, restricted);
    let in_tmpfs = |path: &Path| tmpfs.iter().any(|(t, _)| t != path && path.starts_with(t));
    for (path, _) in &config.tmpfs_mounts {
        if !path.exists() {
            return Err(SandboxError::Config(format!(
                "tmpfs path {} does not exist; without a rootfs, it's mounted over the \
                 host's own path, which must already exist",
                path.display()
            )));
        }
    }
    for m in &config.mounts {
        if !in_tmpfs(&m.target) && !m.target.exists() {
            return Err(SandboxError::Config(format!(
                "bind target {} does not exist; without a rootfs, binds go over the host's \
                 own paths, so it must already exist",
                m.target.display()
            )));
        }
    }
    // A tmpfs starts empty: only what's bound into it is there.
    let wd = &config.working_dir;
    if in_tmpfs(wd) && !config.mounts.iter().any(|m| wd.starts_with(&m.target)) {
        return Err(SandboxError::Config(format!(
            "working_dir {} is inside a tmpfs, which starts empty; make it readable or \
             writable to have it there",
            wd.display()
        )));
    }
    Ok(())
}

fn path_cstring(path: &std::path::Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| SandboxError::Config(format!("path contains a NUL byte: {}", path.display())))
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

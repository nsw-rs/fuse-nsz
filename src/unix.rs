// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! FUSE backend for Linux and macOS. The kernel speaks in inode numbers,
//! the core in paths: a table maps each path seen so far to an inode.
//! Inode numbers are never reused, so the generation is always 0.

use crate::vfs::{self, FsError, Handle, Node, Options, Vfs, lock};
use fuser::{
    BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, LockOwner, MountOption, OpenAccMode, OpenFlags, RenameFlags, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs,
    ReplyWrite, Request, Session, SessionACL, TimeOrNow, WriteFlags,
};
use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::fs::Permissions;
use std::io;
use std::ops::Bound;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const TTL: Duration = Duration::from_secs(1);

#[derive(Default)]
struct Inodes {
    /// Path of inode `i + 1`. Inode 1 is the root, the empty path.
    paths: Vec<PathBuf>,
    /// Ordered, so a directory and everything under it are one range.
    by_path: BTreeMap<PathBuf, u64>,
}

impl Inodes {
    fn ino(&mut self, path: &Path) -> INodeNo {
        if let Some(&ino) = self.by_path.get(path) {
            return INodeNo(ino);
        }
        self.paths.push(path.to_path_buf());
        let ino = self.paths.len() as u64;
        self.by_path.insert(path.to_path_buf(), ino);
        INodeNo(ino)
    }

    /// The live paths `path` and everything under it, with their inodes.
    fn subtree(&self, path: &Path) -> Vec<(PathBuf, u64)> {
        self.by_path
            .range::<Path, _>((Bound::Included(path), Bound::Unbounded))
            .take_while(|(p, _)| p.starts_with(path))
            .map(|(p, &ino)| (p.clone(), ino))
            .collect()
    }

    /// Forget the paths `path` and everything under it, so they get new
    /// inodes if they show up again.
    fn remove(&mut self, path: &Path) {
        for (p, _) in self.subtree(path) {
            self.by_path.remove(&p);
        }
    }

    /// Move the inodes of `old` and of everything under it to `new`, so
    /// open files and the kernel's cached entries keep working.
    fn rename(&mut self, old: &Path, new: &Path) {
        self.remove(new);
        // Only the live names: an inode removed earlier keeps its old path
        // in `paths` and must not get a name again.
        for (p, ino) in self.subtree(old) {
            let Ok(rest) = p.strip_prefix(old) else {
                continue;
            };
            let np = if rest.as_os_str().is_empty() {
                new.to_path_buf()
            } else {
                new.join(rest)
            };
            self.by_path.remove(&p);
            self.by_path.insert(np.clone(), ino);
            self.paths[ino as usize - 1] = np;
        }
    }
}

struct NszFs {
    vfs: Vfs,
    inodes: Mutex<Inodes>,
    files: Mutex<Handles<Arc<Handle>>>,
    dirs: Mutex<Handles<Arc<Listing>>>,
    uid: u32,
    gid: u32,
}

/// A directory listing taken at opendir.
type Listing = Vec<(INodeNo, FileType, OsString)>;

struct Handles<T> {
    next: u64,
    map: HashMap<u64, T>,
}

impl<T: Clone> Handles<T> {
    fn new() -> Self {
        Handles {
            next: 0,
            map: HashMap::new(),
        }
    }
    fn insert(&mut self, v: T) -> FileHandle {
        self.next += 1;
        self.map.insert(self.next, v);
        FileHandle(self.next)
    }
    fn get(&self, fh: FileHandle) -> Option<T> {
        self.map.get(&fh.0).cloned()
    }
    fn remove(&mut self, fh: FileHandle) {
        self.map.remove(&fh.0);
    }
}

fn errno(e: FsError) -> Errno {
    match e {
        FsError::NotFound => Errno::ENOENT,
        FsError::ReadOnly => Errno::EROFS,
        FsError::Denied => Errno::EACCES,
        FsError::Exists => Errno::EEXIST,
        FsError::IsDir => Errno::EISDIR,
        FsError::NotDir => Errno::ENOTDIR,
        FsError::Access => Errno::EACCES,
        FsError::Io(e) => e.raw_os_error().map_or(Errno::EIO, Errno::from_i32),
    }
}

impl NszFs {
    fn path(&self, ino: INodeNo) -> Option<PathBuf> {
        let inodes = lock(&self.inodes);
        let i = usize::try_from(ino.0).ok()?.checked_sub(1)?;
        inodes.paths.get(i).cloned()
    }

    fn attr(&self, ino: INodeNo, node: &Node) -> FileAttr {
        let dir = node.is_dir();
        let size = node.size();
        let t = node.mtime();
        FileAttr {
            ino,
            size,
            // du and tar --sparse take a file with zero blocks for an empty
            // one.
            blocks: size.div_ceil(512),
            atime: t,
            mtime: t,
            ctime: t,
            crtime: t,
            kind: if dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            // Samba takes a file without the w bit for a DOS read-only one
            // and refuses to delete or rename it, so in rw mode virtual
            // files show it too. Their content stays read-only.
            perm: (node.meta.permissions().mode() & if self.vfs.rw() { 0o777 } else { 0o555 })
                as u16,
            nlink: if dir { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// Path of `name` in directory `parent`.
    fn child(&self, parent: INodeNo, name: &OsStr) -> Option<PathBuf> {
        self.path(parent).map(|p| p.join(name))
    }

    fn reply_entry(&self, path: &Path, node: &Node, reply: ReplyEntry) {
        let ino = lock(&self.inodes).ino(path);
        reply.entry(&TTL, &self.attr(ino, node), Generation(0));
    }

    /// The changes of a setattr, in an order where a chmod cannot block
    /// the truncate before it.
    #[expect(clippy::too_many_arguments, reason = "the fields of a setattr")]
    fn set_attr(
        &self,
        path: &Path,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        fh: Option<FileHandle>,
    ) -> Result<(), Errno> {
        // Every file belongs to the mounting user.
        if uid.is_some_and(|u| u != self.uid) || gid.is_some_and(|g| g != self.gid) {
            return Err(Errno::EPERM);
        }
        if let Some(size) = size {
            match fh.and_then(|fh| lock(&self.files).get(fh)) {
                // open(O_RDONLY | O_TRUNC) reaches here as a read-only
                // open and then a truncate through that handle, which
                // the OS refuses: truncate by path then.
                Some(h) => match h.set_len(size) {
                    Err(FsError::Io(_)) => self.vfs.truncate(path, size),
                    r => r,
                },
                None => self.vfs.truncate(path, size),
            }
            .map_err(errno)?;
        }
        if let Some(m) = mode {
            self.vfs
                .set_permissions(path, Permissions::from_mode(m & 0o7777))
                .map_err(errno)?;
        }
        if atime.is_some() || mtime.is_some() {
            let t = |t: TimeOrNow| match t {
                TimeOrNow::SpecificTime(t) => t,
                TimeOrNow::Now => SystemTime::now(),
            };
            self.vfs
                .set_times(path, atime.map(t), mtime.map(t))
                .map_err(errno)?;
        }
        Ok(())
    }
}

impl Filesystem for NszFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(path) = self.child(parent, name) else {
            return reply.error(Errno::ENOENT);
        };
        match self.vfs.lookup(&path) {
            Ok(node) => self.reply_entry(&path, &node, reply),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let Some(path) = self.path(ino) else {
            return reply.error(Errno::ENOENT);
        };
        match self.vfs.lookup(&path) {
            Ok(node) => reply.attr(&TTL, &self.attr(ino, &node)),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let Some(path) = self.path(ino) else {
            return reply.error(Errno::ENOENT);
        };
        let write = flags.acc_mode() != OpenAccMode::O_RDONLY;
        let truncate = flags.0 & libc::O_TRUNC != 0;
        match self
            .vfs
            .lookup(&path)
            .and_then(|n| self.vfs.open(&path, n, write, truncate))
        {
            Ok(h) => {
                let fh = lock(&self.files).insert(Arc::new(h));
                reply.opened(fh, FopenFlags::empty());
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let Some(h) = lock(&self.files).get(fh) else {
            return reply.error(Errno::EBADF);
        };
        let mut buf = vec![0u8; size as usize];
        match h.read(offset, &mut buf) {
            Ok(n) => reply.data(&buf[..n]),
            Err(e) => {
                let path = self.path(ino).unwrap_or_default();
                eprintln!("{}: read {size}@{offset}: {e}", path.display());
                reply.error(Errno::EIO);
            }
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        lock(&self.files).remove(fh);
        reply.ok();
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let Some(path) = self.path(ino) else {
            return reply.error(Errno::ENOENT);
        };
        // The listing is taken once, so it stays stable across the readdir
        // calls of one directory stream.
        let entries = match self.vfs.read_dir(&path) {
            Ok(entries) => entries,
            Err(e) => return reply.error(errno(e)),
        };
        let mut inodes = lock(&self.inodes);
        let parent = path.parent().map_or(ino, |p| inodes.ino(p));
        let mut list = vec![
            (ino, FileType::Directory, ".".into()),
            (parent, FileType::Directory, "..".into()),
        ];
        for e in entries {
            let kind = if e.node.as_ref().is_some_and(Node::is_dir) {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            list.push((inodes.ino(&path.join(&e.name)), kind, e.name));
        }
        drop(inodes);
        let fh = lock(&self.dirs).insert(Arc::new(list));
        reply.opened(fh, FopenFlags::empty());
    }

    fn readdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(list) = lock(&self.dirs).get(fh) else {
            return reply.error(Errno::EBADF);
        };
        let skip = usize::try_from(offset).unwrap_or(usize::MAX);
        for (i, (ino, kind, name)) in list.iter().enumerate().skip(skip) {
            if reply.add(*ino, i as u64 + 1, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        lock(&self.dirs).remove(fh);
        reply.ok();
    }

    /// The source file system's numbers: Samba and Windows refuse to
    /// write to a volume that reports no free space.
    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let root = match vfs::c_path(self.vfs.root()) {
            Ok(root) => root,
            Err(e) => return reply.error(errno(e.into())),
        };
        // SAFETY: statvfs is plain data, valid when zeroed.
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `root` is a valid C string and `st` a valid statvfs.
        if unsafe { libc::statvfs(root.as_ptr(), &mut st) } != 0 {
            return reply.error(errno(io::Error::last_os_error().into()));
        }
        let n = |v| u32::try_from(v).unwrap_or(u32::MAX);
        #[allow(clippy::useless_conversion, reason = "the field types differ by OS")]
        reply.statfs(
            u64::from(st.f_blocks),
            u64::from(st.f_bfree),
            u64::from(st.f_bavail),
            u64::from(st.f_files),
            u64::from(st.f_ffree),
            n(st.f_bsize),
            n(st.f_namemax),
            n(st.f_frsize),
        );
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let Some(path) = self.path(ino) else {
            return reply.error(Errno::ENOENT);
        };
        let r = self.set_attr(&path, mode, uid, gid, size, atime, mtime, fh);
        match r.and_then(|()| self.vfs.lookup(&path).map_err(errno)) {
            Ok(node) => reply.attr(&TTL, &self.attr(ino, &node)),
            Err(e) => reply.error(e),
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(path) = self.child(parent, name) else {
            return reply.error(Errno::ENOENT);
        };
        match self.vfs.create(&path, mode & 0o7777) {
            Ok((node, h)) => {
                let ino = lock(&self.inodes).ino(&path);
                let fh = lock(&self.files).insert(Arc::new(h));
                let attr = self.attr(ino, &node);
                reply.created(&TTL, &attr, Generation(0), fh, FopenFlags::empty());
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let Some(h) = lock(&self.files).get(fh) else {
            return reply.error(Errno::EBADF);
        };
        match h.write(offset, data) {
            // A write is at most max_write bytes, far below 4 GiB.
            Ok(()) => reply.written(data.len() as u32),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let Some(h) = lock(&self.files).get(fh) else {
            return reply.error(Errno::EBADF);
        };
        match h.sync() {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(path) = self.child(parent, name) else {
            return reply.error(Errno::ENOENT);
        };
        match self.vfs.mkdir(&path, mode & 0o7777) {
            Ok(node) => self.reply_entry(&path, &node, reply),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(path) = self.child(parent, name) else {
            return reply.error(Errno::ENOENT);
        };
        match self.vfs.unlink(&path) {
            Ok(source) => {
                let mut inodes = lock(&self.inodes);
                inodes.remove(&path);
                // The source is gone too: a new file there needs a new inode.
                if let Some(src) = source {
                    inodes.remove(&src);
                }
                reply.ok();
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(path) = self.child(parent, name) else {
            return reply.error(Errno::ENOENT);
        };
        match self.vfs.rmdir(&path) {
            Ok(()) => {
                lock(&self.inodes).remove(&path);
                reply.ok();
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        // RENAME_EXCHANGE and RENAME_WHITEOUT are not supported.
        let noreplace = match flags.bits() {
            0 => false,
            #[cfg(target_os = "linux")]
            libc::RENAME_NOREPLACE => true,
            _ => return reply.error(Errno::EINVAL),
        };
        let (Some(from), Some(to)) = (self.child(parent, name), self.child(newparent, newname))
        else {
            return reply.error(Errno::ENOENT);
        };
        match self.vfs.rename(&from, &to, noreplace) {
            Ok(source) => {
                let mut inodes = lock(&self.inodes);
                inodes.rename(&from, &to);
                // The source moved with it, so its inode follows.
                if let Some((sf, st)) = source {
                    inodes.rename(&sf, &st);
                }
                reply.ok();
            }
            Err(e) => reply.error(errno(e)),
        }
    }
}

/// Mount options from the `-o a,b` arguments given after the mountpoint,
/// on top of `ro,fsname=fuse-nsz,default_permissions` (`rw` replaces `ro`).
/// Every request runs with the rights of the mounting user, so without
/// `default_permissions` an `allow_other` mount would let any local user
/// read, and in `rw` mode change, what only that user may touch.
fn config(args: &[String]) -> Result<(Config, Options), String> {
    let mut cfg = Config::default();
    let mut opts = Options::default();
    cfg.mount_options = vec![
        MountOption::FSName("fuse-nsz".into()),
        MountOption::DefaultPermissions,
    ];
    // fuser runs more than one worker thread only on Linux.
    #[cfg(target_os = "linux")]
    {
        cfg.n_threads = Some(std::thread::available_parallelism().map_or(4, |n| n.get()));
    }
    for o in vfs::mount_options(args)? {
        if opts.parse_flag(o) {
            continue;
        }
        match o {
            "allow_other" => cfg.acl = SessionACL::All,
            "allow_root" => cfg.acl = SessionACL::RootAndOwner,
            "auto_unmount" => cfg.mount_options.push(MountOption::AutoUnmount),
            "default_permissions" => {}
            o => match o.split_once('=') {
                Some(("fsname", v)) => {
                    cfg.mount_options
                        .retain(|m| !matches!(m, MountOption::FSName(_)));
                    cfg.mount_options.push(MountOption::FSName(v.into()));
                }
                Some(("subtype", v)) => cfg.mount_options.push(MountOption::Subtype(v.into())),
                _ => cfg.mount_options.push(MountOption::CUSTOM(o.into())),
            },
        }
    }
    cfg.mount_options.push(if opts.rw {
        MountOption::RW
    } else {
        MountOption::RO
    });
    Ok((cfg, opts))
}

/// Unmounts the file system started by [`start`].
type Unmount = Box<dyn FnMut() -> io::Result<()> + Send>;

#[cfg(not(target_os = "macos"))]
fn start(fs: NszFs, mountpoint: &Path, cfg: Config) -> io::Result<(Session<NszFs>, Unmount)> {
    let mut session = Session::new(fs, mountpoint, &cfg)?;
    let mut unmounter = session.unmount_callable();
    Ok((session, Box::new(move || unmounter.unmount())))
}

/// fuser mounts with `fuse_mount_compat25`, which macFUSE 5 fails without
/// setting errno. Its `fuse_mount` takes the same arguments and works, so
/// mount with that and hand the descriptor to fuser.
#[cfg(target_os = "macos")]
fn start(fs: NszFs, mountpoint: &Path, cfg: Config) -> io::Result<(Session<NszFs>, Unmount)> {
    use std::ffi::{CString, c_char, c_int, c_void};
    use std::os::fd::{FromRawFd, OwnedFd};

    #[repr(C)]
    struct FuseArgs {
        argc: c_int,
        argv: *mut *mut c_char,
        allocated: c_int,
    }
    unsafe extern "C" {
        fn fuse_mount(mountpoint: *const c_char, args: *mut FuseArgs) -> *mut c_void;
        fn fuse_chan_fd(ch: *mut c_void) -> c_int;
    }

    let invalid = || io::Error::from(io::ErrorKind::InvalidInput);
    let mut opts = Vec::new();
    for o in &cfg.mount_options {
        opts.push(match o {
            MountOption::FSName(v) => format!("fsname={v}"),
            MountOption::Subtype(v) => format!("subtype={v}"),
            MountOption::CUSTOM(v) => v.clone(),
            MountOption::DefaultPermissions => "default_permissions".into(),
            MountOption::AutoUnmount => "auto_unmount".into(),
            MountOption::RO => "ro".into(),
            MountOption::RW => "rw".into(),
            _ => return Err(invalid()),
        });
    }
    match cfg.acl {
        SessionACL::All => opts.push("allow_other".into()),
        SessionACL::RootAndOwner => opts.push("allow_root".into()),
        SessionACL::Owner => {}
    }
    let mut args = vec![CString::from(c"fuse-nsz")];
    for o in opts {
        args.push(c"-o".into());
        args.push(CString::new(o).map_err(|_| invalid())?);
    }
    let mut argv: Vec<*mut c_char> = args.iter().map(|a| a.as_ptr().cast_mut()).collect();
    let mut fargs = FuseArgs {
        argc: c_int::try_from(argv.len()).map_err(|_| invalid())?,
        argv: argv.as_mut_ptr(),
        allocated: 0,
    };
    let mp = vfs::c_path(mountpoint)?;
    // SAFETY: `mp` and every `argv` entry are valid C strings that outlive
    // the call. libfuse copies what it keeps.
    let ch = unsafe { fuse_mount(mp.as_ptr(), &mut fargs) };
    if ch.is_null() {
        return Err(io::Error::other("macFUSE mount failed"));
    }
    // SAFETY: `ch` is a live channel. It is never destroyed, so its
    // descriptor is owned here alone.
    let fd = unsafe { OwnedFd::from_raw_fd(fuse_chan_fd(ch)) };
    let mut unmount: Unmount = Box::new(move || {
        // SAFETY: `mp` is a valid C string.
        if unsafe { libc::unmount(mp.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    });
    let acl = cfg.acl;
    match Session::from_fd(fs, fd, acl, cfg) {
        Ok(session) => Ok((session, unmount)),
        Err(e) => {
            let _ = unmount();
            Err(e)
        }
    }
}

/// Every cached image keeps its source file open, so a directory with many
/// containers needs more descriptors than the default soft limit (1024 on
/// Linux, 256 on macOS). Raise it to the hard limit. macOS refuses a soft
/// limit above its per process maximum, so fall back to its usual value.
fn raise_nofile_limit() {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `rl` is a valid rlimit for getrlimit to fill.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } != 0 {
        return;
    }
    for cur in [rl.rlim_max, rl.rlim_max.min(10240)] {
        if cur <= rl.rlim_cur {
            return;
        }
        let new = libc::rlimit {
            rlim_cur: cur,
            rlim_max: rl.rlim_max,
        };
        // SAFETY: `new` is a valid rlimit.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new) } == 0 {
            return;
        }
    }
}

/// Mount `src` on `mountpoint` and serve it until it is unmounted, or
/// until SIGINT, SIGTERM or SIGHUP, which unmount it.
pub fn mount(src: PathBuf, mountpoint: &Path, args: &[String]) -> Result<(), String> {
    let (cfg, opts) = config(args)?;
    raise_nofile_limit();
    let mut inodes = Inodes::default();
    inodes.ino(Path::new(""));
    let fs = NszFs {
        vfs: Vfs::new(src, opts),
        inodes: Mutex::new(inodes),
        files: Mutex::new(Handles::new()),
        dirs: Mutex::new(Handles::new()),
        // SAFETY: getuid and getgid have no preconditions and cannot fail.
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    };
    let (session, mut unmount) =
        start(fs, mountpoint, cfg).map_err(|e| format!("{}: {e}", mountpoint.display()))?;
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ])
    .map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        if signals.forever().next().is_some()
            && let Err(e) = unmount()
        {
            eprintln!("unmount: {e}");
        }
    });
    session.run().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inodes_subtree() {
        let mut t = Inodes::default();
        let names = ["", "a", "a b", "a.x", "a/b", "a/b/c", "ab", "z"];
        let ino: Vec<u64> = names.iter().map(|n| t.ino(Path::new(n)).0).collect();
        let live = |t: &Inodes| -> Vec<String> {
            t.by_path
                .keys()
                .map(|p| p.to_string_lossy().into_owned())
                .collect()
        };

        t.rename(Path::new("a"), Path::new("y"));
        assert_eq!(live(&t), ["", "a b", "a.x", "ab", "y", "y/b", "y/b/c", "z"]);
        assert_eq!(t.ino(Path::new("y/b/c")).0, ino[5]);
        assert_eq!(t.paths[ino[4] as usize - 1], Path::new("y/b"));

        // Replacing a target forgets it and everything under it.
        t.ino(Path::new("z/old"));
        t.rename(Path::new("y"), Path::new("z"));
        assert_eq!(live(&t), ["", "a b", "a.x", "ab", "z", "z/b", "z/b/c"]);
        assert_eq!(t.ino(Path::new("z")).0, ino[1]);

        t.remove(Path::new("z"));
        assert_eq!(live(&t), ["", "a b", "a.x", "ab"]);
    }
}

// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! FUSE backend for Linux and macOS. The kernel speaks in inode numbers,
//! the core in paths: a table maps each inode the kernel holds to its path.
//! Inode numbers are never reused, so the generation is always 0.

use crate::vfs::{self, FsError, Handle, Node, Options, Vfs, lock, log};
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
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const TTL: Duration = Duration::from_secs(1);

/// An inode the kernel holds, or one that an open listing shows.
struct Inode {
    /// `None` once the entry was deleted or replaced: an open file may
    /// still use the inode, but no name leads to it.
    path: Option<PathBuf>,
    /// Lookups the kernel did not forget yet. 0 for an entry that was only
    /// listed so far.
    lookups: u64,
}

struct Inodes {
    /// The last number given out.
    last: u64,
    nodes: HashMap<u64, Inode>,
    /// The inodes that have a name. Ordered, so a directory and everything
    /// under it are one range.
    by_path: BTreeMap<PathBuf, u64>,
}

impl Inodes {
    /// Only the root, the empty path, which the kernel never forgets.
    fn new() -> Self {
        let root = Inode {
            path: Some(PathBuf::new()),
            lookups: 1,
        };
        Inodes {
            last: INodeNo::ROOT.0,
            nodes: HashMap::from([(INodeNo::ROOT.0, root)]),
            by_path: BTreeMap::from([(PathBuf::new(), INodeNo::ROOT.0)]),
        }
    }

    /// The inode of `path` for a listing. That is no lookup: an entry the
    /// kernel does not look up is dropped again when the listing is closed,
    /// see [`Inodes::forget`].
    fn list(&mut self, path: &Path) -> INodeNo {
        if let Some(&ino) = self.by_path.get(path) {
            return INodeNo(ino);
        }
        self.last += 1;
        self.by_path.insert(path.to_path_buf(), self.last);
        let node = Inode {
            path: Some(path.to_path_buf()),
            lookups: 0,
        };
        self.nodes.insert(self.last, node);
        INodeNo(self.last)
    }

    /// The inode of `path` for an entry reply. Each reply is one lookup,
    /// which the kernel hands back with a forget.
    fn lookup(&mut self, path: &Path) -> INodeNo {
        let ino = self.list(path);
        if let Some(node) = self.nodes.get_mut(&ino.0) {
            node.lookups += 1;
        }
        ino
    }

    /// The path of `ino`, unless no name leads to it any more.
    fn path(&self, ino: INodeNo) -> Option<&Path> {
        self.nodes.get(&ino.0)?.path.as_deref()
    }

    /// The kernel let go of `count` lookups of `ino`. An inode without
    /// lookups leaves the table. With a count of 0 this drops what was
    /// only listed.
    fn forget(&mut self, ino: INodeNo, count: u64) {
        let Some(node) = self.nodes.get_mut(&ino.0) else {
            return;
        };
        node.lookups = node.lookups.saturating_sub(count);
        if node.lookups == 0
            && ino != INodeNo::ROOT
            && let Some(node) = self.nodes.remove(&ino.0)
            && let Some(path) = node.path
        {
            self.by_path.remove(&path);
        }
    }

    /// The named paths `path` and everything under it, with their inodes.
    fn subtree(&self, path: &Path) -> Vec<(PathBuf, u64)> {
        self.by_path
            .range::<Path, _>((Bound::Included(path), Bound::Unbounded))
            .take_while(|(p, _)| p.starts_with(path))
            .map(|(p, &ino)| (p.clone(), ino))
            .collect()
    }

    /// Take the names of `path` and of everything under it away, so they
    /// get new inodes if they show up again. The inodes stay for the files
    /// still open, until the kernel forgets them.
    fn remove(&mut self, path: &Path) {
        for (p, ino) in self.subtree(path) {
            self.by_path.remove(&p);
            if let Some(node) = self.nodes.get_mut(&ino) {
                node.path = None;
            }
        }
    }

    /// Move the inodes of `old` and of everything under it to `new`, so
    /// open files and the kernel's cached entries keep working.
    fn rename(&mut self, old: &Path, new: &Path) {
        self.remove(new);
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
            if let Some(node) = self.nodes.get_mut(&ino) {
                node.path = Some(np);
            }
        }
    }
}

struct NszFs {
    vfs: Vfs,
    inodes: Mutex<Inodes>,
    /// Each open file with its inode.
    files: Mutex<Handles<(INodeNo, Arc<Handle>)>>,
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
    fn remove(&mut self, fh: FileHandle) -> Option<T> {
        self.map.remove(&fh.0)
    }
}

/// How the mount shows `node`. A FIFO, socket or device shows as a file
/// that cannot be opened.
fn kind(node: &Node) -> FileType {
    if node.is_dir() {
        FileType::Directory
    } else if !node.is_image() && node.meta.is_symlink() {
        FileType::Symlink
    } else {
        FileType::RegularFile
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
        lock(&self.inodes).path(ino).map(Path::to_path_buf)
    }

    fn file(&self, fh: FileHandle) -> Option<Arc<Handle>> {
        lock(&self.files).get(fh).map(|(_, h)| h)
    }

    /// The node of `ino`. A file that was deleted while open has no name
    /// to look up, so one of its open handles answers. The kernel sends
    /// none along for an fstat.
    fn node(&self, ino: INodeNo) -> Result<Node, Errno> {
        if let Some(path) = self.path(ino) {
            return self.vfs.lookup(&path).map_err(errno);
        }
        let files = lock(&self.files);
        let open = files.map.values().find(|(i, _)| *i == ino);
        let h = open.map(|(_, h)| Arc::clone(h)).ok_or(Errno::ENOENT)?;
        drop(files);
        match &*h {
            Handle::File(f) => Ok(Node {
                meta: f.metadata().map_err(|e| errno(e.into()))?,
                image_len: None,
            }),
            // Its source is gone, and the metadata with it.
            Handle::Image(_) => Err(Errno::ENOENT),
        }
    }

    fn attr(&self, ino: INodeNo, node: &Node) -> FileAttr {
        let dir = node.is_dir();
        let size = node.size();
        let t = node.mtime();
        // The permission bits and the sticky bit of the source. Samba
        // takes a file without the w bit for a DOS read-only one and
        // refuses to delete or rename it, so in rw mode virtual files show
        // it too. Their content stays read-only.
        let mut perm = node.meta.permissions().mode() & if self.vfs.rw() { 0o1777 } else { 0o1555 };
        // Every file is shown with the group of the mounting user. Where
        // the source has another group, its group bits would go to the
        // wrong users: that class gets no more than everyone else.
        if node.meta.gid() != self.gid {
            perm &= !0o070 | (perm & 0o007) << 3;
        }
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
            kind: kind(node),
            perm: perm as u16,
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
        let ino = lock(&self.inodes).lookup(path);
        reply.entry(&TTL, &self.attr(ino, node), Generation(0));
    }

    /// The changes of a setattr, in an order where a chmod cannot block
    /// the truncate before it.
    #[expect(clippy::too_many_arguments, reason = "the fields of a setattr")]
    fn set_attr(
        &self,
        ino: INodeNo,
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
        // What has no open file to go through needs the name, which a
        // deleted file does not have any more.
        let path = self.path(ino);
        let named = || path.as_deref().ok_or(Errno::ENOENT);
        if let Some(size) = size {
            match fh.and_then(|fh| self.file(fh)) {
                // open(O_RDONLY | O_TRUNC) reaches here as a read-only
                // open and then a truncate through that handle, which
                // the OS refuses: truncate by path then.
                Some(h) => match (h.set_len(size), &path) {
                    (Err(FsError::Io(_)), Some(path)) => self.vfs.truncate(path, size),
                    (r, _) => r,
                },
                None => self.vfs.truncate(named()?, size),
            }
            .map_err(errno)?;
        }
        if let Some(m) = mode {
            self.vfs
                .set_permissions(named()?, Permissions::from_mode(m))
                .map_err(errno)?;
        }
        if atime.is_some() || mtime.is_some() {
            let t = |t: TimeOrNow| match t {
                TimeOrNow::SpecificTime(t) => t,
                TimeOrNow::Now => SystemTime::now(),
            };
            self.vfs
                .set_times(named()?, atime.map(t), mtime.map(t))
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

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        lock(&self.inodes).forget(ino, nlookup);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.node(ino) {
            Ok(node) => reply.attr(&TTL, &self.attr(ino, &node)),
            Err(e) => reply.error(e),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let Some(path) = self.path(ino) else {
            return reply.error(Errno::ENOENT);
        };
        match self.vfs.read_link(&path) {
            Ok(target) => reply.data(target.as_os_str().as_bytes()),
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
                let fh = lock(&self.files).insert((ino, Arc::new(h)));
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
        let Some(h) = self.file(fh) else {
            return reply.error(Errno::EBADF);
        };
        let mut buf = vec![0u8; size as usize];
        match h.read(offset, &mut buf) {
            Ok(n) => reply.data(&buf[..n]),
            Err(e) => {
                let path = self.path(ino).unwrap_or_default();
                vfs::log_read_error(&path, size as usize, offset, &e);
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
        let parent = path.parent().map_or(ino, |p| inodes.list(p));
        let mut list = vec![
            (ino, FileType::Directory, ".".into()),
            (parent, FileType::Directory, "..".into()),
        ];
        for e in entries {
            let kind = e.node.as_ref().map_or(FileType::RegularFile, kind);
            list.push((inodes.list(&path.join(&e.name)), kind, e.name));
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
        // What the listing showed and the kernel did not look up goes
        // again, so the table does not keep every path ever listed.
        if let Some(list) = lock(&self.dirs).remove(fh) {
            let mut inodes = lock(&self.inodes);
            for (ino, ..) in list.iter() {
                inodes.forget(*ino, 0);
            }
        }
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
        let r = self.set_attr(ino, mode, uid, gid, size, atime, mtime, fh);
        match r.and_then(|()| self.node(ino)) {
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
        match self.vfs.create(&path, mode) {
            Ok((node, h)) => {
                let ino = lock(&self.inodes).lookup(&path);
                let fh = lock(&self.files).insert((ino, Arc::new(h)));
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
        let Some(h) = self.file(fh) else {
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
        let Some(h) = self.file(fh) else {
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
        match self.vfs.mkdir(&path, mode) {
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
/// on top of `ro,nosuid,nodev,fsname=fuse-nsz,default_permissions` (`rw`
/// replaces `ro`).
/// Every request runs with the rights of the mounting user, so without
/// `default_permissions` an `allow_other` mount would let any local user
/// read, and in `rw` mode change, what only that user may touch.
fn config(args: &[String]) -> Result<(Config, Options), String> {
    let mut cfg = Config::default();
    let mut opts = Options::default();
    cfg.mount_options = vec![
        MountOption::FSName("fuse-nsz".into()),
        MountOption::DefaultPermissions,
        MountOption::NoSuid,
        MountOption::NoDev,
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
            // Always in force.
            "default_permissions" | "nosuid" | "nodev" => {}
            "suid" | "dev" => return Err(format!("option {o} is not supported")),
            // Flags of the mount, not parameters of the fuse driver: handed
            // on as text, a mount by root, which does not go through
            // fusermount3, would be refused by the kernel.
            "exec" => cfg.mount_options.push(MountOption::Exec),
            "noexec" => cfg.mount_options.push(MountOption::NoExec),
            "atime" => cfg.mount_options.push(MountOption::Atime),
            "noatime" => cfg.mount_options.push(MountOption::NoAtime),
            "sync" => cfg.mount_options.push(MountOption::Sync),
            "async" => cfg.mount_options.push(MountOption::Async),
            "dirsync" => cfg.mount_options.push(MountOption::DirSync),
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
            MountOption::NoSuid => "nosuid".into(),
            MountOption::NoDev => "nodev".into(),
            MountOption::Exec => "exec".into(),
            MountOption::NoExec => "noexec".into(),
            MountOption::Atime => "atime".into(),
            MountOption::NoAtime => "noatime".into(),
            MountOption::Sync => "sync".into(),
            MountOption::Async => "async".into(),
            MountOption::DirSync => "dirsync".into(),
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
    let mut unmount: Unmount = Box::new(move || {
        // SAFETY: `mp` is a valid C string.
        if unsafe { libc::unmount(mp.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    });
    // SAFETY: `ch` is a live channel.
    let raw = unsafe { fuse_chan_fd(ch) };
    if raw < 0 {
        let _ = unmount();
        return Err(io::Error::other("macFUSE gave no channel descriptor"));
    }
    // SAFETY: the channel is never destroyed, so its descriptor is owned
    // here alone.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let acl = cfg.acl;
    match Session::from_fd(fs, fd, acl, cfg) {
        Ok(session) => Ok((session, unmount)),
        Err(e) => {
            let _ = unmount();
            Err(e)
        }
    }
}

/// Every file a client has open is one descriptor here, on top of the
/// cached images and of the ones a listing is building. The default soft
/// limit (1024 on Linux, 256 on macOS) is low for a file server, so raise
/// it to the hard limit. macOS refuses a soft limit above its per process
/// maximum, so fall back to its usual value.
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

/// Unmount `mountpoint` although it is in use. On Linux it leaves the tree
/// at once and the session ends with its last user. On macOS open files are
/// cut off.
fn detach(mountpoint: &Path) -> io::Result<()> {
    let mp = vfs::c_path(mountpoint)?;
    // SAFETY: `mp` is a valid C string.
    #[cfg(target_os = "linux")]
    let r = unsafe { libc::umount2(mp.as_ptr(), libc::MNT_DETACH) };
    // SAFETY: `mp` is a valid C string.
    #[cfg(target_os = "macos")]
    let r = unsafe { libc::unmount(mp.as_ptr(), libc::MNT_FORCE) };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let r = {
        let _ = mp;
        return Err(io::ErrorKind::Unsupported.into());
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Mount `src` on `mountpoint` and serve it until it is unmounted, or
/// until SIGINT, SIGTERM or SIGHUP, which unmount it. A second signal ends
/// the process without waiting for a mount that is still in use.
pub fn mount(src: PathBuf, mountpoint: &Path, args: &[String]) -> Result<(), String> {
    let (cfg, opts) = config(args)?;
    raise_nofile_limit();
    // The mode of a create or mkdir comes with the umask of its caller
    // applied by the kernel. The one of this process must not come on top.
    // SAFETY: umask has no preconditions and cannot fail.
    unsafe { libc::umask(0) };
    let fs = NszFs {
        vfs: Vfs::new(src, opts),
        inodes: Mutex::new(Inodes::new()),
        files: Mutex::new(Handles::new()),
        dirs: Mutex::new(Handles::new()),
        // SAFETY: getuid and getgid have no preconditions and cannot fail.
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    };
    // Before the mount: a failure here must not leave one behind.
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ])
    .map_err(|e| e.to_string())?;
    let (session, mut unmount) =
        start(fs, mountpoint, cfg).map_err(|e| format!("{}: {e}", mountpoint.display()))?;
    let mountpoint = mountpoint.to_path_buf();
    std::thread::spawn(move || {
        let mut signals = signals.forever();
        signals.next();
        // Root gets "busy" for a mount that is in use, where another user
        // is handed on to fusermount3, which detaches it.
        if let Err(e) = unmount().or_else(|e| detach(&mountpoint).map_err(|_| e)) {
            log!("unmount: {e}");
        }
        // The session ends with the unmount, or with the last user of a
        // detached mount. A second signal does not wait for that.
        signals.next();
        std::process::exit(1);
    });
    session.run().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inodes_subtree() {
        let mut t = Inodes::new();
        let names = ["a", "a b", "a.x", "a/b", "a/b/c", "ab", "z"];
        let ino: Vec<INodeNo> = names.iter().map(|n| t.lookup(Path::new(n))).collect();
        let live = |t: &Inodes| -> Vec<String> {
            t.by_path
                .keys()
                .map(|p| p.to_string_lossy().into_owned())
                .collect()
        };

        t.rename(Path::new("a"), Path::new("y"));
        assert_eq!(live(&t), ["", "a b", "a.x", "ab", "y", "y/b", "y/b/c", "z"]);
        assert_eq!(t.list(Path::new("y/b/c")), ino[4]);
        assert_eq!(t.path(ino[3]), Some(Path::new("y/b")));

        // Replacing a target takes its name and those under it away.
        let old = t.lookup(Path::new("z/old"));
        t.rename(Path::new("y"), Path::new("z"));
        assert_eq!(live(&t), ["", "a b", "a.x", "ab", "z", "z/b", "z/b/c"]);
        assert_eq!(t.list(Path::new("z")), ino[0]);
        assert_eq!(t.path(old), None);
        assert_eq!(t.path(ino[6]), None);

        t.remove(Path::new("z"));
        assert_eq!(live(&t), ["", "a b", "a.x", "ab"]);
    }

    /// An inode lives as long as the kernel holds a lookup of it, also
    /// after its name is gone, and a name that comes back is a new inode.
    #[test]
    fn inodes_lifetime() {
        let mut t = Inodes::new();
        let p = Path::new("f");
        let known = |t: &Inodes| t.by_path.get(p).map(|&i| INodeNo(i));
        let ino = t.lookup(p);
        assert_eq!((t.lookup(p), known(&t)), (ino, Some(ino)));
        t.forget(ino, 1);
        assert_eq!(t.path(ino), Some(p));
        t.forget(ino, 1);
        assert_eq!((t.path(ino), known(&t)), (None, None));
        assert_eq!(t.nodes.len(), 1);

        // Deleted while open: no name, and the next file of that name is
        // another inode.
        let old = t.lookup(p);
        assert_ne!(old, ino);
        t.remove(p);
        assert_eq!((t.path(old), known(&t)), (None, None));
        let new = t.lookup(p);
        assert_ne!(new, old);
        // The late forget of the old inode leaves the new one alone.
        t.forget(old, 1);
        assert_eq!((t.path(new), known(&t)), (Some(p), Some(new)));
        assert_eq!(t.nodes.len(), 2);

        // More forgets than lookups, an unknown inode, the root.
        t.forget(new, 5);
        t.forget(INodeNo(999), 1);
        t.forget(INodeNo::ROOT, u64::MAX);
        assert_eq!(t.path(INodeNo::ROOT), Some(Path::new("")));
        assert_eq!((t.nodes.len(), t.by_path.len()), (1, 1));
    }

    /// A listing gives every entry its number, and keeps none of those the
    /// kernel did not look up.
    #[test]
    fn inodes_listing() {
        let mut t = Inodes::new();
        let (a, b) = (Path::new("d/a"), Path::new("d/b"));
        let listed = [t.list(a), t.list(b)];
        assert_ne!(listed[0], listed[1]);
        // The number a lookup gives is the one the listing showed.
        assert_eq!(t.lookup(a), listed[0]);
        // A second listing of the same directory, closed first.
        assert_eq!([t.list(a), t.list(b)], listed);
        for ino in listed {
            t.forget(ino, 0);
        }
        assert_eq!(t.path(listed[0]), Some(a));
        assert_eq!(t.path(listed[1]), None);
        assert_eq!(t.nodes.len(), 2);
        // Closing the first one finds nothing left to drop, and does not
        // take the number b got meanwhile.
        let again = t.lookup(b);
        assert_ne!(again, listed[1]);
        for ino in listed {
            t.forget(ino, 0);
        }
        assert_eq!(t.path(again), Some(b));
        t.forget(listed[0], 1);
        t.forget(again, 1);
        assert_eq!((t.nodes.len(), t.by_path.len()), (1, 1));
    }

    #[test]
    fn mount_flags() {
        let opts = |o: &str| config(&["-o".into(), o.into()]);
        let (cfg, o) = opts("rw,noexec,nosuid,nodev,noatime,hide_sources").unwrap();
        assert!(o.rw && o.hide_sources);
        for want in [MountOption::NoExec, MountOption::NoAtime, MountOption::RW] {
            assert!(cfg.mount_options.contains(&want), "{want:?}");
        }
        // Nothing is left for the kernel to take as a fuse parameter.
        assert!(
            !cfg.mount_options
                .iter()
                .any(|m| matches!(m, MountOption::CUSTOM(_)))
        );
        for o in ["suid", "dev"] {
            assert!(opts(o).is_err(), "{o}");
        }
        let (cfg, _) = opts("max_read=4096").unwrap();
        assert!(
            cfg.mount_options
                .contains(&MountOption::CUSTOM("max_read=4096".into()))
        );
    }
}

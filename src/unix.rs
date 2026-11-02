// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! FUSE backend for Linux and macOS. The kernel speaks in inode numbers,
//! the core in paths: a table maps each path seen so far to an inode.
//! Inode numbers are never reused, so the generation is always 0.

use crate::vfs::{FsError, Handle, Node, Vfs};
use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    LockOwner, MountOption, OpenAccMode, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, Request, Session, SessionACL,
};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

const TTL: Duration = Duration::from_secs(1);

#[derive(Default)]
struct Inodes {
    /// Path of inode `i + 1`. Inode 1 is the root, the empty path.
    paths: Vec<PathBuf>,
    by_path: HashMap<PathBuf, u64>,
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

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn errno(e: &FsError) -> Errno {
    match e {
        FsError::NotFound => Errno::ENOENT,
        FsError::ReadOnly => Errno::EROFS,
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
            perm: (node.meta.permissions().mode() & 0o555) as u16,
            nlink: if dir { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }
}

impl Filesystem for NszFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(path) = self.path(parent).map(|p| p.join(name)) else {
            return reply.error(Errno::ENOENT);
        };
        match self.vfs.lookup(&path) {
            Ok(node) => {
                let ino = lock(&self.inodes).ino(&path);
                reply.entry(&TTL, &self.attr(ino, &node), Generation(0));
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let Some(path) = self.path(ino) else {
            return reply.error(Errno::ENOENT);
        };
        match self.vfs.lookup(&path) {
            Ok(node) => reply.attr(&TTL, &self.attr(ino, &node)),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let Some(path) = self.path(ino) else {
            return reply.error(Errno::ENOENT);
        };
        let write = flags.acc_mode() != OpenAccMode::O_RDONLY;
        match self
            .vfs
            .lookup(&path)
            .and_then(|n| self.vfs.open(&path, n, write))
        {
            Ok(h) => {
                let fh = lock(&self.files).insert(Arc::new(h));
                reply.opened(fh, FopenFlags::empty());
            }
            Err(e) => reply.error(errno(&e)),
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
            Err(e) => return reply.error(errno(&e)),
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

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 4096, 255, 4096);
    }
}

/// Mount options from the `-o a,b` arguments given after the mountpoint,
/// on top of `ro,fsname=fuse-nsz`.
fn config(args: &[String]) -> Result<Config, String> {
    let mut cfg = Config::default();
    cfg.mount_options = vec![MountOption::RO, MountOption::FSName("fuse-nsz".into())];
    cfg.n_threads = Some(std::thread::available_parallelism().map_or(4, |n| n.get()));
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let opts = match a.strip_prefix("-o") {
            Some("") => it.next().ok_or("-o needs an argument")?.as_str(),
            Some(o) => o,
            None => return Err(format!("unknown argument {a}")),
        };
        for o in opts.split(',').filter(|o| !o.is_empty()) {
            match o {
                "allow_other" => cfg.acl = SessionACL::All,
                "allow_root" => cfg.acl = SessionACL::RootAndOwner,
                "auto_unmount" => cfg.mount_options.push(MountOption::AutoUnmount),
                "default_permissions" => cfg.mount_options.push(MountOption::DefaultPermissions),
                "ro" => {}
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
    }
    Ok(cfg)
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
    let cfg = config(args)?;
    raise_nofile_limit();
    let mut inodes = Inodes::default();
    inodes.ino(Path::new(""));
    let fs = NszFs {
        vfs: Vfs::new(src),
        inodes: Mutex::new(inodes),
        files: Mutex::new(Handles::new()),
        dirs: Mutex::new(Handles::new()),
        // SAFETY: getuid and getgid have no preconditions and cannot fail.
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    };
    let mut session =
        Session::new(fs, mountpoint, &cfg).map_err(|e| format!("{}: {e}", mountpoint.display()))?;
    let mut unmounter = session.unmount_callable();
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ])
    .map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        if signals.forever().next().is_some()
            && let Err(e) = unmounter.unmount()
        {
            eprintln!("unmount: {e}");
        }
    });
    session.run().map_err(|e| e.to_string())
}

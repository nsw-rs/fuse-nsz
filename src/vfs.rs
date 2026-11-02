// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Platform neutral core: a read-only mirror of a directory where every
//! block compressed `.nsz`/`.xcz` also shows up as a virtual `.nsp`/`.xci`.
//! Paths are relative to the mirrored directory.

use libhac::image::{self, Image, Shared};
use libhac::{Error, ReadAt, SubStorage};
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::io;
use std::panic;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

/// Why an operation failed. Backends map it to their own error codes.
#[derive(Debug)]
pub enum FsError {
    NotFound,
    /// A write open on the read-only file system.
    ReadOnly,
    IsDir,
    NotDir,
    /// The file cannot be served, e.g. a FIFO that would block on open.
    Access,
    #[cfg_attr(
        windows,
        expect(dead_code, reason = "only the FUSE backend reports the OS error")
    )]
    Io(io::Error),
}

impl From<io::Error> for FsError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::NotFound => FsError::NotFound,
            io::ErrorKind::PermissionDenied => FsError::Access,
            io::ErrorKind::NotADirectory => FsError::NotDir,
            _ => FsError::Io(e),
        }
    }
}

pub type Result<T> = std::result::Result<T, FsError>;

/// A file or directory as seen through the mount.
pub struct Node {
    /// Metadata of the real file, or of the source container for a
    /// virtual image.
    pub meta: Metadata,
    pub image: Option<Arc<Image>>,
}

impl Node {
    pub fn is_dir(&self) -> bool {
        self.image.is_none() && self.meta.is_dir()
    }

    /// Size in bytes, 0 for a directory.
    pub fn size(&self) -> u64 {
        match &self.image {
            Some(img) => img.len(),
            None if self.meta.is_dir() => 0,
            None => self.meta.len(),
        }
    }

    pub fn mtime(&self) -> SystemTime {
        self.meta.modified().unwrap_or(SystemTime::UNIX_EPOCH)
    }
}

/// A directory entry.
pub struct DirEntry {
    pub name: OsString,
    /// `None` when the entry cannot be resolved, e.g. a dangling symlink.
    pub node: Option<Node>,
}

/// An open file.
pub enum Handle {
    File(File),
    Image(Arc<Image>),
}

impl Handle {
    /// Read at `off` into `buf`. Returns fewer bytes only at end of file.
    pub fn read(&self, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Handle::File(f) => read_file_at(f, off, buf),
            Handle::Image(img) => {
                let size = img.len();
                if off >= size {
                    return Ok(0);
                }
                let n = buf.len().min((size - off).try_into().unwrap_or(usize::MAX));
                match img.read_at(off, &mut buf[..n]) {
                    Ok(()) => Ok(n),
                    Err(Error::Io(e)) => Err(e),
                    Err(e) => Err(io::Error::other(e)),
                }
            }
        }
    }
}

/// Positional read that stops early only at end of file.
fn read_file_at(f: &File, mut off: u64, buf: &mut [u8]) -> io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        #[cfg(unix)]
        let r = std::os::unix::fs::FileExt::read_at(f, &mut buf[done..], off);
        #[cfg(windows)]
        let r = std::os::windows::fs::FileExt::seek_read(f, &mut buf[done..], off);
        match r {
            Ok(0) => break,
            Ok(n) => {
                done += n;
                off += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}

/// The virtual image of one source container, rebuilt when its size or
/// mtime changes.
struct Container {
    /// Real path the container was first reached by.
    path: PathBuf,
    size: u64,
    mtime: Option<SystemTime>,
    /// `None`: no virtual file (solid NCZ or parse error).
    image: OnceLock<Option<Arc<Image>>>,
    /// Set when the build failed with an error that may go away by
    /// itself: the build is retried after this instant.
    retry_at: OnceLock<Instant>,
}

/// How long a container whose build failed with a transient error stays
/// hidden before the next attempt, so it is not reopened and logged on
/// every lookup.
const RETRY: Duration = Duration::from_secs(30);

/// Most threads building the images of one directory listing at once. The
/// builds wait on the source's I/O (a NAS round trip per header read), not
/// on the CPU, so the count is not tied to the number of cores.
const BUILD_THREADS: usize = 8;

/// Identifies a source file whatever name reached it, so a case-insensitive
/// file system (macOS, CIFS) does not get two images of the same file.
#[cfg(unix)]
type Key = (u64, u64);
/// Windows file systems fold case, so the path with ASCII letters folded is
/// enough. Other letters are kept as is: folding them differently from the
/// file system could merge two distinct files.
#[cfg(windows)]
type Key = OsString;

#[cfg(unix)]
fn key(_path: &Path, meta: &Metadata) -> Key {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

#[cfg(windows)]
fn key(path: &Path, _meta: &Metadata) -> Key {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .map(|c| u8::try_from(c).map_or(c, |b| b.to_ascii_lowercase().into()))
        .collect();
    OsString::from_wide(&wide)
}

pub struct Vfs {
    root: PathBuf,
    containers: Mutex<HashMap<Key, Arc<Container>>>,
}

/// Virtual names only differ from the source in the last extension byte,
/// keeping its case: `.nsz` -> `.nsp`, `.xcz` -> `.xci`.
pub fn virtual_name(name: &OsStr) -> Option<OsString> {
    let name = name.to_str()?;
    let ext = name.get(name.len().checked_sub(4)?..)?;
    let c = match ext.to_ascii_lowercase().as_str() {
        ".nsz" => 'p',
        ".xcz" => 'i',
        _ => return None,
    };
    let c = if name.ends_with('Z') {
        c.to_ascii_uppercase()
    } else {
        c
    };
    Some(format!("{}{c}", &name[..name.len() - 1]).into())
}

/// The inverse of [`virtual_name`].
pub fn source_name(name: &OsStr) -> Option<OsString> {
    let s = name.to_str()?;
    let last = s.chars().next_back()?;
    let c = if last.is_ascii_uppercase() { 'Z' } else { 'z' };
    let src: OsString = format!("{}{c}", &s[..s.len() - last.len_utf8()]).into();
    (virtual_name(&src).as_deref() == Some(name)).then_some(src)
}

/// Whether a build error may go away by itself, so the container must be
/// retried after [`RETRY`] instead of staying hidden until the source
/// changes (a chmod changes neither size nor mtime). A truncated file is
/// not transient.
fn transient(e: &Error) -> bool {
    matches!(e, Error::Io(io) if io.kind() != io::ErrorKind::UnexpectedEof)
}

fn build_container(path: &Path, size: u64) -> libhac::Result<Image> {
    let file = File::open(path)?;
    let src: Shared = Arc::new(SubStorage::new(file, 0, size)?);
    // The source file stays open as long as the image (or an open handle)
    // references it.
    image::build(src)
}

impl Vfs {
    pub fn new(root: PathBuf) -> Self {
        Vfs {
            root,
            containers: Mutex::new(HashMap::new()),
        }
    }

    fn containers(&self) -> MutexGuard<'_, HashMap<Key, Arc<Container>>> {
        self.containers.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `rel` under the root. Only plain names are accepted: `..`, a root
    /// or a drive prefix would make `join` leave the root.
    fn real(&self, rel: &Path) -> Result<PathBuf> {
        if !rel.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(FsError::NotFound);
        }
        Ok(self.root.join(rel))
    }

    /// The virtual image of the source container at `path`, if it has one.
    fn image(&self, path: &Path, meta: &Metadata) -> Option<Arc<Image>> {
        let (size, mtime) = (meta.len(), meta.modified().ok());
        let fresh = || {
            Arc::new(Container {
                path: path.to_path_buf(),
                size,
                mtime,
                image: OnceLock::new(),
                retry_at: OnceLock::new(),
            })
        };
        let c = {
            let mut cs = self.containers();
            let c = cs.entry(key(path, meta)).or_insert_with(&fresh);
            if c.size != size
                || c.mtime != mtime
                || c.retry_at.get().is_some_and(|&t| Instant::now() >= t)
            {
                *c = fresh();
            }
            Arc::clone(c)
        };
        // Built outside the lock, so a slow source does not stall other
        // lookups.
        c.image
            .get_or_init(|| match build_container(path, size) {
                Ok(img) => Some(Arc::new(img)),
                Err(e) => {
                    let note = if matches!(e, Error::Unsupported(_)) {
                        ", not exposed"
                    } else {
                        ""
                    };
                    eprintln!("{}: {e}{note}", path.display());
                    if transient(&e) {
                        let _ = c.retry_at.set(Instant::now() + RETRY);
                    }
                    None
                }
            })
            .clone()
    }

    /// [`Vfs::image`] of every job, in order. The builds run on up to
    /// [`BUILD_THREADS`] threads, the calling one included. A thread that
    /// cannot be spawned only means fewer of them.
    fn images(&self, jobs: &[(PathBuf, &Metadata)]) -> Vec<Option<Arc<Image>>> {
        if jobs.len() <= 1 {
            return jobs.iter().map(|(p, m)| self.image(p, m)).collect();
        }
        let next = AtomicUsize::new(0);
        let work = || {
            let mut done = Vec::new();
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some((p, m)) = jobs.get(i) else {
                    return done;
                };
                done.push((i, self.image(p, m)));
            }
        };
        let mut out = vec![None; jobs.len()];
        thread::scope(|s| {
            let workers: Vec<_> = (1..jobs.len().min(BUILD_THREADS))
                .filter_map(|_| thread::Builder::new().spawn_scoped(s, work).ok())
                .collect();
            let mut done = work();
            for w in workers {
                done.extend(w.join().unwrap_or_else(|e| panic::resume_unwind(e)));
            }
            for (i, img) in done {
                out[i] = img;
            }
        });
        out
    }

    /// Drop the cached image of `path`, so its source file gets closed once
    /// no open handle references it.
    fn forget(&self, path: &Path) {
        self.containers().retain(|_, c| c.path != path);
    }

    /// Resolve `rel` to a real file or a virtual image.
    pub fn lookup(&self, rel: &Path) -> Result<Node> {
        let rp = self.real(rel)?;
        match fs::metadata(&rp) {
            Ok(meta) => return Ok(Node { meta, image: None }),
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            Err(_) => {}
        }
        if let Some(src) = rp.file_name().and_then(source_name) {
            let src = rp.with_file_name(src);
            match fs::metadata(&src) {
                Ok(meta) if meta.is_file() => {
                    if let Some(image) = self.image(&src, &meta) {
                        return Ok(Node {
                            meta,
                            image: Some(image),
                        });
                    }
                }
                _ => self.forget(&src),
            }
        }
        Err(FsError::NotFound)
    }

    /// List directory `rel` with the virtual files added. A real file
    /// with the virtual name wins.
    pub fn read_dir(&self, rel: &Path) -> Result<Vec<DirEntry>> {
        let dir = self.real(rel)?;
        let mut names = Vec::new();
        for e in fs::read_dir(&dir)? {
            names.push(e?.file_name());
        }
        let present: HashSet<&OsStr> = names.iter().map(OsString::as_os_str).collect();
        let folded: HashSet<String> = names
            .iter()
            .filter_map(|n| n.to_str())
            .map(str::to_lowercase)
            .collect();
        // Whether a real file answers to the virtual name `vn`, as
        // `lookup` sees it. On a case-insensitive file system it may be
        // listed in another case, so only then is it worth a stat.
        let shadowed = |vn: &OsStr| {
            present.contains(vn)
                || vn
                    .to_str()
                    .is_some_and(|s| folded.contains(&s.to_lowercase()))
                    && fs::metadata(dir.join(vn)).is_ok()
        };
        let mut seen = HashSet::new();
        // Each name with its metadata and, when an image must be built for
        // it, its virtual name.
        let entries: Vec<_> = names
            .iter()
            .map(|name| {
                let path = dir.join(name);
                let meta = fs::metadata(&path).ok();
                let vn = match (&meta, virtual_name(name)) {
                    (Some(m), Some(vn)) if m.is_file() => {
                        seen.insert(key(&path, m));
                        (!shadowed(&vn)).then_some(vn)
                    }
                    _ => None,
                };
                (name, meta, vn)
            })
            .collect();
        let jobs: Vec<(PathBuf, &Metadata)> = entries
            .iter()
            .filter_map(|(name, meta, vn)| {
                vn.as_ref()?;
                Some((dir.join(name), meta.as_ref()?))
            })
            .collect();
        let mut images = self.images(&jobs).into_iter();
        let mut out = Vec::with_capacity(names.len());
        for (name, meta, vn) in entries {
            let virt = match (vn, &meta) {
                (Some(vn), Some(m)) => images.next().flatten().map(|image| DirEntry {
                    name: vn,
                    node: Some(Node {
                        meta: m.clone(),
                        image: Some(image),
                    }),
                }),
                _ => None,
            };
            out.push(DirEntry {
                name: name.clone(),
                node: meta.map(|meta| Node { meta, image: None }),
            });
            out.extend(virt);
        }
        // Source deleted: let its file be closed.
        self.containers()
            .retain(|k, c| c.path.parent() != Some(&dir) || seen.contains(k));
        Ok(out)
    }

    /// Open `rel`, whose `node` came from [`Vfs::lookup`], for reading.
    /// Write opens fail with [`FsError::ReadOnly`].
    pub fn open(&self, rel: &Path, node: Node, write: bool) -> Result<Handle> {
        if write {
            return Err(FsError::ReadOnly);
        }
        if let Some(img) = node.image {
            return Ok(Handle::Image(img));
        }
        if node.meta.is_dir() {
            return Err(FsError::IsDir);
        }
        if !node.meta.is_file() {
            // Opening a FIFO would block until a writer shows up.
            return Err(FsError::Access);
        }
        let mut opts = fs::OpenOptions::new();
        opts.read(true);
        // The node may have been swapped for a FIFO since the lookup: do not
        // wait for a writer. No effect on reads of a regular file.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::custom_flags(&mut opts, libc::O_NONBLOCK);
        let file = opts.open(self.real(rel)?)?;
        if !file.metadata()?.is_file() {
            return Err(FsError::Access);
        }
        Ok(Handle::File(file))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for (src, virt) in [
            ("a.nsz", "a.nsp"),
            ("B.NSZ", "B.NSP"),
            ("c.xcz", "c.xci"),
            ("D.XCZ", "D.XCI"),
            ("e.Nsz", "e.Nsp"),
        ] {
            assert_eq!(virtual_name(OsStr::new(src)).unwrap(), virt);
            assert_eq!(source_name(OsStr::new(virt)).unwrap(), src);
        }
        assert!(virtual_name(OsStr::new("x.nsp")).is_none());
        assert!(virtual_name(OsStr::new("nsz")).is_none());
        assert!(source_name(OsStr::new("x.nca")).is_none());
        assert!(source_name(OsStr::new("x.ns\u{e9}")).is_none());
    }

    /// Mirror of a temporary directory under `target/`.
    fn scratch(name: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/vfs-tests")
            .join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn passthrough_and_errors() {
        let dir = scratch("passthrough");
        fs::write(dir.join("notes.txt"), b"hello").unwrap();
        // Not a container: no virtual file.
        fs::write(dir.join("bad.nsz"), b"junk").unwrap();
        fs::create_dir(dir.join("sub")).unwrap();
        let v = Vfs::new(dir);
        let mut names: Vec<_> = v
            .read_dir(Path::new(""))
            .unwrap()
            .into_iter()
            .map(|e| {
                let is_dir = e.node.is_some_and(|n| n.is_dir());
                (e.name.into_string().unwrap(), is_dir)
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                ("bad.nsz".into(), false),
                ("notes.txt".into(), false),
                ("sub".into(), true)
            ]
        );
        let open = |rel: &str, write| {
            let rel = Path::new(rel);
            v.open(rel, v.lookup(rel)?, write)
        };
        let h = open("notes.txt", false).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(h.read(1, &mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], b"ello");
        assert!(matches!(open("notes.txt", true), Err(FsError::ReadOnly)));
        assert!(matches!(open("sub", false), Err(FsError::IsDir)));
        assert!(matches!(
            v.lookup(Path::new("bad.nsp")),
            Err(FsError::NotFound)
        ));
        assert!(matches!(
            v.read_dir(Path::new("notes.txt")),
            Err(FsError::NotDir)
        ));
        for rel in ["../passthrough/notes.txt", "sub/../notes.txt", "/etc"] {
            assert!(matches!(v.lookup(Path::new(rel)), Err(FsError::NotFound)));
        }
        assert!(matches!(
            v.read_dir(Path::new("..")),
            Err(FsError::NotFound)
        ));
    }

    /// Two names of one file share one container, which goes away with the
    /// last name.
    #[cfg(unix)]
    #[test]
    fn aliases_share_container() {
        let dir = scratch("aliases");
        fs::write(dir.join("a.nsz"), b"junk").unwrap();
        fs::hard_link(dir.join("a.nsz"), dir.join("B.nsz")).unwrap();
        let v = Vfs::new(dir.clone());
        v.read_dir(Path::new("")).unwrap();
        assert!(v.lookup(Path::new("B.nsp")).is_err());
        assert_eq!(v.containers().len(), 1);
        fs::remove_file(dir.join("a.nsz")).unwrap();
        v.read_dir(Path::new("")).unwrap();
        assert_eq!(v.containers().len(), 1);
        fs::remove_file(dir.join("B.nsz")).unwrap();
        v.read_dir(Path::new("")).unwrap();
        assert!(v.containers().is_empty());
    }

    /// Many containers in one directory go through the threaded build and
    /// still list in order, one container per distinct file.
    #[cfg(unix)]
    #[test]
    fn many_containers() {
        let dir = scratch("many");
        let mut want = vec!["notes.txt".to_string()];
        fs::write(dir.join("notes.txt"), b"hello").unwrap();
        for i in 0..10 {
            let name = format!("g{i}.nsz");
            fs::write(dir.join(&name), b"junk").unwrap();
            want.push(name);
        }
        fs::hard_link(dir.join("g0.nsz"), dir.join("h.nsz")).unwrap();
        want.push("h.nsz".into());
        let v = Vfs::new(dir.clone());
        let got: Vec<_> = v
            .read_dir(Path::new(""))
            .unwrap()
            .into_iter()
            .map(|e| e.name.into_string().unwrap())
            .collect();
        let mut listed: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(got, listed, "order of the real listing");
        listed.sort();
        want.sort();
        assert_eq!(listed, want);
        assert_eq!(v.containers().len(), 10);
    }

    /// An unreadable source is retried only after a delay.
    #[cfg(unix)]
    #[test]
    fn unreadable_backs_off() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("unreadable");
        let src = dir.join("p.nsz");
        fs::write(&src, b"junk").unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o000)).unwrap();
        if File::open(&src).is_ok() {
            eprintln!("running as root, skipped");
            return;
        }
        let v = Vfs::new(dir);
        assert!(v.lookup(Path::new("p.nsp")).is_err());
        let c = Arc::clone(v.containers().values().next().unwrap());
        assert!(c.retry_at.get().is_some());
        // Within the delay the failed container is reused, not rebuilt.
        assert!(v.lookup(Path::new("p.nsp")).is_err());
        assert!(Arc::ptr_eq(v.containers().values().next().unwrap(), &c));
        // Leave nothing unreadable behind for tools that walk `target`.
        fs::set_permissions(&src, fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// Check containers in `$FUSE_NSZ_TESTDATA`: `X.nsz` must match `X.nsp`
    /// (as written by `nsz -D`) byte for byte, and every NCA in a virtual
    /// XCI must hash to its name. An image restored from a `--keep` trailer
    /// must match `X.nsp`/`X.xci` byte for byte.
    #[test]
    fn real_data() {
        let Some(dir) = std::env::var_os("FUSE_NSZ_TESTDATA") else {
            eprintln!("FUSE_NSZ_TESTDATA not set, skipped");
            return;
        };
        let mut checked = 0;
        let mut vnames = Vec::new();
        for e in fs::read_dir(&dir).unwrap() {
            let path = e.unwrap().path();
            let Some(vn) = path.file_name().and_then(virtual_name) else {
                continue;
            };
            eprintln!("checking {}", path.display());
            let size = fs::metadata(&path).unwrap().len();
            let src: Shared =
                Arc::new(SubStorage::new(File::open(&path).unwrap(), 0, size).unwrap());
            let xci = vn.to_string_lossy().to_ascii_lowercase().ends_with(".xci");
            let reference = path.with_file_name(&vn);
            if let Some(kv) = image::build_keep(Arc::clone(&src), xci).unwrap()
                && reference.exists()
            {
                compare(&kv, &reference);
            }
            if xci {
                check_xci_ncas(&image::build_xci(src).unwrap());
            } else if reference.exists() {
                compare(&image::build_nsp(src).unwrap(), &reference);
            }
            checked += 1;
            vnames.push(vn);
        }
        assert!(checked > 0, "no .nsz/.xcz in {}", dir.to_string_lossy());
        // Every container builds, so the listing shows each virtual name
        // (or the real file that shadows it).
        let listed: HashSet<OsString> = Vfs::new(dir.into())
            .read_dir(Path::new(""))
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        for vn in vnames {
            assert!(listed.contains(&vn), "{} not listed", vn.to_string_lossy());
        }
    }

    fn compare(img: &Image, reference: &Path) {
        let f = File::open(reference).unwrap();
        let size = f.metadata().unwrap().len();
        assert_eq!(img.len(), size, "{}: size", reference.display());
        const CHUNK: usize = 4 << 20;
        let (mut a, mut b) = (vec![0u8; CHUNK], vec![0u8; CHUNK]);
        let mut off = 0;
        while off < size {
            let n = CHUNK.min((size - off) as usize);
            img.read_at(off, &mut a[..n]).unwrap();
            f.read_at(off, &mut b[..n]).unwrap();
            assert!(
                a[..n] == b[..n],
                "{}: mismatch at {off:#x}",
                reference.display()
            );
            off += n as u64;
        }
        eprintln!("  {} matches", reference.display());
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn check_xci_ncas(img: &Image) {
        use libhac::xci::XciRoot;
        use sha2::{Digest, Sha256};
        let x = XciRoot::parse(img).unwrap();
        for p in x.root.entries() {
            let part = x.partition(img, p).unwrap();
            for e in part.entries() {
                let name = e.name.to_ascii_lowercase();
                if !name.ends_with(".nca") {
                    continue;
                }
                let mut h = Sha256::new();
                img.read_chunks(e.offset, e.size, &mut |c| {
                    h.update(c);
                    Ok(())
                })
                .unwrap();
                let sum = hex(&h.finalize());
                assert!(
                    name.starts_with(&sum[..32]),
                    "{}/{}: sha256 {sum}",
                    p.name,
                    e.name
                );
            }
        }
        eprintln!("  every NCA hashes to its name");
    }
}

// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Platform neutral core: a mirror of a directory where every block
//! compressed `.nsz`/`.xcz` also shows up as a virtual `.nsp`/`.xci`.
//! Paths are relative to the mirrored directory. Read-only unless mounted
//! with `rw`.
//!
//! A symlink in the mirrored directory is an entry of its own: it is shown
//! as a link, and reading, changing or deleting it never touches its
//! target. Following it is left to the caller. The one thing served through
//! a link is the virtual image of a container it points to.

use libhac::image::{self, Image, Shared};
use libhac::{Error, ReadAt, SubStorage};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::io;
use std::panic;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

/// Print a line to stderr. Unlike `eprintln!` it does not panic when stderr
/// cannot be written (a closed pipe, a full disk): a panic would end the
/// thread that serves the request.
macro_rules! log {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}
pub(crate) use log;

/// Log a failed read, at most one line a second: a client that keeps
/// reading a broken file must not fill the log. The other errors of that
/// second are dropped.
pub fn log_read_error(path: &Path, len: usize, off: u64, e: &io::Error) {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let mut last = lock(&LAST);
    if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
        *last = Some(Instant::now());
        log!("{}: read {len}@{off}: {e}", path.display());
    }
}

/// Mount options shared by the backends.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// Changes to the mirrored directory are allowed.
    pub rw: bool,
    /// A source container whose virtual file is shown is left out.
    pub hide_sources: bool,
}

impl Options {
    /// Apply `o` if it is one of the shared options (`ro`, `rw`,
    /// `hide_sources`). Returns whether it was.
    pub fn parse_flag(&mut self, o: &str) -> bool {
        match o {
            "ro" => self.rw = false,
            "rw" => self.rw = true,
            "hide_sources" => self.hide_sources = true,
            _ => return false,
        }
        true
    }
}

/// The options of the `-o a,b` (or `-oa,b`) arguments, in order.
pub fn mount_options(args: &[String]) -> std::result::Result<Vec<&str>, String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let opts = match a.strip_prefix("-o") {
            Some("") => it.next().ok_or("-o needs an argument")?.as_str(),
            Some(o) => o,
            None => return Err(format!("unknown argument {a}")),
        };
        out.extend(opts.split(',').filter(|o| !o.is_empty()));
    }
    Ok(out)
}

/// Why an operation failed. Backends map it to their own error codes.
#[derive(Debug)]
pub enum FsError {
    NotFound,
    /// A change on a read-only mount.
    ReadOnly,
    /// A change the mirror refuses, e.g. writing into a virtual image or
    /// replacing one.
    Denied,
    Exists,
    IsDir,
    NotDir,
    /// The file cannot be served, e.g. a FIFO that would block on open.
    Access,
    Io(io::Error),
}

impl From<io::Error> for FsError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::NotFound => FsError::NotFound,
            io::ErrorKind::PermissionDenied => FsError::Access,
            io::ErrorKind::NotADirectory => FsError::NotDir,
            io::ErrorKind::AlreadyExists => FsError::Exists,
            _ => FsError::Io(e),
        }
    }
}

pub type Result<T> = std::result::Result<T, FsError>;

/// A file or directory as seen through the mount.
#[derive(Clone)]
pub struct Node {
    /// Metadata of the real entry itself, a symlink not followed, or of
    /// the source container for a virtual image.
    pub meta: Metadata,
    /// Size of the virtual image, for one.
    pub image_len: Option<u64>,
}

impl Node {
    /// A virtual image, not an entry of the mirrored directory.
    pub fn is_image(&self) -> bool {
        self.image_len.is_some()
    }

    pub fn is_dir(&self) -> bool {
        !self.is_image() && self.meta.is_dir()
    }

    /// Size in bytes, 0 for a directory.
    pub fn size(&self) -> u64 {
        match self.image_len {
            Some(len) => len,
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
    /// `None` when the entry cannot be read, e.g. it is gone again.
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

    /// Write all of `data` at `off`. Virtual images cannot be written.
    pub fn write(&self, off: u64, data: &[u8]) -> Result<()> {
        match self {
            Handle::File(f) => Ok(write_file_at(f, off, data)?),
            Handle::Image(_) => Err(FsError::Denied),
        }
    }

    /// Truncate or extend the file to `size` bytes.
    pub fn set_len(&self, size: u64) -> Result<()> {
        match self {
            Handle::File(f) => Ok(f.set_len(size)?),
            Handle::Image(_) => Err(FsError::Denied),
        }
    }

    /// Flush written data to the source file system.
    pub fn sync(&self) -> Result<()> {
        match self {
            Handle::File(f) => Ok(f.sync_all()?),
            Handle::Image(_) => Ok(()),
        }
    }
}

/// Positional write of all of `data`.
#[cfg(unix)]
fn write_file_at(f: &File, off: u64, data: &[u8]) -> io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(f, data, off)
}

/// Positional write of all of `data`.
#[cfg(windows)]
fn write_file_at(f: &File, mut off: u64, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        match std::os::windows::fs::FileExt::seek_write(f, data, off) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                data = &data[n..];
                off += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// `path` as a C string for a raw libc call.
#[cfg(unix)]
pub fn c_path(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// Rename `src` to `dst` in one step that fails with `AlreadyExists` if
/// `dst` exists, so a file created there meanwhile is never replaced.
#[cfg(target_os = "linux")]
fn rename_noreplace(src: &Path, dst: &Path) -> io::Result<()> {
    let (s, d) = (c_path(src)?, c_path(dst)?);
    // Raw syscall: musl before 1.2.5 has no renameat2 wrapper, so the
    // static release builds would not link.
    // SAFETY: both are valid C strings.
    let r = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            s.as_ptr(),
            libc::AT_FDCWD,
            d.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if r == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        // The kernel or the file system (CIFS, some FUSE ones) does not
        // support the flag.
        Some(libc::EINVAL | libc::ENOSYS) => rename_checked(src, dst),
        _ => Err(e),
    }
}

/// Rename `src` to `dst` in one step that fails with `AlreadyExists` if
/// `dst` exists, so a file created there meanwhile is never replaced.
#[cfg(target_os = "macos")]
fn rename_noreplace(src: &Path, dst: &Path) -> io::Result<()> {
    let (s, d) = (c_path(src)?, c_path(dst)?);
    // SAFETY: both are valid C strings.
    if unsafe { libc::renamex_np(s.as_ptr(), d.as_ptr(), libc::RENAME_EXCL) } == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        // The file system does not support the flag.
        Some(libc::ENOTSUP) => rename_checked(src, dst),
        _ => Err(e),
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn rename_noreplace(src: &Path, dst: &Path) -> io::Result<()> {
    rename_checked(src, dst)
}

/// Fallback without an atomic rename: a file created at `dst` between the
/// check and the rename is replaced.
#[cfg(unix)]
fn rename_checked(src: &Path, dst: &Path) -> io::Result<()> {
    if fs::symlink_metadata(dst).is_ok() {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    fs::rename(src, dst)
}

/// Rename `src` to `dst` in one step that fails with `AlreadyExists` if
/// `dst` exists, so a file created there meanwhile is never replaced.
#[cfg(windows)]
fn rename_noreplace(src: &Path, dst: &Path) -> io::Result<()> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    }
    let (s, d) = (verbatim(src), verbatim(dst));
    // SAFETY: both are NUL terminated UTF-16 strings. Without
    // MOVEFILE_REPLACE_EXISTING an existing `dst` is not replaced.
    if unsafe { MoveFileExW(s.as_ptr(), d.as_ptr(), 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The absolute `path` with the `\\?\` prefix and a NUL, so a raw Win32
/// call accepts it over 260 characters, as std does.
#[cfg(windows)]
fn verbatim(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let w: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .map(|c| {
            if c == u16::from(b'/') {
                b'\\'.into()
            } else {
                c
            }
        })
        .collect();
    let starts = |p: &str| w.iter().copied().take(p.len()).eq(p.encode_utf16());
    let (prefix, rest) = if starts(r"\\?\") || starts(r"\\.\") {
        ("", &w[..])
    } else if starts(r"\\") {
        // `\\server\share` becomes `\\?\UNC\server\share`.
        (r"\\?\UNC\", &w[2..])
    } else {
        (r"\\?\", &w[..])
    };
    let mut out: Vec<u16> = prefix.encode_utf16().collect();
    out.extend_from_slice(rest);
    out.push(0);
    out
}

/// Set the times of the file or directory at `path`, `None` keeping one
/// as is. The file is not opened, so its owner can touch it even without
/// read permission, as on any other file system. A symlink gets the times
/// itself.
#[cfg(unix)]
fn set_path_times(
    path: &Path,
    atime: Option<SystemTime>,
    mtime: Option<SystemTime>,
) -> io::Result<()> {
    let overflow = || io::Error::from(io::ErrorKind::InvalidInput);
    let ts = |t: Option<SystemTime>| -> io::Result<libc::timespec> {
        // SAFETY: timespec is plain data, valid when zeroed.
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        let Some(t) = t else {
            ts.tv_nsec = libc::UTIME_OMIT;
            return Ok(ts);
        };
        let (secs, nsecs) = match t.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => (
                i64::try_from(d.as_secs()).map_err(|_| overflow())?,
                d.subsec_nanos(),
            ),
            Err(e) => {
                let d = e.duration();
                let secs = i64::try_from(d.as_secs()).map_err(|_| overflow())?;
                match d.subsec_nanos() {
                    0 => (-secs, 0),
                    n => (-secs - 1, 1_000_000_000 - n),
                }
            }
        };
        #[allow(clippy::useless_conversion, reason = "time_t is i32 on some targets")]
        {
            ts.tv_sec = secs.try_into().map_err(|_| overflow())?;
        }
        // Below one billion, so it fits any c_long.
        ts.tv_nsec = nsecs as _;
        Ok(ts)
    };
    let times = [ts(atime)?, ts(mtime)?];
    let path = c_path(path)?;
    // SAFETY: `path` is a valid C string and `times` holds two timespecs.
    let r = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Set the times of the file or directory at `path`, `None` keeping one
/// as is. It is opened with write attributes access only. A symlink gets
/// the times itself.
#[cfg(windows)]
fn set_path_times(
    path: &Path,
    atime: Option<SystemTime>,
    mtime: Option<SystemTime>,
) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
    // Needed to open a directory.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    // The link, not its target.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut times = fs::FileTimes::new();
    if let Some(t) = atime {
        times = times.set_accessed(t);
    }
    if let Some(t) = mtime {
        times = times.set_modified(t);
    }
    fs::OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?
        .set_times(times)
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

/// What tells one version of a source file from the next.
#[derive(PartialEq)]
struct Stamp {
    size: u64,
    mtime: Option<SystemTime>,
    /// Seconds and nanoseconds. Unlike the mtime it cannot be set back, so
    /// it also shows a file that was replaced and given its old mtime.
    #[cfg(unix)]
    ctime: (i64, i64),
}

impl Stamp {
    fn of(meta: &Metadata) -> Self {
        Stamp {
            size: meta.len(),
            mtime: meta.modified().ok(),
            #[cfg(unix)]
            ctime: {
                use std::os::unix::fs::MetadataExt;
                (meta.ctime(), meta.ctime_nsec())
            },
        }
    }
}

/// One source container and the size of its virtual image. A new one takes
/// its place when the source changes, see [`Stamp`].
struct Container {
    key: Key,
    /// Real path the container was first reached by.
    path: PathBuf,
    stamp: Stamp,
    /// Size of the image, set by the first build. `None`: no virtual file
    /// (solid NCZ or parse error).
    len: OnceLock<Option<u64>>,
    /// Set when the build failed with an error that may go away by
    /// itself: the build is retried after this instant.
    retry_at: OnceLock<Instant>,
}

/// The containers seen so far, and the few images that are kept built.
#[derive(Default)]
struct Cache {
    containers: HashMap<Key, Arc<Container>>,
    /// Least recently used first, at most [`MAX_IMAGES`].
    images: VecDeque<(Arc<Container>, Arc<Image>)>,
}

impl Cache {
    /// Whether `c` is still the container cached for its source.
    fn current(&self, c: &Arc<Container>) -> bool {
        self.containers
            .get(&c.key)
            .is_some_and(|x| Arc::ptr_eq(x, c))
    }

    /// Let go of the images whose container is not cached any more, so
    /// their source files get closed once no open handle references them.
    fn prune(&mut self) {
        let containers = &self.containers;
        self.images
            .retain(|(c, _)| containers.get(&c.key).is_some_and(|x| Arc::ptr_eq(x, c)));
    }
}

/// How long a container whose build failed with a transient error stays
/// hidden before the next attempt, so it is not reopened and logged on
/// every lookup.
const RETRY: Duration = Duration::from_secs(30);

/// How long the virtual file that takes the place of a deleted or renamed
/// real file cannot be deleted or renamed itself. The name stays in the
/// listing, so whoever deletes it again, as if the first delete had failed,
/// would lose the source container too.
const UNSHADOW: Duration = Duration::from_secs(60);

/// Most images kept built at once. Each one holds its source file open and
/// the tables of its container in memory, so without a limit a large library
/// runs into the limit of open files. A listing only needs the sizes, which
/// stay cached; an image that was let go is built again when it is opened.
/// An open file keeps its image whatever this limit says.
const MAX_IMAGES: usize = 64;

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
    fold(path).into_owned().into_os_string()
}

/// `path` as the file system compares it.
#[cfg(unix)]
fn fold(path: &Path) -> Cow<'_, Path> {
    Cow::Borrowed(path)
}

/// `path` with ASCII letters folded, see [`Key`].
#[cfg(windows)]
fn fold(path: &Path) -> Cow<'_, Path> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .map(|c| u8::try_from(c).map_or(c, |b| b.to_ascii_lowercase().into()))
        .collect();
    Cow::Owned(OsString::from_wide(&wide).into())
}

pub struct Vfs {
    root: PathBuf,
    opts: Options,
    cache: Mutex<Cache>,
    /// Real files with a virtual name deleted or renamed away through the
    /// mount, by path as
    /// [`fold`] gives it, with the time: see [`UNSHADOW`].
    unshadowed: Mutex<HashMap<PathBuf, Instant>>,
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

/// The source path of the virtual file `path`, see [`source_name`].
pub fn source_path(path: &Path) -> Option<PathBuf> {
    let name = source_name(path.file_name()?)?;
    Some(path.with_file_name(name))
}

/// Whether a build error may go away by itself, so the container must be
/// retried after [`RETRY`] instead of staying hidden until the source
/// changes (a chmod changes neither size nor mtime). A truncated file is
/// not transient.
fn transient(e: &Error) -> bool {
    matches!(e, Error::Io(io) if io.kind() != io::ErrorKind::UnexpectedEof)
}

/// Metadata of the file a container at `path` is read from, `meta` being
/// that of `path` itself: a regular file, or a symlink to one.
fn container_meta(path: &Path, meta: &Metadata) -> Option<Metadata> {
    if meta.is_symlink() {
        fs::metadata(path).ok().filter(Metadata::is_file)
    } else {
        meta.is_file().then(|| meta.clone())
    }
}

/// The image of the container at `path`. Fails when the file opened is not
/// the version `stamp` was taken from.
fn build_container(path: &Path, stamp: &Stamp) -> libhac::Result<Image> {
    let file = File::open(path)?;
    if Stamp::of(&file.metadata()?) != *stamp {
        return Err(io::Error::other("changed while it was opened").into());
    }
    let src: Shared = Arc::new(SubStorage::new(file, 0, stamp.size)?);
    // The source file stays open as long as the image (or an open handle)
    // references it.
    image::build(src)
}

/// Lock `m`, also after a panic in another holder: the guarded maps stay
/// consistent between single operations.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Vfs {
    pub fn new(root: PathBuf, opts: Options) -> Self {
        Vfs {
            root,
            opts,
            cache: Mutex::new(Cache::default()),
            unshadowed: Mutex::new(HashMap::new()),
        }
    }

    /// The mirrored directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Changes to the mirrored directory are allowed.
    pub fn rw(&self) -> bool {
        self.opts.rw
    }

    fn cache(&self) -> MutexGuard<'_, Cache> {
        lock(&self.cache)
    }

    /// `rel` under the root. Only plain names are accepted: `..`, a root
    /// or a drive prefix would make `join` leave the root.
    fn real(&self, rel: &Path) -> Result<PathBuf> {
        if !rel.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(FsError::NotFound);
        }
        Ok(self.root.join(rel))
    }

    /// The cached container of the source at `path`, a new one when the
    /// source changed or a failed build is due again.
    fn container(&self, path: &Path, meta: &Metadata) -> Arc<Container> {
        let (key, stamp) = (key(path, meta), Stamp::of(meta));
        let mut cache = self.cache();
        if let Some(c) = cache.containers.get(&key)
            && c.stamp == stamp
            && !c.retry_at.get().is_some_and(|&t| Instant::now() >= t)
        {
            return Arc::clone(c);
        }
        let c = Arc::new(Container {
            key: self::key(path, meta),
            path: path.to_path_buf(),
            stamp,
            len: OnceLock::new(),
            retry_at: OnceLock::new(),
        });
        cache.containers.insert(key, Arc::clone(&c));
        cache.prune();
        c
    }

    /// Cache `image` as the most recently used one of `c`.
    fn keep(&self, c: &Arc<Container>, image: Arc<Image>) {
        let mut cache = self.cache();
        // Replaced or forgotten meanwhile: the source must not stay open.
        if !cache.current(c) {
            return;
        }
        cache.images.retain(|(x, _)| !Arc::ptr_eq(x, c));
        cache.images.push_back((Arc::clone(c), image));
        let evicted = if cache.images.len() > MAX_IMAGES {
            cache.images.pop_front()
        } else {
            None
        };
        // Closing the source of the image let go of can take a round trip
        // to a NAS: not while other lookups wait for the lock.
        drop(cache);
        drop(evicted);
    }

    /// The size of the virtual image of the source container at `path`, if
    /// it has one. The first call builds the image.
    fn image_len(&self, path: &Path, meta: &Metadata) -> Option<u64> {
        let c = self.container(path, meta);
        self.len_of(&c)
    }

    fn len_of(&self, c: &Arc<Container>) -> Option<u64> {
        // Built outside the lock, so a slow source does not stall other
        // lookups.
        *c.len
            .get_or_init(|| match build_container(&c.path, &c.stamp) {
                Ok(img) => {
                    let len = img.len();
                    self.keep(c, Arc::new(img));
                    Some(len)
                }
                Err(e) => {
                    let note = if matches!(e, Error::Unsupported(_)) {
                        ", not exposed"
                    } else {
                        ""
                    };
                    log!("{}: {e}{note}", c.path.display());
                    if transient(&e) {
                        let _ = c.retry_at.set(Instant::now() + RETRY);
                    }
                    None
                }
            })
    }

    /// The virtual image of the source container at `path`, built again
    /// when the cache let go of it.
    fn image(&self, path: &Path, meta: &Metadata) -> Option<Arc<Image>> {
        let c = self.container(path, meta);
        let len = self.len_of(&c)?;
        let held = self
            .cache()
            .images
            .iter()
            .find(|(x, _)| Arc::ptr_eq(x, &c))
            .map(|(_, img)| Arc::clone(img));
        let image = match held {
            Some(img) => img,
            None => match build_container(&c.path, &c.stamp) {
                Ok(img) if img.len() == len => Arc::new(img),
                // Not what the first build saw: the next lookup starts
                // over with a new container.
                r => {
                    if let Err(e) = r {
                        log!("{}: {e}", c.path.display());
                    }
                    let mut cache = self.cache();
                    if cache.current(&c) {
                        cache.containers.remove(&c.key);
                    }
                    return None;
                }
            },
        };
        self.keep(&c, Arc::clone(&image));
        Some(image)
    }

    /// [`Vfs::image_len`] of every job, in order. The builds run on up to
    /// [`BUILD_THREADS`] threads, the calling one included. A thread that
    /// cannot be spawned only means fewer of them.
    fn image_lens(&self, jobs: &[(PathBuf, &Metadata)]) -> Vec<Option<u64>> {
        if jobs.len() <= 1 {
            return jobs.iter().map(|(p, m)| self.image_len(p, m)).collect();
        }
        let next = AtomicUsize::new(0);
        let work = || {
            let mut done = Vec::new();
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some((p, m)) = jobs.get(i) else {
                    return done;
                };
                done.push((i, self.image_len(p, m)));
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
            for (i, len) in done {
                out[i] = len;
            }
        });
        out
    }

    /// Drop the cached images of `path` and of everything under it, so
    /// their source files get closed once no open handle references them.
    /// WinFsp may pass a name in another case than the one cached.
    fn forget(&self, path: &Path) {
        let path = fold(path);
        let mut cache = self.cache();
        cache
            .containers
            .retain(|_, c| !fold(&c.path).starts_with(&path));
        cache.prune();
    }

    /// Whether the real file `path` is a source container hidden by
    /// `hide_sources`: its virtual file is shown in its place.
    fn hidden(&self, path: &Path, meta: &Metadata) -> bool {
        self.opts.hide_sources
            && path.file_name().and_then(virtual_name).is_some_and(|vn| {
                matches!(fs::symlink_metadata(path.with_file_name(vn)),
                    Err(e) if e.kind() == io::ErrorKind::NotFound)
                    && container_meta(path, meta)
                        .is_some_and(|m| self.image_len(path, &m).is_some())
            })
    }

    /// Resolve `rel` to a real file or a virtual image.
    pub fn lookup(&self, rel: &Path) -> Result<Node> {
        let rp = self.real(rel)?;
        // The root is the user's choice and may be a link.
        let meta = if rel.as_os_str().is_empty() {
            fs::metadata(&rp)
        } else {
            fs::symlink_metadata(&rp)
        };
        match meta {
            Ok(meta) if self.hidden(&rp, &meta) => return Err(FsError::NotFound),
            Ok(meta) => {
                return Ok(Node {
                    meta,
                    image_len: None,
                });
            }
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            Err(_) => {}
        }
        if let Some(src) = rp.file_name().and_then(source_name) {
            let src = rp.with_file_name(src);
            // Followed: a link to a container is a source too.
            match fs::metadata(&src) {
                Ok(meta) if meta.is_file() => {
                    if let Some(len) = self.image_len(&src, &meta) {
                        return Ok(Node {
                            meta,
                            image_len: Some(len),
                        });
                    }
                }
                _ => self.forget(&src),
            }
        }
        Err(FsError::NotFound)
    }

    /// List directory `rel` with the virtual files added. A real file
    /// with the virtual name wins. With `hide_sources` a virtual file
    /// replaces its source.
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
                    && fs::symlink_metadata(dir.join(vn)).is_ok()
        };
        let mut seen = HashSet::new();
        // Each name with its metadata and, when an image must be built for
        // it, its virtual name and the metadata of the container.
        let entries: Vec<_> = names
            .iter()
            .map(|name| {
                let path = dir.join(name);
                let meta = fs::symlink_metadata(&path).ok();
                let virt = meta.as_ref().zip(virtual_name(name)).and_then(|(m, vn)| {
                    let cm = container_meta(&path, m)?;
                    seen.insert(key(&path, &cm));
                    (!shadowed(&vn)).then_some((vn, cm))
                });
                (name, meta, virt)
            })
            .collect();
        let jobs: Vec<(PathBuf, &Metadata)> = entries
            .iter()
            .filter_map(|(name, _, virt)| Some((dir.join(name), &virt.as_ref()?.1)))
            .collect();
        let mut lens = self.image_lens(&jobs).into_iter();
        let mut out = Vec::with_capacity(names.len());
        for (name, meta, virt) in entries {
            let virt = virt.and_then(|(vn, cm)| {
                lens.next().flatten().map(|len| DirEntry {
                    name: vn,
                    node: Some(Node {
                        meta: cm,
                        image_len: Some(len),
                    }),
                })
            });
            if !(self.opts.hide_sources && virt.is_some()) {
                out.push(DirEntry {
                    name: name.clone(),
                    node: meta.map(|meta| Node {
                        meta,
                        image_len: None,
                    }),
                });
            }
            out.extend(virt);
        }
        // Source deleted: let its file be closed.
        let mut cache = self.cache();
        cache
            .containers
            .retain(|k, c| c.path.parent() != Some(&dir) || seen.contains(k));
        cache.prune();
        Ok(out)
    }

    /// Open `rel`, whose `node` came from [`Vfs::lookup`], for reading,
    /// and for writing with `write` or `truncate`. Write opens fail with
    /// [`FsError::ReadOnly`] on a read-only mount, and with
    /// [`FsError::Denied`] on a virtual image.
    pub fn open(&self, rel: &Path, node: Node, write: bool, truncate: bool) -> Result<Handle> {
        let write = write || truncate;
        if write {
            self.writable()?;
        }
        if node.is_image() {
            if write {
                return Err(FsError::Denied);
            }
            let src = source_path(&self.real(rel)?).ok_or(FsError::NotFound)?;
            return match self.image(&src, &node.meta) {
                Some(img) => Ok(Handle::Image(img)),
                None => Err(FsError::NotFound),
            };
        }
        if node.meta.is_dir() {
            return Err(FsError::IsDir);
        }
        if !node.meta.is_file() {
            // Opening a FIFO would block until a writer shows up.
            return Err(FsError::Access);
        }
        let mut opts = fs::OpenOptions::new();
        opts.read(true).write(write).truncate(truncate);
        // The node may have been swapped for a FIFO or a symlink since the
        // lookup: do not wait for a writer, do not follow the link. No
        // effect on a regular file.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::custom_flags(
            &mut opts,
            libc::O_NONBLOCK | libc::O_NOFOLLOW,
        );
        let file = opts.open(self.real(rel)?)?;
        if !file.metadata()?.is_file() {
            return Err(FsError::Access);
        }
        Ok(Handle::File(file))
    }

    fn writable(&self) -> Result<()> {
        if self.opts.rw {
            Ok(())
        } else {
            Err(FsError::ReadOnly)
        }
    }

    /// Look up `rel` for a change, with the real path the change applies
    /// to: the source container of a virtual image.
    fn target(&self, rel: &Path) -> Result<(Node, PathBuf)> {
        self.writable()?;
        let node = self.lookup(rel)?;
        let rp = self.real(rel)?;
        if !node.is_image() {
            return Ok((node, rp));
        }
        let src = source_path(&rp).ok_or(FsError::NotFound)?;
        Ok((node, src))
    }

    /// Create the regular file `rel` and open it for reading and writing.
    /// `mode` gives its permissions on Unix, where only the permission bits
    /// are taken: no set-user-ID or set-group-ID file is made through the
    /// mount.
    pub fn create(&self, rel: &Path, mode: u32) -> Result<(Node, Handle)> {
        self.writable()?;
        if self.lookup(rel).is_ok() {
            return Err(FsError::Exists);
        }
        let mut opts = fs::OpenOptions::new();
        // A hidden source fails here with Exists, so it is never truncated.
        opts.read(true).write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, mode & 0o777);
        #[cfg(windows)]
        let _ = mode;
        let file = opts.open(self.real(rel)?)?;
        let meta = file.metadata()?;
        Ok((
            Node {
                meta,
                image_len: None,
            },
            Handle::File(file),
        ))
    }

    /// Create the directory `rel`. `mode` gives its permissions on Unix, the
    /// permission bits only as for [`Vfs::create`]. The sticky bit comes
    /// with a chmod: not every system takes it at mkdir.
    pub fn mkdir(&self, rel: &Path, mode: u32) -> Result<Node> {
        self.writable()?;
        if self.lookup(rel).is_ok() {
            return Err(FsError::Exists);
        }
        let rp = self.real(rel)?;
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut fs::DirBuilder::new(), mode & 0o777)
            .create(&rp)?;
        #[cfg(windows)]
        {
            let _ = mode;
            fs::create_dir(&rp)?;
        }
        let meta = fs::symlink_metadata(&rp)?;
        Ok(Node {
            meta,
            image_len: None,
        })
    }

    /// The target of the symlink `rel`.
    #[cfg(unix)]
    pub fn read_link(&self, rel: &Path) -> Result<PathBuf> {
        Ok(fs::read_link(self.real(rel)?)?)
    }

    /// Fails with [`FsError::Denied`] while the virtual file `rel` cannot
    /// be deleted or renamed, see [`UNSHADOW`].
    pub fn deletable(&self, rel: &Path) -> Result<()> {
        let name = fold(&self.real(rel)?).into_owned();
        match lock(&self.unshadowed).get(&name) {
            Some(t) if t.elapsed() < UNSHADOW => Err(FsError::Denied),
            _ => Ok(()),
        }
    }

    /// Remove the file `rel`. A virtual image removes its source, and
    /// returns the path of that source. A symlink is removed itself, also
    /// when it is the source.
    pub fn unlink(&self, rel: &Path) -> Result<Option<PathBuf>> {
        let (node, path) = self.target(rel)?;
        if node.is_dir() {
            return Err(FsError::IsDir);
        }
        if node.is_image() {
            self.deletable(rel)?;
        }
        // On Windows the cached image must let go of the source first.
        self.forget(&path);
        fs::remove_file(&path)?;
        if !node.is_image() {
            self.unshadow(rel, &path);
        }
        Ok(node.image_len.and(source_path(rel)))
    }

    /// The real file `rel` at `path` is gone: when it hid a virtual file,
    /// that one shows up under its name and is guarded, see [`UNSHADOW`].
    fn unshadow(&self, rel: &Path, path: &Path) {
        if source_path(rel).is_some() {
            let mut gone = lock(&self.unshadowed);
            gone.retain(|_, t| t.elapsed() < UNSHADOW);
            gone.insert(fold(path).into_owned(), Instant::now());
        }
    }

    /// Remove the empty directory `rel`.
    pub fn rmdir(&self, rel: &Path) -> Result<()> {
        self.writable()?;
        if rel.as_os_str().is_empty() {
            return Err(FsError::Denied);
        }
        if !self.lookup(rel)?.is_dir() {
            return Err(FsError::NotDir);
        }
        Ok(fs::remove_dir(self.real(rel)?)?)
    }

    /// The real directory `rel` has no entries. Hidden sources count, as
    /// they keep [`Vfs::rmdir`] from removing it.
    #[cfg_attr(unix, allow(dead_code, reason = "FUSE rmdir reports it"))]
    pub fn is_empty_dir(&self, rel: &Path) -> Result<bool> {
        Ok(fs::read_dir(self.real(rel)?)?.next().is_none())
    }

    /// Rename `from` to `to`, replacing `to` unless `noreplace`. A virtual
    /// image renames its source container, so `to` must be a virtual name
    /// with the same extension and must not exist. Replacing a virtual file
    /// or a hidden source is refused: it would leave the source behind, or
    /// delete it.
    /// For a virtual image, returns the old and new paths of its source.
    pub fn rename(
        &self,
        from: &Path,
        to: &Path,
        noreplace: bool,
    ) -> Result<Option<(PathBuf, PathBuf)>> {
        self.writable()?;
        if from.as_os_str().is_empty() || to.as_os_str().is_empty() {
            return Err(FsError::Denied);
        }
        let node = self.lookup(from)?;
        let image = node.is_image();
        let (rf, rt) = (self.real(from)?, self.real(to)?);
        if rf == rt {
            return Ok(None);
        }
        if image {
            self.deletable(from)?;
        }
        let target = self.lookup(to);
        // `to` is `from` in another case, on a case-insensitive file
        // system. Same file alone is not enough: a hard link, or a source
        // and its own virtual file, are other names that must not be
        // replaced.
        let same = rf.as_os_str().eq_ignore_ascii_case(rt.as_os_str())
            && target
                .as_ref()
                .is_ok_and(|t| key(&rf, &node.meta) == key(&rt, &t.meta));
        if !same {
            match target {
                Ok(t) if t.is_image() || image => {
                    return Err(FsError::Denied);
                }
                Ok(_) if noreplace => return Err(FsError::Exists),
                Ok(_) => {}
                // A hidden source.
                Err(_) if fs::symlink_metadata(&rt).is_ok() => return Err(FsError::Denied),
                Err(_) => {}
            }
        }
        let (src, dst) = if image {
            // An `.nsp` stays one: its source would become an `.xcz`.
            let ext = |p: &Path| p.extension().map(OsStr::to_ascii_lowercase);
            if ext(&rf) != ext(&rt) {
                return Err(FsError::Denied);
            }
            let dst = source_path(&rt).ok_or(FsError::Denied)?;
            if !same && fs::symlink_metadata(&dst).is_ok() {
                return Err(FsError::Denied);
            }
            (source_path(&rf).ok_or(FsError::NotFound)?, dst)
        } else {
            (rf, rt)
        };
        self.forget(&src);
        self.forget(&dst);
        // The checks above can race with another process creating the
        // target, so the rename itself must refuse to replace it.
        if !same && (noreplace || image) {
            rename_noreplace(&src, &dst).map_err(|e| match e.kind() {
                io::ErrorKind::AlreadyExists if image => FsError::Denied,
                _ => FsError::from(e),
            })?;
        } else {
            fs::rename(&src, &dst)?;
        }
        if !image && !same {
            self.unshadow(from, &src);
        }
        Ok(if image {
            source_path(from).zip(source_path(to))
        } else {
            None
        })
    }

    /// Set the access and modification times of `rel`, or of its source
    /// container. A new mtime makes the image be built again.
    pub fn set_times(
        &self,
        rel: &Path,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> Result<()> {
        let (_, path) = self.target(rel)?;
        Ok(set_path_times(&path, atime, mtime)?)
    }

    /// Set the permissions of `rel`, or of its source container. Refused
    /// for a symlink: it has none of its own, and the change would land on
    /// its target. On Unix only the permission bits and the sticky bit
    /// change, which are the ones the mount shows: set-user-ID and
    /// set-group-ID stay as the source has them.
    pub fn set_permissions(&self, rel: &Path, perm: fs::Permissions) -> Result<()> {
        let (_, path) = self.target(rel)?;
        let meta = fs::symlink_metadata(&path)?;
        if meta.is_symlink() {
            return Err(FsError::Denied);
        }
        #[cfg(unix)]
        let perm = {
            use std::os::unix::fs::PermissionsExt;
            let kept = meta.permissions().mode() & 0o6000;
            fs::Permissions::from_mode(kept | perm.mode() & 0o1777)
        };
        #[cfg(windows)]
        let _ = meta;
        Ok(fs::set_permissions(path, perm)?)
    }

    /// Truncate or extend the real file `rel` to `size` bytes.
    #[cfg_attr(
        windows,
        allow(dead_code, reason = "WinFsp truncates through the open handle")
    )]
    pub fn truncate(&self, rel: &Path, size: u64) -> Result<()> {
        let node = self.lookup(rel)?;
        self.open(rel, node, true, false)?.set_len(size)
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
        let v = Vfs::new(dir, Options::default());
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
            v.open(rel, v.lookup(rel)?, write, false)
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

    /// A PFS0 holding one plain file: an NSZ without NCZ, whose image is
    /// the same bytes.
    fn pfs0() -> Vec<u8> {
        let data = b"hello world";
        let mut v = b"PFS0".to_vec();
        for n in [1u32, 8, 0] {
            v.extend(n.to_le_bytes());
        }
        v.extend(0u64.to_le_bytes());
        v.extend((data.len() as u64).to_le_bytes());
        v.extend([0u8; 8]);
        v.extend(b"a.bin\0\0\0");
        v.extend(data);
        v
    }

    fn listing(v: &Vfs, rel: &str) -> Vec<String> {
        let mut n: Vec<_> = v
            .read_dir(Path::new(rel))
            .unwrap()
            .into_iter()
            .map(|e| e.name.into_string().unwrap())
            .collect();
        n.sort();
        n
    }

    fn read_all(v: &Vfs, rel: &str) -> Vec<u8> {
        let rel = Path::new(rel);
        let h = v.open(rel, v.lookup(rel).unwrap(), false, false).unwrap();
        let mut buf = vec![0u8; 4096];
        let n = h.read(0, &mut buf).unwrap();
        buf.truncate(n);
        buf
    }

    #[test]
    fn hide_sources() {
        let dir = scratch("hide");
        fs::write(dir.join("g.nsz"), pfs0()).unwrap();
        fs::write(dir.join("bad.nsz"), b"junk").unwrap();
        fs::write(dir.join("s.nsz"), pfs0()).unwrap();
        fs::write(dir.join("s.nsp"), b"real").unwrap();
        let shown = Vfs::new(dir.clone(), Options::default());
        assert_eq!(
            listing(&shown, ""),
            ["bad.nsz", "g.nsp", "g.nsz", "s.nsp", "s.nsz"]
        );
        let opts = Options {
            hide_sources: true,
            ..Options::default()
        };
        let v = Vfs::new(dir, opts);
        // Only a source whose virtual file is shown is hidden.
        assert_eq!(listing(&v, ""), ["bad.nsz", "g.nsp", "s.nsp", "s.nsz"]);
        assert!(matches!(
            v.lookup(Path::new("g.nsz")),
            Err(FsError::NotFound)
        ));
        assert!(v.lookup(Path::new("s.nsz")).is_ok());
        assert_eq!(read_all(&v, "g.nsp"), pfs0());
    }

    #[test]
    fn read_write() {
        let dir = scratch("rw");
        fs::write(dir.join("g.nsz"), pfs0()).unwrap();
        fs::write(dir.join("notes.txt"), b"hello").unwrap();
        fs::create_dir(dir.join("sub")).unwrap();
        let ro = Vfs::new(dir.clone(), Options::default());
        assert!(matches!(
            ro.unlink(Path::new("notes.txt")),
            Err(FsError::ReadOnly)
        ));
        assert!(matches!(
            ro.create(Path::new("new"), 0o644),
            Err(FsError::ReadOnly)
        ));
        let v = Vfs::new(
            dir.clone(),
            Options {
                rw: true,
                hide_sources: true,
            },
        );
        let p = Path::new;

        // Virtual files: no content changes.
        let open = |rel: &str, write, trunc| {
            let rel = p(rel);
            v.open(rel, v.lookup(rel)?, write, trunc)
        };
        assert!(matches!(open("g.nsp", true, false), Err(FsError::Denied)));
        assert!(matches!(open("g.nsp", false, true), Err(FsError::Denied)));
        assert!(matches!(v.truncate(p("g.nsp"), 0), Err(FsError::Denied)));
        // The hidden source cannot be clobbered by a create.
        assert!(matches!(v.create(p("g.nsz"), 0o644), Err(FsError::Exists)));
        assert!(matches!(v.create(p("g.nsp"), 0o644), Err(FsError::Exists)));
        assert_eq!(fs::read(dir.join("g.nsz")).unwrap(), pfs0());

        // Renaming a virtual file renames its source, and keeps its kind.
        for to in ["g.bin", "g.xci", "g.nsz"] {
            assert!(
                matches!(v.rename(p("g.nsp"), p(to), false), Err(FsError::Denied)),
                "{to}"
            );
        }
        assert!(dir.join("g.nsz").is_file());
        assert_eq!(
            v.rename(p("g.nsp"), p("sub/H.NSP"), false).unwrap(),
            Some((p("g.nsz").into(), p("sub/H.NSZ").into()))
        );
        assert!(dir.join("sub/H.NSZ").is_file());
        assert!(!dir.join("g.nsz").exists());
        assert_eq!(listing(&v, "sub"), ["H.NSP"]);
        assert_eq!(read_all(&v, "sub/H.NSP"), pfs0());
        // Replacing a virtual file, or its hidden source, is refused.
        assert!(matches!(
            v.rename(p("notes.txt"), p("sub/H.NSP"), false),
            Err(FsError::Denied)
        ));
        assert!(matches!(
            v.rename(p("notes.txt"), p("sub/H.NSZ"), false),
            Err(FsError::Denied)
        ));
        fs::write(dir.join("sub/I.NSZ"), pfs0()).unwrap();
        assert!(matches!(
            v.rename(p("sub/H.NSP"), p("sub/I.NSP"), false),
            Err(FsError::Denied)
        ));
        assert_eq!(
            v.unlink(p("sub/I.NSP")).unwrap(),
            Some(p("sub/I.NSZ").into())
        );
        assert!(!dir.join("sub/I.NSZ").exists());

        // Times and modes go to the source.
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        v.set_times(p("sub/H.NSP"), None, Some(t)).unwrap();
        assert_eq!(v.lookup(p("sub/H.NSP")).unwrap().mtime(), t);
        assert_eq!(
            fs::metadata(dir.join("sub/H.NSZ"))
                .unwrap()
                .modified()
                .unwrap(),
            t
        );
        assert_eq!(read_all(&v, "sub/H.NSP"), pfs0());
        let mut perm = fs::metadata(dir.join("sub/H.NSZ")).unwrap().permissions();
        perm.set_readonly(true);
        v.set_permissions(p("sub/H.NSP"), perm.clone()).unwrap();
        assert!(
            fs::metadata(dir.join("sub/H.NSZ"))
                .unwrap()
                .permissions()
                .readonly()
        );
        #[expect(
            clippy::permissions_set_readonly_false,
            reason = "only the scratch file, made writable again"
        )]
        perm.set_readonly(false);
        v.set_permissions(p("sub/H.NSP"), perm).unwrap();

        // Real files: full passthrough.
        let (_, h) = v.create(p("new.txt"), 0o644).unwrap();
        h.write(0, b"abcdef").unwrap();
        h.set_len(4).unwrap();
        drop(h);
        assert_eq!(fs::read(dir.join("new.txt")).unwrap(), b"abcd");
        open("new.txt", true, true).unwrap().write(1, b"x").unwrap();
        assert_eq!(fs::read(dir.join("new.txt")).unwrap(), b"\0x");
        v.truncate(p("notes.txt"), 2).unwrap();
        assert_eq!(fs::read(dir.join("notes.txt")).unwrap(), b"he");
        assert!(matches!(
            v.rename(p("notes.txt"), p("new.txt"), true),
            Err(FsError::Exists)
        ));
        v.rename(p("notes.txt"), p("new.txt"), false).unwrap();
        assert_eq!(fs::read(dir.join("new.txt")).unwrap(), b"he");
        assert_eq!(v.unlink(p("new.txt")).unwrap(), None);
        assert!(!dir.join("new.txt").exists());

        // Directories.
        v.mkdir(p("d"), 0o755).unwrap();
        assert!(matches!(v.mkdir(p("d"), 0o755), Err(FsError::Exists)));
        v.rename(p("sub/H.NSP"), p("d/H.NSP"), false).unwrap();
        assert!(matches!(v.rmdir(p("d")), Err(FsError::Io(_))));
        v.rename(p("d"), p("e"), false).unwrap();
        assert_eq!(read_all(&v, "e/H.NSP"), pfs0());
        assert!(matches!(v.rmdir(p("e/H.NSP")), Err(FsError::NotDir)));
        assert!(matches!(v.unlink(p("e")), Err(FsError::IsDir)));
        v.unlink(p("e/H.NSP")).unwrap();
        v.rmdir(p("e")).unwrap();
        v.rmdir(p("sub")).unwrap();
        assert!(listing(&v, "").is_empty());
        assert!(matches!(v.rmdir(p("")), Err(FsError::Denied)));
        assert!(matches!(
            v.rename(p("../x"), p("y"), false),
            Err(FsError::NotFound)
        ));

        // The atomic rename never replaces, file or directory.
        fs::write(dir.join("a"), b"a").unwrap();
        fs::write(dir.join("b"), b"b").unwrap();
        fs::create_dir(dir.join("c")).unwrap();
        for to in ["b", "c"] {
            let e = rename_noreplace(&dir.join("a"), &dir.join(to)).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        }
        assert_eq!(fs::read(dir.join("b")).unwrap(), b"b");
        rename_noreplace(&dir.join("a"), &dir.join("d")).unwrap();
        rename_noreplace(&dir.join("c"), &dir.join("e")).unwrap();
        assert_eq!(fs::read(dir.join("d")).unwrap(), b"a");
        for f in ["b", "d"] {
            fs::remove_file(dir.join(f)).unwrap();
        }
        fs::remove_dir(dir.join("e")).unwrap();

        // With the source shown, it cannot replace its own virtual file.
        let v = Vfs::new(
            dir.clone(),
            Options {
                rw: true,
                hide_sources: false,
            },
        );
        fs::write(dir.join("k.nsz"), pfs0()).unwrap();
        assert!(matches!(
            v.rename(p("k.nsz"), p("k.nsp"), false),
            Err(FsError::Denied)
        ));
        // The owner can touch a file it cannot read.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.join("k.nsz"), fs::Permissions::from_mode(0o000)).unwrap();
            v.set_times(p("k.nsz"), None, Some(t)).unwrap();
            assert_eq!(
                fs::metadata(dir.join("k.nsz")).unwrap().modified().unwrap(),
                t
            );
        }
    }

    /// A symlink is an entry of its own: nothing is read, changed or deleted
    /// through it, except the image of a container it points to.
    #[cfg(unix)]
    #[test]
    fn symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let top = scratch("symlinks");
        let (dir, out) = (top.join("src"), top.join("outside"));
        fs::create_dir(&dir).unwrap();
        fs::create_dir_all(out.join("sub")).unwrap();
        fs::write(out.join("sub/data.bin"), b"data").unwrap();
        fs::write(out.join("secret.txt"), b"secret").unwrap();
        fs::write(out.join("c.nsz"), pfs0()).unwrap();
        fs::write(dir.join("x.nsz"), pfs0()).unwrap();
        for (target, link) in [
            ("../outside", "dlink"),
            ("../outside/secret.txt", "flink"),
            ("nowhere", "dead"),
            // Dangling, with the name of the virtual file of x.nsz.
            ("nowhere", "x.nsp"),
            ("../outside/c.nsz", "l.nsz"),
        ] {
            symlink(target, dir.join(link)).unwrap();
        }
        let p = Path::new;
        let hide = Options {
            hide_sources: true,
            ..Options::default()
        };
        // A linked container is hidden like any other. x.nsz is not: the
        // link x.nsp takes the name of its virtual file.
        assert_eq!(
            listing(&Vfs::new(dir.clone(), hide), ""),
            ["dead", "dlink", "flink", "l.nsp", "x.nsp", "x.nsz"]
        );
        let v = Vfs::new(
            dir.clone(),
            Options {
                rw: true,
                hide_sources: false,
            },
        );
        assert_eq!(
            listing(&v, ""),
            ["dead", "dlink", "flink", "l.nsp", "l.nsz", "x.nsp", "x.nsz"]
        );
        for link in ["dlink", "flink", "dead", "x.nsp", "l.nsz"] {
            let node = v.lookup(p(link)).unwrap();
            assert!(node.meta.is_symlink() && !node.is_image(), "{link}");
            assert!(!node.is_dir(), "{link}");
        }
        assert_eq!(v.read_link(p("dlink")).unwrap(), p("../outside"));
        assert_eq!(read_all(&v, "l.nsp"), pfs0());

        // No read and no change goes through a link.
        let secret = out.join("secret.txt");
        let state = || {
            let m = fs::metadata(&secret).unwrap();
            (m.permissions().mode(), m.modified().unwrap())
        };
        let before = state();
        let node = v.lookup(p("flink")).unwrap();
        assert!(matches!(
            v.open(p("flink"), node, false, false),
            Err(FsError::Access)
        ));
        assert!(matches!(v.truncate(p("flink"), 0), Err(FsError::Access)));
        for rel in ["flink", "l.nsp"] {
            assert!(matches!(
                v.set_permissions(p(rel), fs::Permissions::from_mode(0o600)),
                Err(FsError::Denied)
            ));
        }
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let container = fs::metadata(out.join("c.nsz")).unwrap().modified().unwrap();
        // The times of a virtual file go to its source, here a link.
        for (rel, link) in [("flink", "flink"), ("l.nsp", "l.nsz")] {
            v.set_times(p(rel), None, Some(t)).unwrap();
            let link = fs::symlink_metadata(dir.join(link)).unwrap();
            assert_eq!(link.modified().unwrap(), t, "{rel}");
        }
        assert_eq!(state(), before);
        assert_eq!(v.lookup(p("l.nsp")).unwrap().mtime(), container);
        assert_eq!(fs::read(&secret).unwrap(), b"secret");
        assert!(matches!(v.create(p("dead"), 0o644), Err(FsError::Exists)));
        assert!(matches!(v.mkdir(p("dead"), 0o755), Err(FsError::Exists)));

        // A delete removes the link itself, also a dangling one, and also
        // when the link is the source of a virtual file.
        assert!(matches!(v.rmdir(p("dlink")), Err(FsError::NotDir)));
        for link in ["dlink", "flink", "dead", "x.nsp"] {
            assert_eq!(v.unlink(p(link)).unwrap(), None, "{link}");
        }
        assert_eq!(v.unlink(p("l.nsp")).unwrap(), Some(p("l.nsz").into()));
        // x.nsp is now the virtual file of x.nsz.
        assert_eq!(listing(&v, ""), ["x.nsp", "x.nsz"]);
        assert!(out.join("c.nsz").is_file());
        assert!(out.join("sub/data.bin").is_file());
    }

    /// Deleting the real file that hides a virtual one leaves the name in
    /// the listing. A second delete must not take the source with it.
    #[test]
    fn shadow_delete() {
        let dir = scratch("shadow");
        fs::write(dir.join("g.nsz"), pfs0()).unwrap();
        fs::write(dir.join("g.nsp"), b"real").unwrap();
        let v = Vfs::new(
            dir.clone(),
            Options {
                rw: true,
                hide_sources: false,
            },
        );
        let p = Path::new;
        assert_eq!(v.unlink(p("g.nsp")).unwrap(), None);
        assert_eq!(listing(&v, ""), ["g.nsp", "g.nsz"]);
        assert!(matches!(v.unlink(p("g.nsp")), Err(FsError::Denied)));
        assert!(dir.join("g.nsz").is_file());
        // Later it is a delete like any other. Skipped when the clock
        // cannot go back that far.
        let Some(old) = Instant::now().checked_sub(UNSHADOW) else {
            return;
        };
        lock(&v.unshadowed).values_mut().for_each(|t| *t = old);
        assert_eq!(v.unlink(p("g.nsp")).unwrap(), Some(p("g.nsz").into()));
        assert!(!dir.join("g.nsz").exists());
    }

    /// Renaming the real file away, as moving it to a trash does, reveals
    /// the virtual one the same way. Neither a delete nor a rename of that
    /// one may take the source with it.
    #[test]
    fn shadow_rename() {
        let dir = scratch("shadow-rename");
        fs::create_dir(dir.join("trash")).unwrap();
        fs::write(dir.join("g.nsz"), pfs0()).unwrap();
        fs::write(dir.join("g.nsp"), b"real").unwrap();
        let v = Vfs::new(
            dir.clone(),
            Options {
                rw: true,
                hide_sources: false,
            },
        );
        let p = Path::new;
        assert_eq!(v.rename(p("g.nsp"), p("trash/g.nsp"), true).unwrap(), None);
        assert_eq!(listing(&v, ""), ["g.nsp", "g.nsz", "trash"]);
        assert!(matches!(
            v.rename(p("g.nsp"), p("trash/h.nsp"), true),
            Err(FsError::Denied)
        ));
        assert!(matches!(v.unlink(p("g.nsp")), Err(FsError::Denied)));
        assert!(dir.join("g.nsz").is_file());
        let Some(old) = Instant::now().checked_sub(UNSHADOW) else {
            return;
        };
        lock(&v.unshadowed).values_mut().for_each(|t| *t = old);
        v.rename(p("g.nsp"), p("trash/h.nsp"), true).unwrap();
        assert!(dir.join("trash/h.nsz").is_file());
    }

    /// Only the permission bits, and with a chmod the sticky bit, go from
    /// the mount to the source. A chmod leaves the set-ID bits of the source
    /// as they are.
    #[cfg(unix)]
    #[test]
    fn mode_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("modes");
        let v = Vfs::new(
            dir.clone(),
            Options {
                rw: true,
                hide_sources: false,
            },
        );
        let p = Path::new;
        let mode = |name: &str| fs::metadata(dir.join(name)).unwrap().permissions().mode() & 0o7777;
        let chmod = |name: &str, m| v.set_permissions(p(name), fs::Permissions::from_mode(m));
        // The scratch directory may hand its set-group-ID bit down.
        let inherited = mode("") & 0o2000;

        // Owner bits only, which the umask of the test run leaves alone.
        drop(v.create(p("f"), 0o6700).unwrap());
        assert_eq!(mode("f"), 0o700);
        chmod("f", 0o6711).unwrap();
        assert_eq!(mode("f"), 0o711);

        v.mkdir(p("d"), 0o7700).unwrap();
        assert_eq!(mode("d"), 0o700 | inherited);
        chmod("d", 0o755).unwrap();
        assert_eq!(mode("d"), 0o755 | inherited);
        // A set-group-ID directory of the source keeps the bit, which the
        // mount does not show and a chmod through it does not name.
        fs::set_permissions(dir.join("d"), fs::Permissions::from_mode(0o2775)).unwrap();
        chmod("d", 0o1750).unwrap();
        assert_eq!(mode("d"), 0o3750);
    }

    /// The images of a large directory are not all kept built: the sizes
    /// are, and an image that was let go is built again when opened.
    #[test]
    fn image_cache_is_bounded() {
        let dir = scratch("bounded");
        let count = MAX_IMAGES + 5;
        for i in 0..count {
            fs::write(dir.join(format!("g{i}.nsz")), pfs0()).unwrap();
        }
        let v = Vfs::new(dir.clone(), Options::default());
        assert_eq!(listing(&v, "").len(), 2 * count);
        assert_eq!(v.cache().containers.len(), count);
        assert_eq!(v.cache().images.len(), MAX_IMAGES);
        // Every one opens and reads, cached or not, and the limit holds.
        for i in 0..count {
            assert_eq!(read_all(&v, &format!("g{i}.nsp")), pfs0(), "g{i}");
        }
        assert_eq!(v.cache().images.len(), MAX_IMAGES);
        // An open file keeps its image while others take its place.
        let rel = Path::new("g0.nsp");
        let h = v.open(rel, v.lookup(rel).unwrap(), false, false).unwrap();
        for i in 1..count {
            read_all(&v, &format!("g{i}.nsp"));
        }
        let mut buf = [0u8; 4];
        assert_eq!(h.read(0, &mut buf).unwrap(), 4);
        assert_eq!(&buf, b"PFS0");
        // A source that is gone takes its container and its image along.
        // Not on Windows, where a deleted file may keep its name while the
        // cached image has it open.
        if cfg!(windows) {
            return;
        }
        for i in 0..count {
            fs::remove_file(dir.join(format!("g{i}.nsz"))).unwrap();
        }
        assert!(listing(&v, "").is_empty());
        assert!(v.cache().containers.is_empty());
        assert!(v.cache().images.is_empty());
    }

    /// A source rewritten in place with the same size and the old mtime is
    /// still seen as changed.
    #[cfg(unix)]
    #[test]
    fn changed_in_place() {
        let dir = scratch("inplace");
        let src = dir.join("g.nsz");
        fs::write(&src, pfs0()).unwrap();
        let before = fs::metadata(&src).unwrap();
        let mtime = before.modified().unwrap();
        let v = Vfs::new(dir, Options::default());
        assert_eq!(read_all(&v, "g.nsp"), pfs0());
        // Past one tick of the clock that stamps files.
        thread::sleep(Duration::from_millis(50));
        let mut other = pfs0();
        let end = other.len();
        other[end - 5..].copy_from_slice(b"WORLD");
        fs::write(&src, &other).unwrap();
        set_path_times(&src, None, Some(mtime)).unwrap();
        let after = fs::metadata(&src).unwrap();
        assert_eq!(after.modified().unwrap(), mtime);
        if Stamp::of(&after) == Stamp::of(&before) {
            eprintln!("the file system keeps no finer ctime, skipped");
            return;
        }
        assert_eq!(read_all(&v, "g.nsp"), other);
    }

    /// Two names of one file share one container, which goes away with the
    /// last name.
    #[cfg(unix)]
    #[test]
    fn aliases_share_container() {
        let dir = scratch("aliases");
        fs::write(dir.join("a.nsz"), b"junk").unwrap();
        fs::hard_link(dir.join("a.nsz"), dir.join("B.nsz")).unwrap();
        let v = Vfs::new(dir.clone(), Options::default());
        v.read_dir(Path::new("")).unwrap();
        assert!(v.lookup(Path::new("B.nsp")).is_err());
        assert_eq!(v.cache().containers.len(), 1);
        fs::remove_file(dir.join("a.nsz")).unwrap();
        v.read_dir(Path::new("")).unwrap();
        assert_eq!(v.cache().containers.len(), 1);
        fs::remove_file(dir.join("B.nsz")).unwrap();
        v.read_dir(Path::new("")).unwrap();
        assert!(v.cache().containers.is_empty());
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
        let v = Vfs::new(dir.clone(), Options::default());
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
        assert_eq!(v.cache().containers.len(), 10);
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
        let v = Vfs::new(dir, Options::default());
        assert!(v.lookup(Path::new("p.nsp")).is_err());
        let c = Arc::clone(v.cache().containers.values().next().unwrap());
        assert!(c.retry_at.get().is_some());
        // Within the delay the failed container is reused, not rebuilt.
        assert!(v.lookup(Path::new("p.nsp")).is_err());
        assert!(Arc::ptr_eq(
            v.cache().containers.values().next().unwrap(),
            &c
        ));
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
        let listed: HashSet<OsString> = Vfs::new(dir.into(), Options::default())
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

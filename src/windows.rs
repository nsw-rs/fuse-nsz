// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! WinFsp backend for Windows. WinFsp passes paths like `\dir\file`, which
//! map directly onto the core.

use crate::vfs::{self, FsError, Handle, Node, Options, Vfs, lock, log};
use std::ffi::{OsString, c_void};
use std::io;
use std::ops::Deref;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};
use winfsp_wrs::{
    CleanupFlags, CloseHandle, CreateFileInfo, CreateOptions, DirInfo, ERROR_DIR_NOT_EMPTY,
    ERROR_DISK_FULL, ERROR_HANDLE_DISK_FULL, ERROR_SHARING_VIOLATION, FileAccessRights,
    FileAttributes, FileContextKind, FileContextMode, FileInfo, FileSystem, FileSystemInterface,
    HANDLE, LocalFree, NTSTATUS, PSecurityDescriptor, Params, STATUS_ACCESS_DENIED,
    STATUS_DIRECTORY_NOT_EMPTY, STATUS_DISK_FULL, STATUS_END_OF_FILE, STATUS_FILE_IS_A_DIRECTORY,
    STATUS_IO_DEVICE_ERROR, STATUS_MEDIA_WRITE_PROTECTED, STATUS_NOT_A_DIRECTORY,
    STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SHARING_VIOLATION,
    SecurityDescriptor, U16CStr, U16CString, U16Str, VolumeInfo, WriteMode, u16cstr,
};

/// Read and execute for everyone, on a read-only volume.
const SDDL_RO: &U16CStr = u16cstr!("O:BAG:BAD:P(A;;FRFX;;;WD)");
/// A virtual image on a read-write volume: read and execute, plus delete
/// and write attributes so it can be renamed, deleted and touched. Without
/// write data, an open asking for the most access allowed still gets a
/// read-only handle.
const IMAGE_ACCESS: &str = "0x1301a9";

/// The descriptor of a read-write volume. Every request is carried out with
/// the rights of the user who mounted, whatever the permissions of the
/// source say, so only that user, the system and the administrators get
/// `access`. Everyone else reads, as on a read-only volume.
fn sddl_rw(user: &str, access: &str) -> String {
    format!("O:BAG:BAD:P(A;;{access};;;{user})(A;;{access};;;SY)(A;;{access};;;BA)(A;;FRFX;;;WD)")
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetDiskFreeSpaceExW(
        dir: *const u16,
        free_to_caller: *mut u64,
        total: *mut u64,
        free: *mut u64,
    ) -> i32;
    fn GetCurrentProcess() -> HANDLE;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: HANDLE, access: u32, token: *mut HANDLE) -> i32;
    fn GetTokenInformation(
        token: HANDLE,
        class: u32,
        info: *mut c_void,
        len: u32,
        needed: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *const c_void, text: *mut *mut u16) -> i32;
}

/// The SID of the user this process runs as, in the text form SDDL takes.
fn user_sid() -> Result<String, String> {
    const TOKEN_QUERY: u32 = 8;
    /// The `TokenUser` information class.
    const TOKEN_USER: u32 = 1;
    let failed = |what: &str| format!("{what}: {}", io::Error::last_os_error());
    let mut token: HANDLE = 0;
    // SAFETY: the pseudo handle of this process needs no close, and `token`
    // is a valid place for the result.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(failed("OpenProcessToken"));
    }
    // A TOKEN_USER is a pointer and a flags word, followed by the SID the
    // pointer leads to, which is at most 68 bytes. The u64 items give the
    // alignment the pointer needs.
    let mut info = [0u64; 16];
    let mut needed = 0;
    // SAFETY: `info` is writable for the length given.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TOKEN_USER,
            info.as_mut_ptr().cast(),
            size_of_val(&info) as u32,
            &mut needed,
        )
    };
    let r = if ok == 0 {
        Err(failed("GetTokenInformation"))
    } else {
        Ok(())
    };
    // SAFETY: `token` was opened above and is not used after this.
    unsafe { CloseHandle(token) };
    r?;
    // SAFETY: the call filled `info` with a TOKEN_USER, whose first field
    // is the pointer to the SID.
    let sid = unsafe { info.as_ptr().cast::<*const c_void>().read() };
    let mut text = ptr::null_mut();
    // SAFETY: `sid` is a valid SID inside `info`, and `text` a valid place
    // for the result.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(failed("ConvertSidToStringSidW"));
    }
    // SAFETY: on success `text` is a NUL terminated string that the caller
    // frees with LocalFree.
    let s = unsafe { U16CStr::from_ptr_str(text) }.to_string_lossy();
    // SAFETY: allocated by the call above and not used after this.
    unsafe { LocalFree(text.cast()) };
    Ok(s)
}

/// Win32 epoch (1601) to Unix epoch, in 100 ns units.
const EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;

fn status(e: FsError) -> NTSTATUS {
    match e {
        FsError::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        FsError::ReadOnly => STATUS_MEDIA_WRITE_PROTECTED,
        FsError::Denied => STATUS_ACCESS_DENIED,
        FsError::Exists => STATUS_OBJECT_NAME_COLLISION,
        FsError::IsDir => STATUS_FILE_IS_A_DIRECTORY,
        FsError::NotDir => STATUS_NOT_A_DIRECTORY,
        FsError::Access => STATUS_ACCESS_DENIED,
        FsError::Io(e) => match e.raw_os_error().and_then(|c| u32::try_from(c).ok()) {
            Some(ERROR_DIR_NOT_EMPTY) => STATUS_DIRECTORY_NOT_EMPTY,
            Some(ERROR_SHARING_VIOLATION) => STATUS_SHARING_VIOLATION,
            Some(ERROR_DISK_FULL | ERROR_HANDLE_DISK_FULL) => STATUS_DISK_FULL,
            // The table of WinFsp for the rest: as a device error, which
            // clients show as a hardware fault, they would all look alike.
            // SAFETY: a lookup in the WinFsp DLL, which `mount` loads
            // before any request is served.
            Some(code) => unsafe { winfsp_wrs_sys::FspNtStatusFromWin32(code) },
            // Not from the OS: an image that cannot be decoded.
            None => STATUS_IO_DEVICE_ERROR,
        },
    }
}

/// Core path of a WinFsp file name: `\a\b` -> `a\b`, `\` -> ``. Kept as
/// UTF-16, so names with unpaired surrogates still resolve.
fn rel(name: &U16CStr) -> PathBuf {
    let s = name.as_slice();
    let start = s.iter().take_while(|&&c| c == u16::from(b'\\')).count();
    PathBuf::from(OsString::from_wide(&s[start..]))
}

fn filetime(t: SystemTime) -> u64 {
    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    (d.as_nanos() / 100) as u64 + EPOCH_AS_FILETIME
}

/// A FILETIME as a time to set; 0 and all ones mean "leave as is".
fn systime(ft: u64) -> Option<SystemTime> {
    if ft == 0 || ft == u64::MAX {
        return None;
    }
    let d = |n: u64| Duration::from_nanos(n.saturating_mul(100));
    match ft.checked_sub(EPOCH_AS_FILETIME) {
        Some(n) => SystemTime::UNIX_EPOCH.checked_add(d(n)),
        None => SystemTime::UNIX_EPOCH.checked_sub(d(EPOCH_AS_FILETIME - ft)),
    }
}

/// Info of `node`. In rw mode only a read-only source shows the read-only
/// attribute: with it, Windows refuses to rename or delete the file.
fn file_info(node: &Node, rw: bool) -> FileInfo {
    let mut fi = FileInfo::default();
    let size = node.size();
    let attrs = if node.is_dir() {
        FileAttributes::DIRECTORY
    } else if !rw || node.meta.permissions().readonly() {
        FileAttributes::READONLY
    } else {
        FileAttributes::NORMAL
    };
    let t = filetime(node.mtime());
    fi.set_file_attributes(attrs)
        .set_file_size(size)
        .set_allocation_size(size.div_ceil(4096) * 4096)
        .set_time(t)
        .set_hard_links(1);
    fi
}

/// An open file or directory.
struct Ctx {
    /// Changed by a rename.
    path: Mutex<PathBuf>,
    /// Read again after every change.
    info: Mutex<FileInfo>,
    /// `None` for a directory.
    handle: Option<Handle>,
    /// Directory listing, sorted by name, taken on the first read.
    listing: OnceLock<Vec<(U16CString, FileInfo)>>,
}

impl Ctx {
    fn new(path: PathBuf, info: FileInfo, handle: Option<Handle>) -> Arc<Ctx> {
        Arc::new(Ctx {
            path: Mutex::new(path),
            info: Mutex::new(info),
            handle,
            listing: OnceLock::new(),
        })
    }

    fn path(&self) -> PathBuf {
        lock(&self.path).clone()
    }

    fn file(&self) -> Result<&Handle, NTSTATUS> {
        self.handle.as_ref().ok_or(STATUS_FILE_IS_A_DIRECTORY)
    }
}

/// The file context WinFsp hands to a callback. It has none for a flush of
/// the whole volume, which a plain `Arc` context would take for a file and
/// crash on.
struct Open(Option<Arc<Ctx>>);

impl FileContextKind for Open {
    const MODE: FileContextMode = FileContextMode::Descriptor;

    unsafe fn write(self, out: *mut *mut c_void) {
        let raw = self.0.map_or(ptr::null(), Arc::into_raw);
        // SAFETY: the caller gives a valid place for the context.
        unsafe { out.write(raw.cast_mut().cast()) }
    }

    unsafe fn access(raw: *mut c_void) -> Self {
        if raw.is_null() {
            return Open(None);
        }
        // SAFETY: a context that is not null came from `write`, and WinFsp
        // keeps it until the close. The count taken here is the one this
        // value gives back when dropped.
        unsafe {
            Arc::increment_strong_count(raw.cast_const().cast::<Ctx>());
            Self::access_for_close(raw)
        }
    }

    unsafe fn access_for_close(raw: *mut c_void) -> Self {
        // SAFETY: as in `access`. This takes over the count `write` left
        // with WinFsp.
        Open(Some(unsafe {
            Arc::from_raw(raw.cast_const().cast::<Ctx>())
        }))
    }
}

impl Deref for Open {
    type Target = Ctx;

    /// Only a flush comes without a context, and it checks for that.
    fn deref(&self) -> &Ctx {
        self.0.as_deref().expect("a file context")
    }
}

struct NszFs {
    vfs: Vfs,
    security: SecurityDescriptor,
    /// For virtual images in rw mode.
    image_security: SecurityDescriptor,
}

impl NszFs {
    fn security(&self, image: bool) -> PSecurityDescriptor {
        if image && self.vfs.rw() {
            self.image_security.as_ptr()
        } else {
            self.security.as_ptr()
        }
    }

    fn info(&self, node: &Node) -> FileInfo {
        file_info(node, self.vfs.rw())
    }

    /// Info of `ctx` read again after a change.
    fn refresh(&self, ctx: &Ctx) -> Result<FileInfo, NTSTATUS> {
        let node = match &ctx.handle {
            Some(Handle::File(f)) => Node {
                meta: f.metadata().map_err(|e| status(e.into()))?,
                image_len: None,
            },
            _ => self.vfs.lookup(&ctx.path()).map_err(status)?,
        };
        let info = self.info(&node);
        *lock(&ctx.info) = info;
        Ok(info)
    }

    fn listing(&self, ctx: &Ctx) -> Result<Vec<(U16CString, FileInfo)>, NTSTATUS> {
        let path = ctx.path();
        let entries = self.vfs.read_dir(&path).map_err(status)?;
        let mut out = Vec::with_capacity(entries.len() + 2);
        if !path.as_os_str().is_empty() {
            let info = *lock(&ctx.info);
            for dot in [".", ".."] {
                out.push((U16CString::from_str_truncate(dot), info));
            }
        }
        for e in entries {
            let Some(node) = &e.node else {
                continue;
            };
            let Ok(name) = U16CString::from_os_str(&e.name) else {
                continue;
            };
            out.push((name, self.info(node)));
        }
        out.sort_by(|a, b| a.0.as_slice().cmp(b.0.as_slice()));
        Ok(out)
    }
}

impl FileSystemInterface for NszFs {
    type FileContext = Open;

    const GET_VOLUME_INFO_DEFINED: bool = true;
    const GET_SECURITY_BY_NAME_DEFINED: bool = true;
    // WinFsp fails every open unless Create and Overwrite exist too.
    const CREATE_DEFINED: bool = true;
    const OPEN_DEFINED: bool = true;
    const OVERWRITE_DEFINED: bool = true;
    const CLOSE_DEFINED: bool = true;
    const READ_DEFINED: bool = true;
    const GET_FILE_INFO_DEFINED: bool = true;
    const GET_SECURITY_DEFINED: bool = true;
    const READ_DIRECTORY_DEFINED: bool = true;
    const CLEANUP_DEFINED: bool = true;
    const WRITE_DEFINED: bool = true;
    const FLUSH_DEFINED: bool = true;
    const SET_BASIC_INFO_DEFINED: bool = true;
    const SET_FILE_SIZE_DEFINED: bool = true;
    const CAN_DELETE_DEFINED: bool = true;
    const RENAME_DEFINED: bool = true;

    /// The source volume's numbers: Windows refuses to copy onto a volume
    /// that reports no free space.
    fn get_volume_info(&self) -> Result<VolumeInfo, NTSTATUS> {
        let mut root: Vec<u16> = self.vfs.root().as_os_str().encode_wide().collect();
        // A UNC path (a source on a network share) must end with a
        // backslash.
        if root.last() != Some(&u16::from(b'\\')) {
            root.push(u16::from(b'\\'));
        }
        root.push(0);
        let (mut avail, mut total, mut free) = (0, 0, 0);
        // SAFETY: `root` is NUL terminated and the outputs are valid u64s.
        if unsafe { GetDiskFreeSpaceExW(root.as_ptr(), &mut avail, &mut total, &mut free) } == 0 {
            (avail, total) = (0, 0);
        }
        VolumeInfo::new(total, avail, U16Str::from_slice(&[])).map_err(|_| STATUS_IO_DEVICE_ERROR)
    }

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _find_reparse_point: impl Fn() -> Option<FileAttributes>,
    ) -> Result<(FileAttributes, PSecurityDescriptor, bool), NTSTATUS> {
        let node = self.vfs.lookup(&rel(file_name)).map_err(status)?;
        Ok((
            self.info(&node).file_attributes(),
            self.security(node.is_image()),
            false,
        ))
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_file_info: CreateFileInfo,
        _security_descriptor: SecurityDescriptor,
    ) -> Result<(Self::FileContext, FileInfo), NTSTATUS> {
        let path = rel(file_name);
        let (node, handle) = if create_file_info
            .create_options
            .is(CreateOptions::FILE_DIRECTORY_FILE)
        {
            (self.vfs.mkdir(&path, 0o777).map_err(status)?, None)
        } else {
            let (node, h) = self.vfs.create(&path, 0o666).map_err(status)?;
            (node, Some(h))
        };
        let info = self.info(&node);
        Ok((Open(Some(Ctx::new(path, info, handle))), info))
    }

    /// Truncate on open (supersede or overwrite dispositions).
    fn overwrite(
        &self,
        ctx: Self::FileContext,
        _file_attributes: FileAttributes,
        _replace_file_attributes: bool,
        _allocation_size: u64,
    ) -> Result<FileInfo, NTSTATUS> {
        if !self.vfs.rw() {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        ctx.file()?.set_len(0).map_err(status)?;
        self.refresh(&ctx)
    }

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: CreateOptions,
        granted_access: FileAccessRights,
    ) -> Result<(Self::FileContext, FileInfo), NTSTATUS> {
        let path = rel(file_name);
        let node = self.vfs.lookup(&path).map_err(status)?;
        let info = self.info(&node);
        let handle = if node.is_dir() {
            if create_options.is(CreateOptions::FILE_NON_DIRECTORY_FILE) {
                return Err(STATUS_FILE_IS_A_DIRECTORY);
            }
            None
        } else {
            if create_options.is(CreateOptions::FILE_DIRECTORY_FILE) {
                return Err(STATUS_NOT_A_DIRECTORY);
            }
            let write = granted_access.is(FileAccessRights::FILE_WRITE_DATA)
                || granted_access.is(FileAccessRights::FILE_APPEND_DATA);
            let image = node.is_image();
            let r = match self.vfs.open(&path, node.clone(), write, false) {
                // The security descriptor grants write data, so an open
                // asking for MAXIMUM_ALLOWED gets it even on a source the
                // user can only read (read-only attribute or share). Open
                // it read-only then: a write through it fails instead.
                Err(FsError::Access) if write && !image => self.vfs.open(&path, node, false, false),
                r => r,
            };
            Some(r.map_err(status)?)
        };
        Ok((Open(Some(Ctx::new(path, info, handle))), info))
    }

    /// The last handle of a file is closed: delete it if asked to.
    fn cleanup(&self, ctx: Self::FileContext, file_name: Option<&U16CStr>, flags: CleanupFlags) {
        if !flags.is(CleanupFlags::DELETE) {
            return;
        }
        // The name WinFsp sends with a delete is the current one. The path
        // kept in the context misses a rename made through another handle.
        let path = file_name.map_or_else(|| ctx.path(), rel);
        let r = if ctx.handle.is_some() {
            self.vfs.unlink(&path).map(drop)
        } else {
            self.vfs.rmdir(&path)
        };
        if let Err(e) = r {
            log!("{}: delete: {e:?}", path.display());
        }
    }

    fn close(&self, _file_context: Self::FileContext) {}

    fn write(
        &self,
        ctx: Self::FileContext,
        buffer: &[u8],
        mode: WriteMode,
    ) -> Result<(usize, FileInfo), NTSTATUS> {
        let h = ctx.file()?;
        let (off, len) = match mode {
            WriteMode::Normal { offset } => (offset, buffer.len()),
            WriteMode::ConstrainedIO { offset } => {
                // Never past the end of file.
                let left = self.refresh(&ctx)?.file_size().saturating_sub(offset);
                let len = usize::try_from(left).map_or(buffer.len(), |l| l.min(buffer.len()));
                (offset, len)
            }
            WriteMode::WriteToEOF => (self.refresh(&ctx)?.file_size(), buffer.len()),
        };
        h.write(off, &buffer[..len]).map_err(status)?;
        Ok((len, self.refresh(&ctx)?))
    }

    fn flush(&self, ctx: Self::FileContext) -> Result<FileInfo, NTSTATUS> {
        // The whole volume: nothing is buffered here, every write went
        // straight to the source.
        let Some(ctx) = ctx.0 else {
            return Ok(FileInfo::default());
        };
        if let Some(h) = &ctx.handle {
            h.sync().map_err(status)?;
        }
        self.refresh(&ctx)
    }

    fn read(
        &self,
        ctx: Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> Result<usize, NTSTATUS> {
        let Some(h) = &ctx.handle else {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        };
        match h.read(offset, buffer) {
            Ok(0) if !buffer.is_empty() => Err(STATUS_END_OF_FILE),
            Ok(n) => Ok(n),
            Err(e) => {
                vfs::log_read_error(&ctx.path(), buffer.len(), offset, &e);
                Err(STATUS_IO_DEVICE_ERROR)
            }
        }
    }

    fn get_file_info(&self, ctx: Self::FileContext) -> Result<FileInfo, NTSTATUS> {
        Ok(*lock(&ctx.info))
    }

    /// Times and the read-only attribute. For a virtual image they apply
    /// to its source.
    fn set_basic_info(
        &self,
        ctx: Self::FileContext,
        file_attributes: FileAttributes,
        _creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        _change_time: u64,
    ) -> Result<FileInfo, NTSTATUS> {
        let path = ctx.path();
        if file_attributes != FileAttributes::INVALID {
            let node = self.vfs.lookup(&path).map_err(status)?;
            let ro = file_attributes.is(FileAttributes::READONLY);
            let mut perm = node.meta.permissions();
            if !node.is_dir() && perm.readonly() != ro {
                perm.set_readonly(ro);
                self.vfs.set_permissions(&path, perm).map_err(status)?;
            }
        }
        let (atime, mtime) = (systime(last_access_time), systime(last_write_time));
        if atime.is_some() || mtime.is_some() {
            self.vfs.set_times(&path, atime, mtime).map_err(status)?;
        }
        self.refresh(&ctx)
    }

    fn set_file_size(
        &self,
        ctx: Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
    ) -> Result<FileInfo, NTSTATUS> {
        let h = ctx.file()?;
        // Allocation is not tracked: only a size below the file's end
        // truncates it.
        if !set_allocation_size || new_size < lock(&ctx.info).file_size() {
            h.set_len(new_size).map_err(status)?;
        }
        self.refresh(&ctx)
    }

    fn can_delete(&self, ctx: Self::FileContext, file_name: &U16CStr) -> Result<(), NTSTATUS> {
        if !self.vfs.rw() {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        // The current name, as in `cleanup`.
        let path = rel(file_name);
        if ctx.handle.is_none() && !self.vfs.is_empty_dir(&path).map_err(status)? {
            return Err(STATUS_DIRECTORY_NOT_EMPTY);
        }
        if matches!(ctx.handle, Some(Handle::Image(_))) {
            self.vfs.deletable(&path).map_err(status)?;
        }
        Ok(())
    }

    fn rename(
        &self,
        ctx: Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> Result<(), NTSTATUS> {
        let to = rel(new_file_name);
        self.vfs
            .rename(&rel(file_name), &to, !replace_if_exists)
            .map_err(status)?;
        *lock(&ctx.path) = to;
        Ok(())
    }

    fn get_security(&self, ctx: Self::FileContext) -> Result<PSecurityDescriptor, NTSTATUS> {
        Ok(self.security(matches!(ctx.handle, Some(Handle::Image(_)))))
    }

    fn read_directory(
        &self,
        ctx: Self::FileContext,
        marker: Option<&U16CStr>,
        mut add_dir_info: impl FnMut(DirInfo) -> bool,
    ) -> Result<(), NTSTATUS> {
        if ctx.handle.is_some() {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        let list = match ctx.listing.get() {
            Some(l) => l,
            None => {
                let _ = ctx.listing.set(self.listing(&ctx)?);
                ctx.listing.get().expect("listing was just set")
            }
        };
        // Entries are sorted, so the ones after the marker follow it.
        let start = marker.map_or(0, |m| {
            list.partition_point(|(n, _)| n.as_slice() <= m.as_slice())
        });
        for (name, info) in &list[start..] {
            if !add_dir_info(DirInfo::new(*info, name)) {
                break;
            }
        }
        Ok(())
    }
}

/// Mount `src` on `mountpoint` (a drive letter like `X:` or a directory
/// that does not exist yet) and serve it until the process is stopped.
pub fn mount(src: PathBuf, mountpoint: &Path, args: &[String]) -> Result<(), String> {
    let mut opts = Options::default();
    for o in vfs::mount_options(args)? {
        if !opts.parse_flag(o) {
            return Err(format!("unknown option {o}"));
        }
    }
    winfsp_wrs::init().map_err(|e| e.to_string())?;
    let user = user_sid()?;
    let sddl = |access| U16CString::from_str_truncate(sddl_rw(&user, access));
    let security = if opts.rw {
        SecurityDescriptor::from_wstr(&sddl("FA"))?
    } else {
        SecurityDescriptor::from_wstr(SDDL_RO)?
    };
    let image_security = SecurityDescriptor::from_wstr(&sddl(IMAGE_ACCESS))?;
    let mut params = Params::default();
    let vp = &mut params.volume_params;
    vp.set_sector_size(4096)
        .set_sectors_per_allocation_unit(1)
        .set_max_component_length(255)
        .set_case_sensitive_search(false)
        .set_case_preserved_names(true)
        .set_unicode_on_disk(true)
        .set_persistent_acls(true)
        .set_read_only_volume(!opts.rw)
        .set_file_info_timeout(1000);
    let _ = vp.set_file_system_name(u16cstr!("fuse-nsz"));
    let mp = U16CString::from_os_str(mountpoint)
        .map_err(|_| format!("{}: invalid mountpoint", mountpoint.display()))?;
    let fs = NszFs {
        vfs: Vfs::new(src, opts),
        security,
        image_security,
    };
    let _host = FileSystem::start(params, Some(&mp), fs)
        .map_err(|s| format!("{}: cannot mount (NTSTATUS {s:#x})", mountpoint.display()))?;
    loop {
        std::thread::park();
    }
}

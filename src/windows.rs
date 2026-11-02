// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! WinFsp backend for Windows. WinFsp passes paths like `\dir\file`, which
//! map directly onto the core.

use crate::vfs::{FsError, Handle, Node, Vfs};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;
use winfsp_wrs::{
    CreateFileInfo, CreateOptions, DirInfo, FileAccessRights, FileAttributes, FileInfo, FileSystem,
    FileSystemInterface, NTSTATUS, PSecurityDescriptor, Params, STATUS_ACCESS_DENIED,
    STATUS_END_OF_FILE, STATUS_FILE_IS_A_DIRECTORY, STATUS_IO_DEVICE_ERROR,
    STATUS_MEDIA_WRITE_PROTECTED, STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_NOT_FOUND,
    SecurityDescriptor, U16CStr, U16CString, U16Str, VolumeInfo, u16cstr,
};

/// Read and execute for everyone. The volume is read-only anyway.
const SDDL: &U16CStr = u16cstr!("O:BAG:BAD:P(A;;FRFX;;;WD)");

/// Win32 epoch (1601) to Unix epoch, in 100 ns units.
const EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;

fn status(e: &FsError) -> NTSTATUS {
    match e {
        FsError::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        FsError::ReadOnly => STATUS_MEDIA_WRITE_PROTECTED,
        FsError::IsDir => STATUS_FILE_IS_A_DIRECTORY,
        FsError::NotDir => STATUS_NOT_A_DIRECTORY,
        FsError::Access => STATUS_ACCESS_DENIED,
        FsError::Io(_) => STATUS_IO_DEVICE_ERROR,
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

fn file_info(node: &Node) -> FileInfo {
    let mut fi = FileInfo::default();
    let size = node.size();
    let attrs = if node.is_dir() {
        FileAttributes::DIRECTORY
    } else {
        FileAttributes::READONLY
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
    path: PathBuf,
    info: FileInfo,
    /// `None` for a directory.
    handle: Option<Handle>,
    /// Directory listing, sorted by name, taken on the first read.
    listing: OnceLock<Vec<(U16CString, FileInfo)>>,
}

struct NszFs {
    vfs: Vfs,
    security: SecurityDescriptor,
}

impl NszFs {
    fn listing(&self, ctx: &Ctx) -> Result<Vec<(U16CString, FileInfo)>, NTSTATUS> {
        let entries = self.vfs.read_dir(&ctx.path).map_err(|e| status(&e))?;
        let mut out = Vec::with_capacity(entries.len() + 2);
        if !ctx.path.as_os_str().is_empty() {
            for dot in [".", ".."] {
                out.push((U16CString::from_str_truncate(dot), ctx.info));
            }
        }
        for e in entries {
            let Some(node) = &e.node else {
                continue;
            };
            let Ok(name) = U16CString::from_os_str(&e.name) else {
                continue;
            };
            out.push((name, file_info(node)));
        }
        out.sort_by(|a, b| a.0.as_slice().cmp(b.0.as_slice()));
        Ok(out)
    }
}

impl FileSystemInterface for NszFs {
    type FileContext = Arc<Ctx>;

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

    fn get_volume_info(&self) -> Result<VolumeInfo, NTSTATUS> {
        VolumeInfo::new(0, 0, U16Str::from_slice(&[])).map_err(|_| STATUS_IO_DEVICE_ERROR)
    }

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _find_reparse_point: impl Fn() -> Option<FileAttributes>,
    ) -> Result<(FileAttributes, PSecurityDescriptor, bool), NTSTATUS> {
        let node = self.vfs.lookup(&rel(file_name)).map_err(|e| status(&e))?;
        Ok((
            file_info(&node).file_attributes(),
            self.security.as_ptr(),
            false,
        ))
    }

    fn create(
        &self,
        _file_name: &U16CStr,
        _create_file_info: CreateFileInfo,
        _security_descriptor: SecurityDescriptor,
    ) -> Result<(Self::FileContext, FileInfo), NTSTATUS> {
        Err(STATUS_MEDIA_WRITE_PROTECTED)
    }

    fn overwrite(
        &self,
        _file_context: Self::FileContext,
        _file_attributes: FileAttributes,
        _replace_file_attributes: bool,
        _allocation_size: u64,
    ) -> Result<FileInfo, NTSTATUS> {
        Err(STATUS_MEDIA_WRITE_PROTECTED)
    }

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: CreateOptions,
        granted_access: FileAccessRights,
    ) -> Result<(Self::FileContext, FileInfo), NTSTATUS> {
        let path = rel(file_name);
        let node = self.vfs.lookup(&path).map_err(|e| status(&e))?;
        let info = file_info(&node);
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
            Some(self.vfs.open(&path, node, write).map_err(|e| status(&e))?)
        };
        let ctx = Ctx {
            path,
            info,
            handle,
            listing: OnceLock::new(),
        };
        Ok((Arc::new(ctx), info))
    }

    fn close(&self, _file_context: Self::FileContext) {}

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
                eprintln!(
                    "{}: read {}@{offset}: {e}",
                    ctx.path.display(),
                    buffer.len()
                );
                Err(STATUS_IO_DEVICE_ERROR)
            }
        }
    }

    fn get_file_info(&self, ctx: Self::FileContext) -> Result<FileInfo, NTSTATUS> {
        Ok(ctx.info)
    }

    fn get_security(&self, _ctx: Self::FileContext) -> Result<PSecurityDescriptor, NTSTATUS> {
        Ok(self.security.as_ptr())
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
    if let Some(a) = args.first() {
        return Err(format!("unknown argument {a}"));
    }
    winfsp_wrs::init().map_err(|e| e.to_string())?;
    let security = SecurityDescriptor::from_wstr(SDDL)?;
    let mut params = Params::default();
    let vp = &mut params.volume_params;
    vp.set_sector_size(4096)
        .set_sectors_per_allocation_unit(1)
        .set_max_component_length(255)
        .set_case_sensitive_search(false)
        .set_case_preserved_names(true)
        .set_unicode_on_disk(true)
        .set_persistent_acls(true)
        .set_read_only_volume(true)
        .set_file_info_timeout(1000);
    let _ = vp.set_file_system_name(u16cstr!("fuse-nsz"));
    let mp = U16CString::from_os_str(mountpoint)
        .map_err(|_| format!("{}: invalid mountpoint", mountpoint.display()))?;
    let fs = NszFs {
        vfs: Vfs::new(src),
        security,
    };
    let _host = FileSystem::start(params, Some(&mp), fs)
        .map_err(|s| format!("{}: cannot mount (NTSTATUS {s:#x})", mountpoint.display()))?;
    loop {
        std::thread::park();
    }
}

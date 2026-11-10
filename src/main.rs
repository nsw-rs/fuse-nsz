// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! fuse-nsz mirrors a directory and exposes every block compressed
//! `.nsz`/`.xcz` in it also as a virtual `.nsp`/`.xci`, decompressed on the
//! fly. The mount is read-only unless `-o rw` is given; `-o hide_sources`
//! leaves out the sources whose virtual files are shown.

#[cfg(unix)]
mod unix;
mod vfs;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as backend;
#[cfg(windows)]
use windows as backend;

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "<srcdir> <mountpoint> [-o option[,option...]]";

const HELP: &str = "\
Mirrors <srcdir> on <mountpoint> and shows every block compressed .nsz/.xcz
in it as a virtual .nsp/.xci too. Stays in the foreground until unmounted.

Options:
  ro             read-only mount (default)
  rw             pass changes through to <srcdir>
  hide_sources   leave out a .nsz/.xcz whose virtual file is shown
";

#[cfg(unix)]
const HELP_BACKEND: &str =
    "  allow_other    let other users in (needs user_allow_other in /etc/fuse.conf)
  allow_root     let root in
  auto_unmount   unmount when the process ends, with allow_other or allow_root
  fsname=NAME    the source shown by mount(8), default fuse-nsz
  subtype=NAME   the file system subtype shown by mount(8)
  noexec, noatime, sync, dirsync
                 the mount flags of these names

Any other option is handed to the FUSE mount as it is.
";

#[cfg(windows)]
const HELP_BACKEND: &str = "
<mountpoint> is a free drive letter (X:) or a directory that does not exist
yet.
";

/// `path` with its links resolved. One that does not exist yet (a
/// mountpoint on Windows) is resolved up to its parent.
fn resolved(path: &Path) -> io::Result<PathBuf> {
    match std::fs::canonicalize(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let abs = std::path::absolute(path)?;
            match (abs.parent(), abs.file_name()) {
                (Some(dir), Some(name)) => Ok(std::fs::canonicalize(dir)?.join(name)),
                _ => Ok(abs),
            }
        }
        r => r,
    }
}

fn main() -> ExitCode {
    // Paths may not be valid UTF-8, so take them as they are.
    let args: Vec<OsString> = std::env::args_os().collect();
    let prog = args.first().map(Path::new).and_then(Path::file_name);
    let prog = prog.map_or("fuse-nsz".into(), |p| p.to_string_lossy());
    // Not println: a closed pipe must not turn into a panic.
    let mut out = io::stdout();
    match args.get(1).and_then(|a| a.to_str()) {
        Some("-h" | "--help") => {
            let _ = write!(out, "usage: {prog} {USAGE}\n\n{HELP}{HELP_BACKEND}");
            return ExitCode::SUCCESS;
        }
        Some("-V" | "--version") => {
            let _ = writeln!(out, "fuse-nsz {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        _ => {}
    }
    if args.len() < 3 {
        eprintln!("usage: {prog} {USAGE}");
        return ExitCode::from(2);
    }
    let mut opts = Vec::with_capacity(args.len() - 3);
    for a in &args[3..] {
        match a.to_str() {
            Some(a) => opts.push(a.to_owned()),
            None => {
                eprintln!("{}: invalid argument", a.to_string_lossy());
                return ExitCode::from(2);
            }
        }
    }
    let mountpoint = Path::new(&args[2]);
    let src = match std::path::absolute(&args[1]) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    if !src.is_dir() {
        eprintln!("{}: not a directory", src.display());
        return ExitCode::from(1);
    }
    // With one inside the other, serving a request would mean asking the
    // kernel for a path that this process serves itself. A path that cannot
    // be resolved is left to the mount to report.
    let real = resolved(&src);
    if let (Ok(s), Ok(m)) = (&real, resolved(mountpoint))
        && (s.starts_with(&m) || m.starts_with(s))
    {
        eprintln!(
            "{}: the mountpoint and the source directory must not contain each other",
            mountpoint.display()
        );
        return ExitCode::from(1);
    }
    // The resolved form (`\\?\C:\...`) keeps Win32 from rewriting the names
    // under it: no trailing dot or space is dropped, and `NUL` or `COM1` is
    // a file name, not a device.
    #[cfg(windows)]
    let src = real.unwrap_or(src);
    if let Err(e) = backend::mount(src, mountpoint, &opts) {
        eprintln!("{e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

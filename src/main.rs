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
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    // Paths may not be valid UTF-8, so take them as they are.
    let args: Vec<OsString> = std::env::args_os().collect();
    if args.len() < 3 {
        let prog = args.first().map(Path::new).and_then(Path::file_name);
        let prog = prog.map_or("fuse-nsz".into(), |p| p.to_string_lossy());
        eprintln!("usage: {prog} <srcdir> <mountpoint> [-o rw,hide_sources,...]");
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
    if let Err(e) = backend::mount(src, Path::new(&args[2]), &opts) {
        eprintln!("{e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

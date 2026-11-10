// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runs the built binary. The tests that mount need FUSE, which build
//! sandboxes and most CI runners do not have, so they only run with
//! `FUSE_NSZ_MOUNT_TEST` set.

#![cfg(unix)]

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirEntryExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_fuse-nsz");

/// Longer than the time the kernel trusts the attributes of a file for.
const ATTR_TTL: Duration = Duration::from_millis(1200);

/// A PFS0 holding one plain file: an NSZ without NCZ, whose image is the
/// same bytes.
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

/// An empty source directory and mountpoint for the test `name`.
fn tree(name: &str) -> (PathBuf, PathBuf) {
    let top = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&top);
    let (src, mnt) = (top.join("src"), top.join("mnt"));
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&mnt).unwrap();
    (src, mnt)
}

fn fuse() -> bool {
    let set = std::env::var_os("FUSE_NSZ_MOUNT_TEST").is_some();
    if !set {
        eprintln!("FUSE_NSZ_MOUNT_TEST not set, skipped");
    }
    set
}

fn mounted(mnt: &Path) -> bool {
    match (fs::metadata(mnt), fs::metadata(mnt.parent().unwrap())) {
        (Ok(a), Ok(b)) => a.dev() != b.dev(),
        _ => false,
    }
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(Instant::now() < end, "timed out: {what}");
        sleep(Duration::from_millis(20));
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut n: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    n.sort();
    n
}

/// A running fuse-nsz. Dropped while still running (a failed test), it is
/// killed and the mount detached.
struct Mount {
    child: Child,
    mnt: PathBuf,
}

impl Mount {
    /// Mount `src` on `mnt` with `opts`, the log going to `stderr`.
    fn start(src: &Path, mnt: &Path, opts: &str, stderr: Stdio) -> Mount {
        let mut cmd = Command::new(BIN);
        cmd.args([src, mnt]).args(["-o", opts]).stderr(stderr);
        // A umask of its own, which must not show in what it creates.
        // SAFETY: umask is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                libc::umask(0o077);
                Ok(())
            })
        };
        let child = cmd.spawn().unwrap();
        let mut m = Mount {
            child,
            mnt: mnt.to_path_buf(),
        };
        wait_for("mount", || {
            assert!(m.child.try_wait().unwrap().is_none(), "fuse-nsz ended");
            mounted(mnt)
        });
        m
    }

    fn signal(&self, sig: libc::c_int) {
        // SAFETY: the child is not reaped yet, so the pid is its own.
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, sig) },
            0
        );
    }

    fn wait(&mut self) -> ExitStatus {
        wait_for("exit", || self.child.try_wait().unwrap().is_some());
        self.child.wait().unwrap()
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            return;
        }
        // A failed test: without its process the mount would stay behind,
        // dead, and be in the way of the next run.
        let _ = self.child.kill();
        let _ = self.child.wait();
        let unmount = if cfg!(target_os = "linux") {
            "fusermount3 -u -z"
        } else {
            "umount -f"
        };
        let mut args = unmount.split(' ');
        let _ = Command::new(args.next().unwrap())
            .args(args)
            .arg(&self.mnt)
            .stderr(Stdio::null())
            .status();
    }
}

#[test]
fn help_and_version() {
    for flag in ["--help", "-h"] {
        let out = Command::new(BIN).arg(flag).output().unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(out.status.success() && out.stderr.is_empty(), "{flag}");
        assert!(text.starts_with("usage: fuse-nsz <srcdir> <mountpoint>"));
        assert!(text.contains("hide_sources"));
    }
    for flag in ["--version", "-V"] {
        let out = Command::new(BIN).arg(flag).output().unwrap();
        assert!(out.status.success(), "{flag}");
        let want = format!("fuse-nsz {}\n", env!("CARGO_PKG_VERSION"));
        assert_eq!(String::from_utf8(out.stdout).unwrap(), want);
    }
    let out = Command::new(BIN).arg("only-one").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
}

/// Refused before anything is mounted, so this needs no FUSE.
#[test]
fn overlapping_mountpoint_is_refused() {
    let (src, _) = tree("overlap");
    let inside = src.join("sub/mnt");
    fs::create_dir_all(&inside).unwrap();
    // The same directory under another name.
    let alias = src.with_file_name("alias");
    symlink(&src, &alias).unwrap();
    for (s, m) in [
        (&src, &inside),
        (&inside, &src),
        (&src, &src),
        (&src, &alias),
        (&alias, &inside),
    ] {
        let out = Command::new(BIN).args([s, m]).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{s:?} on {m:?}: {err}");
        assert!(err.contains("must not contain each other"), "{err}");
    }
}

#[test]
fn mount_read_write() {
    if !fuse() {
        return;
    }
    let (src, mnt) = tree("rw");
    fs::write(src.join("g.nsz"), pfs0()).unwrap();
    fs::write(src.join("notes.txt"), b"hello").unwrap();
    symlink("notes.txt", src.join("link")).unwrap();
    let log = src.with_file_name("log");
    let stderr = File::create(&log).unwrap();
    let mut m = Mount::start(&src, &mnt, "rw", stderr.into());

    assert_eq!(names(&mnt), ["g.nsp", "g.nsz", "link", "notes.txt"]);
    assert_eq!(fs::read(mnt.join("g.nsp")).unwrap(), pfs0());
    assert_eq!(
        fs::read_link(mnt.join("link")).unwrap(),
        Path::new("notes.txt")
    );
    assert_eq!(fs::read(mnt.join("link")).unwrap(), b"hello");
    // Once an entry was looked up, a listing gives the number stat gives.
    for e in fs::read_dir(&mnt).unwrap() {
        let e = e.unwrap();
        assert_eq!(e.ino(), fs::symlink_metadata(e.path()).unwrap().ino());
    }

    // A file deleted while open is served through its handle.
    let path = mnt.join("tmp.bin");
    let mut f = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    f.write_all(b"abcdef").unwrap();
    fs::remove_file(&path).unwrap();
    sleep(ATTR_TTL);
    assert_eq!(f.metadata().unwrap().len(), 6);
    f.write_all(b"gh").unwrap();
    f.set_len(7).unwrap();
    let mut text = String::new();
    f.seek(SeekFrom::Start(0)).unwrap();
    f.read_to_string(&mut text).unwrap();
    assert_eq!(text, "abcdefg");
    // Its name is free again, and the handle does not follow the name.
    fs::write(&path, b"new").unwrap();
    sleep(ATTR_TTL);
    assert_eq!(f.metadata().unwrap().len(), 7);
    assert_eq!(fs::read(&path).unwrap(), b"new");
    drop(f);
    fs::remove_file(&path).unwrap();

    // No set-user-ID or set-group-ID bit reaches the source.
    let mode = |name: &str| fs::metadata(src.join(name)).unwrap().mode() & 0o7777;
    let setid = File::options()
        .write(true)
        .create_new(true)
        .mode(0o6700)
        .open(mnt.join("setid"));
    drop(setid.unwrap());
    assert_eq!(mode("setid"), 0o700);
    fs::set_permissions(mnt.join("setid"), fs::Permissions::from_mode(0o6750)).unwrap();
    assert_eq!(mode("setid"), 0o750);
    fs::remove_file(mnt.join("setid")).unwrap();

    // The umask that counts is the one of the caller, not the one of
    // fuse-nsz (077, see `Mount::start`).
    let sh = Command::new("sh")
        .args(["-c", r#"umask 002 && : > "$0/file" && mkdir "$0/dir""#])
        .arg(&mnt)
        .status()
        .unwrap();
    assert!(sh.success());
    assert_eq!(mode("file"), 0o664);
    assert_eq!(mode("dir"), 0o775);
    fs::remove_file(mnt.join("file")).unwrap();
    fs::remove_dir(mnt.join("dir")).unwrap();

    // A virtual file is renamed through its source, and keeps its kind.
    fs::rename(mnt.join("g.nsp"), mnt.join("h.nsp")).unwrap();
    assert_eq!(fs::read(src.join("h.nsz")).unwrap(), pfs0());
    assert_eq!(fs::read(mnt.join("h.nsp")).unwrap(), pfs0());
    let e = fs::rename(mnt.join("h.nsp"), mnt.join("h.xci")).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(names(&mnt), ["h.nsp", "h.nsz", "link", "notes.txt"]);

    m.signal(libc::SIGTERM);
    assert!(m.wait().success());
    assert!(!mounted(&mnt));
    assert_eq!(fs::read_to_string(&log).unwrap(), "");
}

/// A signal unmounts. A mount that is in use is detached and served until
/// its last user is gone, and a second signal does not wait for that.
#[cfg(target_os = "linux")]
#[test]
fn signals_with_a_busy_mount() {
    if !fuse() {
        return;
    }
    let (src, mnt) = tree("busy");
    fs::write(src.join("notes.txt"), b"hello").unwrap();
    let mut m = Mount::start(&src, &mnt, "ro", Stdio::inherit());
    let mut f = File::open(mnt.join("notes.txt")).unwrap();
    m.signal(libc::SIGTERM);
    wait_for("detach", || !mounted(&mnt));
    sleep(Duration::from_millis(300));
    assert!(m.child.try_wait().unwrap().is_none(), "ended while in use");
    let mut text = String::new();
    f.read_to_string(&mut text).unwrap();
    assert_eq!(text, "hello");
    m.signal(libc::SIGTERM);
    assert_eq!(m.wait().code(), Some(1));
}

/// Log lines that cannot be written do not take the mount down.
#[test]
fn survives_a_closed_stderr() {
    if !fuse() {
        return;
    }
    let (src, mnt) = tree("stderr");
    fs::write(src.join("bad.nsz"), b"junk").unwrap();
    let mut m = Mount::start(&src, &mnt, "ro", Stdio::piped());
    drop(m.child.stderr.take());
    for _ in 0..3 {
        // Each change makes the broken container be read, and logged, again.
        let f = File::options().append(true).open(src.join("bad.nsz"));
        f.unwrap().write_all(b"more").unwrap();
        assert_eq!(names(&mnt), ["bad.nsz"]);
    }
    m.signal(libc::SIGTERM);
    assert!(m.wait().success());
}

<!--
SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# fuse-nsz

A FUSE filesystem that mirrors a directory and shows every block
compressed `.nsz`/`.xcz` file in it as a plain `.nsp`/`.xci` too.
It is read-only unless mounted with `-o rw`.
The virtual files are decompressed on the fly, so you can keep only the
compressed copies on disk and still feed the uncompressed images to
tools that do not understand NSZ.

```
src/                         mnt/
  game.nsz          ->         game.nsz
                               game.nsp   (virtual)
  other.xcz         ->         other.xcz
                               other.xci  (virtual)
  notes.txt         ->         notes.txt
```

The NSZ format and the `nsz` tool that writes it are by nicoboss and
contributors. This tool only reads what `nsz` writes.

> [!IMPORTANT]
> This tool is designed to work with legal backup copies of your own
> games.

## Features

- Random access reads: only the zstd blocks covering the requested range
  are decompressed and re-encrypted. A small global LRU (16 blocks) keeps
  recently used blocks.
- No keys needed. NCZ files carry the AES-CTR key of each section, which
  is all that is needed to re-encrypt the NCA.
- Byte-exact originals: when the container ends with an `NSZKEEP1`
  trailer, the image is rebuilt from it and matches the source dump byte
  for byte, for both NSP and XCI.
- Everything else in the source directory is passed through unchanged.
- The size of every image is found on the first lookup or directory
  listing and cached until the source file changes (size, mtime, and on
  Linux and macOS ctime). At most 64 images are kept built at once, each
  with its source file open. Any other one is built again when it is
  opened.
- Linux and macOS through FUSE ([fuser](https://github.com/cberner/fuser)),
  Windows through [WinFsp](https://winfsp.dev/).

## Limitations

- Only block compressed NCZ files (`nsz -C -B`, the `NCZBLOCK` format)
  are exposed. Solid NCZ is one zstd stream with no random access; such
  containers are logged and skipped.
- Without an `NSZKEEP1` trailer:
  - a virtual `.nsp` matches the one written by `nsz -D` byte for byte;
  - a virtual `.xci` is not identical to the original dump. `nsz -C`
    drops the update, normal and logo partitions unless `--keep` is
    given, and either way the image is laid out again with new HFS0
    headers and padding. Every NCA inside still hashes to its name.
    Check integrity by NCA hash, not with `cmp`.
- If the source directory already holds `game.nsp` next to `game.nsz`,
  the real file wins and the virtual one is hidden. Mount a directory
  that contains only the compressed files to avoid surprises.
- A symbolic link in the source directory is shown as a link and is not
  followed. Whoever opens it resolves the target, starting from the
  mount, so a relative link that leaves the source directory usually
  points nowhere. A link to a `.nsz`/`.xcz` file still gets its virtual
  file. On Windows a link is listed as a file that cannot be opened.
- The mountpoint and the source directory must not contain each other.
- The first listing of a directory reads the headers of every container
  in it, so a large directory on a slow source takes a while to show up.
- On macOS requests are served one at a time.
- Read-only by default: any change fails with `EROFS` (write protected
  on Windows). See [Read-write mode](#read-write-mode).
- The content of a virtual file can never be written, also in `rw`
  mode: there is no compression on write.
- Names that are not valid UTF-8 are passed through, but never get a
  virtual file.

## Requirements

- Linux: the `fusermount3` (or `fusermount`) helper, usually in the
  `fuse3` package. No libfuse is linked, so the release binaries are
  static.
- macOS: [macFUSE](https://macfuse.github.io/).
- Windows: [WinFsp](https://winfsp.dev/). Building needs its Developer
  feature (the import libraries).
- Building: Rust 1.89 or newer and a C compiler (for zstd).

## Build

```sh
cargo build --release
```

## Usage

```
usage: fuse-nsz <srcdir> <mountpoint> [-o option[,option...]]

Mirrors <srcdir> on <mountpoint> and shows every block compressed .nsz/.xcz
in it as a virtual .nsp/.xci too. Stays in the foreground until unmounted.

Options:
  ro             read-only mount (default)
  rw             pass changes through to <srcdir>
  hide_sources   leave out a .nsz/.xcz whose virtual file is shown
  allow_other    let other users in (needs user_allow_other in /etc/fuse.conf)
  allow_root     let root in
  auto_unmount   unmount when the process ends, with allow_other or allow_root
  fsname=NAME    the source shown by mount(8), default fuse-nsz
  subtype=NAME   the file system subtype shown by mount(8)
  noexec, noatime, sync, dirsync
                 the mount flags of these names

Any other option is handed to the FUSE mount as it is.
```

`fuse-nsz --help` prints this text (the one for Linux and macOS is shown)
and `fuse-nsz --version` the version.

Example:

```sh
mkdir -p ~/mnt/switch
fuse-nsz ~/switch/nsz ~/mnt/switch
```

The process stays in the foreground until the filesystem is unmounted.
To mount at boot, run it from a service unit: an `/etc/fstab` line does
not work, because the program does not go to the background.
Unmount with:

```sh
fusermount3 -u ~/mnt/switch    # Linux
umount ~/mnt/switch            # macOS
```

Ctrl-C (SIGINT), SIGTERM and SIGHUP also unmount it. On Linux a mount
that is still in use is detached: it leaves the directory tree at once
and is served until its last open file is closed. A second signal ends
the process without waiting for that. On macOS a mount that is in use is
unmounted by force.

On Linux and macOS the mount uses
`-o ro,nosuid,nodev,fsname=fuse-nsz,default_permissions` (`rw` replaces
`ro`). `suid` and `dev` are refused. Options given with `-o` after the
mountpoint are added, for example:

```sh
fuse-nsz ~/switch/nsz ~/mnt/switch -o allow_other
```

Every file is shown as owned by the user who mounted, with the permission
bits and the sticky bit of the source, and every request is carried out
with the rights of that user. With `allow_other` the kernel checks the
other users against the bits shown:

- The group bits count for the group of the user who mounted. For a file
  that has another group in the source they are cut down to the bits for
  everyone else.
- Access control lists of the source are not looked at.
- A file that another user creates belongs to the user who mounted.

On Windows the mountpoint is a free drive letter (`X:`) or a directory
that does not exist yet. Files are readable by everyone. In `rw` mode
only the user who mounted, the system and the administrators can change
them. Stop it with Ctrl-C. Of the options, only `ro`, `rw` and
`hide_sources` are accepted there.

### Hiding the sources

With `-o hide_sources`, a `.nsz`/`.xcz` whose virtual file is shown is
left out of the mount, so only `game.nsp` is visible instead of both
`game.nsz` and `game.nsp`. Sources that are not exposed (solid NCZ, broken
files, or a real `game.nsp` next to them) stay visible. It works in
read-only mode too. The name of a hidden source stays taken: creating a
file of that name, or renaming one to it, fails.

### Read-write mode

With `-o rw` the mirror passes changes through to the source directory:

- Real files and directories: create, write, truncate, rename, delete,
  `mkdir`, `rmdir`, `chmod` and `touch` work as usual. Hard links, new
  symbolic links, extended attributes and special files cannot be made,
  and a rename that swaps two files is refused.
- A new file or directory gets the permission bits its creator asked
  for, with the umask of that creator. The umask fuse-nsz was started
  with is not used.
- `chmod` changes the permission bits and the sticky bit. The
  set-user-ID and set-group-ID bits are never set through the mount, and
  a `chmod` leaves them as the source has them.
- A virtual file can be renamed, moved and deleted: the operation applies
  to its source. Deleting a virtual file deletes its source container, so
  `rm mnt/*.nsp` removes every `.nsz`.
- A rename of a virtual file must keep its extension (`game.nsp` to
  `other.nsp`, which renames `game.nsz` to `other.nsz`); any other name is
  refused with `EACCES`. `chmod` and `touch` apply to the source too.
- Opening a virtual file for writing or truncating it fails with
  `EACCES` (access denied on Windows).
- A symbolic link is never changed through: delete and rename apply to
  the link itself, also when it is the source of a virtual file, and
  `chmod` of a link or of such a virtual file fails with `EACCES`.
- Deleting a real `game.nsp` that hides the virtual one, or renaming it
  away (as moving it to a trash does), makes the virtual `game.nsp` show
  up under the same name. For one minute that file cannot be deleted or
  renamed (`EACCES`), so that a repeated delete does not remove
  `game.nsz` by mistake.
- Replacing a virtual file or a hidden source with a rename is refused,
  since that would leave the source behind or delete it.
- `chown` fails with `EPERM`: every file belongs to the user that
  mounted it.

A virtual file shows the permission bits of its source, in `rw` mode
the write bits too: Samba takes a file without them for a read-only one
and refuses to delete or rename it. Its content stays read-only.

On Windows, the security descriptor of a virtual file grants no write
access to its data. .NET Framework (Windows PowerShell 5.1) sets file
times through a write open, so setting `LastWriteTime` on a virtual file
fails there; tools that open with `FILE_WRITE_ATTRIBUTES` only work.

## Creating compatible archives

Use block compression:

```sh
nsz -C -B game.nsp
nsz -C -B game.xci
```

Upstream `nsz --keep` keeps every file and partition, but on XCI it
still loses the bytes outside the container files: the original HFS0
headers, hash tables, gamecard certificate and padding. Neither
`nsz -D` nor fuse-nsz can give back the original dump from such an
archive.

To get byte-exact originals back, compress with an `nsz` build that
writes the `NSZKEEP1` trailer with `--keep` (a patch on top of upstream
nsz, not merged yet), for example:

```sh
nsz -C --long --block --verify --keep game.xci
```

The trailer stores every source byte not held in a container file.
Older nsz versions ignore it and read the container as before. Archives
without the trailer still work, with the limitations above.

## The `NSZKEEP1` trailer

The trailer is appended after the regular container:

```
[zstd stream: gap bytes] [zstd frame: JSON map] [u64 gapSize, u64 mapSize, "NSZKEEP1"]
```

The JSON map (`version`, `size`, `segments`) lists segments that tile
the original image in order:

- `[off, len]` takes the next `len` bytes from the gap stream;
- `[off, len, partition, index]` copies file `index` of `partition`
  (`""` for NSZ) from the container as is;
- `[off, len, partition, index, 1]` does the same but decompresses the
  file as an NCZ first.

Uniform gap blocks (for example padding) are stored as fill runs, so
large paddings cost no memory. An unknown `version` falls back to the
rebuilt layout.

## Tests

```sh
cargo test
```

The format unit tests (synthetic NSZ/XCZ containers) live in libhac.
To check real files, point `FUSE_NSZ_TESTDATA` at a directory that holds
each compressed file next to its reference (`X.nsz` with `X.nsp`,
`X.xcz` with `X.xci`):

```sh
FUSE_NSZ_TESTDATA=~/switch/testdata cargo test --release real_data -- --nocapture
```

It checks that:

- a virtual `.nsp` equals the reference `.nsp` byte for byte;
- every NCA in a virtual `.xci` hashes to its name;
- images restored from a `--keep` trailer equal the reference byte for byte.

The tests that mount a scratch directory with the built binary need FUSE
(Linux or macOS), so they only run when asked for:

```sh
FUSE_NSZ_MOUNT_TEST=1 cargo test --test mount
```

## License

fuse-nsz is licensed under either of [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt) at your option.

The repository is [REUSE](https://reuse.software/) compliant: every file
states its copyright and license.

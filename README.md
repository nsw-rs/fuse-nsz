<!--
SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# fuse-nsz

A read-only FUSE filesystem that mirrors a directory and shows every
block compressed `.nsz`/`.xcz` file in it as a plain `.nsp`/`.xci` too.
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
- Images are built on first lookup or directory listing and cached until
  the source file size or mtime changes.
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
- Read-only. Any open for writing fails with `EROFS` (access denied on
  Windows).
- Names that are not valid UTF-8 are passed through, but never get a
  virtual file.

## Requirements

- Linux: the `fusermount3` (or `fusermount`) helper, usually in the
  `fuse3` package. No libfuse is linked, so the release binaries are
  static.
- macOS: [macFUSE](https://macfuse.github.io/).
- Windows: [WinFsp](https://winfsp.dev/). Building needs its Developer
  feature (the import libraries).
- Building: Rust 1.89 or newer and a C compiler (for zstd). The
  [libhac](https://github.com/nsw-rs/libhac) checkout is expected
  next to this one.

## Build

```sh
cargo build --release
```

## Usage

```sh
fuse-nsz <srcdir> <mountpoint> [fuse options]
```

Example:

```sh
mkdir -p ~/mnt/switch
fuse-nsz ~/switch/nsz ~/mnt/switch
```

The process stays in the foreground until the filesystem is unmounted.
Unmount with:

```sh
fusermount3 -u ~/mnt/switch    # Linux
umount ~/mnt/switch            # macOS
```

Ctrl-C (SIGINT), SIGTERM and SIGHUP also unmount it.

On Linux and macOS the mount uses `-o ro,fsname=fuse-nsz`. Options given
with `-o` after the mountpoint are added, for example:

```sh
fuse-nsz ~/switch/nsz ~/mnt/switch -o allow_other
```

On Windows the mountpoint is a free drive letter (`X:`) or a directory
that does not exist yet. Files are readable by everyone. Stop it with
Ctrl-C.

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

## License

fuse-nsz is licensed under either of [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt) at your option.

The repository is [REUSE](https://reuse.software/) compliant: every file
states its copyright and license.

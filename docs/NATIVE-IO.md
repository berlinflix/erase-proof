# Native bounded I/O

`native/io.c` provides Linux C primitives through a small shared library. It has
no privilege changes, setuid bit, listener or service. Python passes an already
opened, identity-checked descriptor; the library never resolves a write path.

The image/virtual-disk eraser uses aligned 4 MiB `O_DIRECT` writes when the native
library is installed. Each call checks the actual file/device length and range,
uses an aligned buffer, handles short writes/EINTR, and flushes data. Direct-I/O
failure stops the job; it never silently retries through the cache. A final
unaligned file tail uses a separately reported buffered write and flush.
Verification still reads the complete logical range and reports actual direct
and tail byte counts in the signed record. Source-only execution without the
library retains the explicitly reported buffered/fsync implementation.

The library also exposes bounded FIEMAP queries and discard/FITRIM primitives.
FIEMAP is an inventory, not permission to raw-write a mounted filesystem. Extent
flags remain visible to callers. Discard primitives are not automatically called
by overwrite: deallocated-sector read behavior must not be confused with proof
of zeros or physical erasure. No physical discard was executed during testing.

Build with `bash scripts/build-native.sh`. The source installer, binary builder
and CI perform this step. The native shared library and ext4 helper are included
in the Linux bundle; clean source archives contain their C source and build
script rather than precompiled ELF files.

References: [Linux FIEMAP](https://www.kernel.org/doc/html/latest/filesystems/fiemap.html),
[open(2), O_DIRECT](https://man7.org/linux/man-pages/man2/open.2.html).

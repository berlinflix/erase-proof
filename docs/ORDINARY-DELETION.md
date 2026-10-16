# Recovery after ordinary deletion

The FAT32 demonstration is one experiment, not a prerequisite or a recovery
database. Recovery does not read its originals, manifest or a predefined file
list. It examines the selected source's surviving filesystem metadata, ext4
journal inode versions and recognizable file structures.

For a file deleted normally, choose the affected disk or an offline filesystem
image in **Recover files**, select a separate output directory, and scan.
Filesystem metadata can recover arbitrary file contents and extensions when its
allocation information survives. Carving identifies supported formats from their
contents. Ext4 journal recovery can recover old allocation maps after normal
unlink has cleared the current inode. Journal candidates have numeric names when
the original path is unavailable, and are labelled as historical candidates.

The C journal reader opens a regular volume image read-only. It reads committed
JBD2 transactions, validates available journal/tag/inode checksums, and extracts
regular files through libext2fs using historical inode maps. It never replays or
changes the source. Each file is limited to 256 MiB and a run to 8 GiB/10,000
candidates, with CPU/memory/time limits. Fast-commit deltas are not decoded.
An attached loop image is refused; acquire/unmount the source first. Direct
device journal recovery requires a separate offline image.

An unreadable metadata entry does not stop other entries. Empty inode outputs
are recorded as warnings and excluded from the desktop's recovered-file list.
A valid file decoder does not prove that historical data blocks were not reused;
check important recovered contents. Overwritten or discarded bytes cannot be
recreated by a recovery application.

## Independent normal-deletion validation

`scripts/verify-normal-deletion.py` creates fresh files with random contents and
names, formats new 128 MiB filesystem images, mounts them through Linux drivers,
writes the files, flushes them and deletes them using ordinary `os.unlink` and
`os.rmdir`. It unmounts/detaches the images before calling the actual recovery
engine. Recovery receives only the image and output path. The original hashes
are compared afterwards by the test harness.

`--image-mib` also supports 1, 2, 4 and 8 GiB images. `--user-activity` adds
prior versions, atomic saves and deleted backup copies. A complete 1 GiB run on
all four filesystems recovered all six current files exactly after that activity
and left every source hash unchanged. [Evaluation](EVALUATION.md) records the
larger erasure checks and reproduction commands.

```bash
sudo /path/to/project-venv/bin/python scripts/verify-normal-deletion.py \
  --output qa/normal-deletion-NEW
```

This requires loop/mount privileges and FAT32/ext4/NTFS/exFAT tools; it uses no
physical disks. The source volume images are temporary. Extracted outputs,
fresh originals and comparison reports remain in the requested QA directory.

Measured in WSL Ubuntu on 16 October 2026: all six fresh files recovered exactly
on FAT32, NTFS and exFAT. Ext4 initially recovered PNG, JPEG, PDF and ZIP through
carving; adding journal inode recovery also recovered the plain-text and unknown
`.custom` files exactly. A repeated four-filesystem run also verified that source
image hashes remained unchanged throughout recovery. These results concern fresh surviving bytes, not a
promise of successful recovery after every possible overwrite or reuse.

The experiment also found and fixed a PDF boundary error: the carver now retains
the EOF line ending and follows contiguous incremental updates rather than
silently returning the earlier revision.

JPEG boundaries are parsed through application segments and scan markers, so an
embedded thumbnail's end marker does not truncate the main photo. ZIP boundaries
require a consistent central directory and local-header offsets, including ZIP64
end records; footer-like bytes inside an ordinary archive member are ignored.

Format reference: [Linux JBD2 journal structures](https://www.kernel.org/doc/html/latest/filesystems/ext4/journal.html).

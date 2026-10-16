# Native architecture and implementation boundary

## Execution

```text
Qt desktop / CLI
      |
      +-- target discovery and plan policy (lsblk + stat + device identity)
      |
      +-- native recovery
      |     +-- chunked binary carver (16 container families, ZIP/Office identification)
      |     +-- bounded PNG chunk-gap reconstruction
      |     +-- isolated decoding / strict PDF / ZIP CRC / SQLite validators
      |     +-- independent filesystem adapter (fls / icat)
      |     +-- PhotoRec attack reports and MBR/GPT partition offsets
      |
      +-- overwrite engine
      |     +-- C descriptor-only O_DIRECT writes, reported buffered tails
      |     +-- pinned file descriptor, exclusive file lock
      |     +-- O_EXCL block-device open, explicit path + serial allowlist
      |     +-- actual bounded writes, fsync, cache-drop advice
      |     +-- complete byte read-back and reference search
      |     +-- recovery attack using the native carver
      |
      +-- targeted operations
      |     +-- pinned logical file/folder overwrite and unlink
      |     +-- offline FAT32 chains, metadata and known free-space copies
      |     +-- C/libext2fs offline ext4 free space, unused inodes, directory slack and journal history
      |     +-- allocated unrelated file hashes and read-only filesystem consistency gates
      |
      +-- media operations
      |     +-- read-only NVMe/ATA/HPA/DCO discovery
      |     +-- all-namespace guarded NVMe submission, audited receipts
      |     +-- real software LUKS2 image keyslot removal
      |
      +-- evidence
            +-- Ed25519 local operator key
            +-- signed target / plan / before hash / after hash / measurements
            +-- SQLite certificate + audit append transaction
            +-- expected signer checks and external signed audit checkpoints
            +-- PDF/QR summary with attached authoritative signed JSON
```

The native application runs Qt widgets directly. There is no web view, web server, hosted backend or remote data path. The GUI performs long-running engine operations in a background QThread and passes progress/results back through Qt signals. The CLI invokes the same engine.

## Trust boundaries

- A regular user can perform the filesystem-image experiment and recovery. The app never silently grants itself root access.
- Actual block-device writes require Linux device permissions. The engine only enables them for recognized virtual-disk models, a complete disk, a matching explicit path and exact serial, no mounted descendants, and a writable target. System-disk/mount refusal policy is checked again after opening the device. Linux's exclusive block-device open adds a kernel-level in-use check.
- Input paths are not interpolated into shell commands. The forensic and demo adapters pass argument arrays to installed system executables.
- Recovery sources are opened read-only. New extraction outputs use exclusive creation. Raw-device recovery refuses a destination on the same source device.
- Image writes refuse symbolic links, hard links, target identity changes, invalid reference manifests, empty images and unsupported filename suffixes. A cancelled write remains a real partial overwrite; it is not rolled back or certified.

## What is measured

The reference score counts matched unique aligned block hashes and matched metadata byte patterns against a provided baseline. It does not measure all possible recoverability. A missing baseline yields an unavailable score. Whole-image records require full zero read-back; targeted operations state exactly which logical bytes/allocation metadata were checked.

The carver scans in 4 MiB chunks, with a 256 MiB candidate limit. Recovered images, PDFs, archives and SQLite databases receive resource-bounded format validation in separate processes. Other containers expose their structural checks. Confidence remains a heuristic. Sleuth Kit and PhotoRec adapters preserve their own outputs and failures; an unrecognized filesystem is not a clean forensic verdict.

## Delivered versus research milestones

The software milestones and exact validation state are tracked in [MILESTONES.md](MILESTONES.md). Device command scope is in [MEDIA.md](MEDIA.md); signer trust, PDF verification and truncation detection are in [EVIDENCE.md](EVIDENCE.md).

The shared offline coordinator fingerprints selected files and preserves hashes
of unrelated allocated user streams. Ext4 uses libext2fs; NTFS uses libntfs-3g
plus ntfswipe, with complete free-cluster and allocated USN readback. Both keep
filesystem-specific pre/post consistency gates and fail without certification
when unknown free-space bytes remain.

The exFAT adapter validates both boot regions and all bitmap/FAT allocation
ownership, including contiguous streams and fragmented chains. It clears free
allocation, inactive directory records and stream slack, then separately reads
those regions back. It rejects unknown allocations and TexFAT layouts.

Remaining implementation/evaluation covers broader fragmentation, ATA destructive commands, HPA/DCO changes, privileged orchestration, unknown snapshots/copies, public operator trust infrastructure and physical-media sanitization assurance. The C I/O and offline filesystem components are unprivileged and use policy-checked descriptors. No mounted filesystem is scrubbed through guessed raw extents or blind journal edits.

The default image experiment and GUI flow are tested in WSL Ubuntu. VirtualBox guest device I/O and physical media need separate acceptance tests; a VM result must not be presented as host SSD sanitization.

## API references used

- [Linux open(2): O_EXCL for block devices](https://man7.org/linux/man-pages/man2/open.2.html)
- [The Sleuth Kit fls](https://www.sleuthkit.org/sleuthkit/man/fls.html)
- [The Sleuth Kit icat](https://www.sleuthkit.org/sleuthkit/man/icat.html)
- [Qt for Python](https://doc.qt.io/qtforpython-6/)

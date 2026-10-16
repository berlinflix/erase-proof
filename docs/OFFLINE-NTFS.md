# Offline NTFS targeted cleanup

The native Targeted erasure page supports an **unattached, regular NTFS volume
image at offset zero**. This path never opens a block device or force-mounts a
dirty/hibernated volume. It preserves unrelated allocated user data streams.

```bash
eraseproof ntfs-list /path/to/volume.img
eraseproof ntfs-plan /path/to/volume.img /private-folder
eraseproof ntfs-erase /path/to/volume.img /private-folder \
  --confirm volume.img:/private-folder --case ~/EraseProof/ntfs-case
```

The plan explains that cleanup removes **all deleted history on this volume**,
including history unrelated to the selected path. Review it before proceeding.
Snapshots, external copies and physical flash remnants remain outside its scope.

## Method

The C adapter uses libntfs-3g for path traversal, ordinary unlink and empty-folder
removal. It accepts only a single-link regular image; system files, reparse
points, EFS targets, hard-linked targets and direct stream selection are refused.
Selecting a base file includes all its named data streams. Directory traversal
checks every parent rather than following reparse points.

Before writing, `ntfsfix --no-action` and `ntfsresize --info --no-action` must
pass. The coordinator fingerprints selected content and filenames, and hashes
every unrelated allocated user stream. It then unlinks selected entries from
the leaves upward, clears allocated `$UsnJrnl:$J` payload, and runs `ntfswipe`
for unused MFT/index space, `$LogFile`, free clusters and file tails. The tool's
actual output and its SHA-256 are retained in the evidence case. `$LogFile`
uses ntfswipe's filesystem-specific reset pattern; it is not claimed to contain
all zero bytes.

USN cleanup leaves offsets, IDs and `$Max` intact. Sparse holes are skipped so
the cleanup cannot expand a sparse journal into a huge allocated file. Both
resident payloads and allocated nonresident runs are supported. Bounds are
checked before processing the runlist.

After flushing, both consistency checks must pass again. Every preserved user
stream must retain its exact SHA-256, length, inode and path. The engine scans
the complete logical image for selected content/name fingerprints and checks
for identical live copies. A separate C readback checks **every unallocated
cluster** and all allocated USN payload for nonzero residue. Failure of any
required check leaves an incomplete audit event and no certificate.

The signed record states the image scope, selected files, reference-manifest
digest, cleanup log digest, consistency results and readback counters. It does
not certify unchanged copies outside this image, NTFS snapshots, storage
firmware or physical remanence. File-name/content reference checks cannot
establish the absence of every unknown metadata field on every NTFS variant.

## Validation

Generated 64 MiB NTFS images cover resident files, larger files, folder trees,
alternate data streams, unrelated allocated streams, previously deleted copies
and allocated USN data. Tests verify exact preservation, filesystem consistency,
rejection without image changes, live duplicate detection, and injected known
or unknown free-space residues. The native Qt background workflow also exercises
NTFS list, erase and evidence creation. Firmware operations are not involved.

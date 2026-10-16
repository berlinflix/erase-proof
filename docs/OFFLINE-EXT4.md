# Ext4 targeted image cleanup

EraseProof 0.4 adds an offline ext4 adapter written in C against libext2fs.
It accepts a regular volume image at offset zero. An image attached to a loop
device is refused. It never edits a mounted filesystem or raw physical disk.

```bash
eraseproof ext4-plan volume.img /private-case
eraseproof ext4-erase volume.img /private-case \
  --confirm volume.img:/private-case --case ~/EraseProof/evidence
```

The native app exposes the same operation under Targeted erasure → Offline
filesystem image → ext4. Confirmation includes both image filename and internal
path. Erasing a folder removes its selected descendants first.

The operation removes the selected allocations and clears **all unallocated
history on the volume**: free blocks, unused inode records, ordinary directory
slack and inactive internal journal payload. This also removes recovery history
for other previously deleted files. It does not remove unrelated allocated files.
Every unrelated allocated regular file is SHA-256 checked before and after.
Directory indexes and metadata checksums are maintained through libext2fs.
Read-only `e2fsck -fn` must pass before and after the changes; no automatic
filesystem repair is attempted.

Before erasure, the verifier fingerprints selected content in 512-byte blocks,
head/tail samples and UTF-8/UTF-16 names. Afterwards it scans the complete image
and runs the native carver. A remaining live duplicate is preserved and prevents
a successful target-residue record. An RRS of zero refers to this measured
baseline and current image; host snapshots, changed live versions, other devices
and physical flash pages remain outside its proof.

Dirty/replay-required filesystems, external journals, bigalloc, quotas, inline
data, encryption, casefold and shared-block features are refused. Target trees
containing special files, hard-linked files or external extended attributes are
refused before deletion. These restrictions are checked rather than guessed.
Take a separate backup of valuable unrelated data before choosing any destructive
filesystem operation. Cancellation/failure leaves a genuine partial operation,
an incomplete audit event and no completion certificate.

Validation covers 1 KiB and 4 KiB ext4 blocks, actual deleted content/name history,
hash preservation, indexed directories, and injected journal/free-space residue.
The verifier refuses certification when the injected content survives.

The C build requires `gcc` and `libext2fs-dev`; runtime uses Ubuntu's libext2fs
from e2fsprogs. See `scripts/build-native.sh` and the Ubuntu setup script.

Format references: [kernel ext4 structures](https://www.kernel.org/doc/html/latest/filesystems/ext4/),
[e2fsprogs reference implementation](https://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git/).

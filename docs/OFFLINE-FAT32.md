# Offline FAT32 targeted cleanup

The native Targeted erasure page and `fat32-list`, `fat32-plan`, `fat32-erase`
commands use the shared offline coordinator. This replaces the earlier
known-sector-only sweep with **all deleted history on the image**. Review the
plan and its scope before confirming.

```bash
eraseproof fat32-plan volume.img /private-folder
eraseproof fat32-erase volume.img /private-folder \
  --confirm volume.img:/private-folder --case ~/EraseProof/fat-case
```

The source must be an unattached regular FAT32 volume image at offset zero.
Geometry, FAT mirrors, allocation chains and complete live allocation ownership
are checked before writing. Cross-links, orphaned/bad allocations, dirty/error
flags and unsupported layouts are refused. `fsck.fat -n` must pass before and
after cleanup; repair is never automatic.

The first mutation flushes the dirty flag to every FAT copy. Selected entries
are removed, their clusters released, and every proven free cluster is cleared.
Deleted directory records retain their deleted marker but have a zero payload;
existing end markers and subsequent directory space become zero. Live file
slack is cleared without changing logical contents. FAT copies are written
consistently and FSInfo hints become unknown rather than guessed. Data is
flushed before restoring the clean flag.

Free runs use the C I/O component for aligned direct writes. Explicit buffered
prefixes/tails stay within their proven ranges. Evidence records actual direct
and buffered byte counts. Full readback checks free space, inactive directory
payloads and allocated file slack. Target fingerprints and names must be absent,
and every unrelated allocated file must retain its SHA-256, size, path and
directory-entry location. PhotoRec, Sleuth Kit and bulk_extractor must also pass
the [independent gate](ATTACK-VERIFICATION.md).

A retained identical live copy prevents certification, while its data remains
preserved. Shared target byte patterns can also keep RRS above zero; a zero
score is limited to the recorded references and current logical image. Source
snapshots, changed copies elsewhere and physical storage remain outside scope.

Tests cover ordinary and long names, fresh arbitrary binary contents, previously
deleted copies, exact preservation, duplicate-copy refusal and injected unknown
residue in free space, directory records and file tails. A private mounted-vfat
fixture validates real fragmentation and a supplementary Unicode character
whose UTF-16 surrogate pair spans two long-name records. The parser joins raw
UTF-16 fragments before decoding, so the name is preserved correctly.

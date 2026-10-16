# Offline exFAT targeted cleanup

Use the native Targeted erasure page or these CLI commands with an unattached
regular **volume image at offset zero**:

```bash
eraseproof exfat-list volume.img
eraseproof exfat-plan volume.img /private-folder
eraseproof exfat-erase volume.img /private-folder \
  --confirm volume.img:/private-folder --case ~/EraseProof/exfat-case
```

Cleanup removes the selected allocation and **all deleted history on the
volume**. It clears every bitmap-confirmed free cluster, stale FAT links for
free clusters, inactive directory records, directory space after end markers
and allocated stream slack. Unrelated allocated file contents are hash-checked.
Other copies, snapshots and physical remnants remain outside this proof.

## Validation and writes

The parser follows the [Microsoft exFAT specification](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification).
It checks both boot-region checksums, main/backup agreement, geometry, file-entry
set checksums, the up-case table checksum, directory structures and all allocation
ownership. Allocation comes from the bitmap; a contiguous `NoFatChain` stream
does not require meaningful FAT links. Fragmented streams follow a checked FAT
chain. Every claimed cluster must be allocated and owned exactly once, and every
allocated cluster must have a recognized owner.

Both pre/post `fsck.exfat -n` must pass. The first mutation marks both boot
regions dirty and flushes that state before modifying allocation. Completion
flushes the changed bitmap/FAT and updates the percent-in-use fields before
clearing the dirty flags. The excluded boot-checksum fields retain the original
checksum validity. A failed partial cleanup is never automatically repaired.

Inactive directory slots retain a nonzero inactive type byte with a zero payload;
they are not changed into premature end markers that would hide later live
entries. Existing end markers and subsequent directory space become zero. The
engine writes only selected metadata, proven free allocations and stream slack.

Preserved files must retain their SHA-256, length, inode-location and path. The
target fingerprint/name scan must be clean. Independent full readback also
checks every free cluster, free FAT entry, inactive directory payload and
allocated stream slack; unknown random bytes in these regions block
certification even when RRS from known references is zero.

## Supported scope

Supported volumes use exFAT revision 1.0 and one FAT. TexFAT, dirty/media-failure
flags, unknown active/vendor allocations, malformed structures, overlapping or
orphaned allocations are refused. Metadata bounds are explicit: at most
32 million clusters, a 256 MiB FAT, 64 MiB per directory and one million file
entries. These bounds avoid unlimited allocations from untrusted images.
Case-sensitive paths must exactly match the displayed inventory.

Driver-based tests format generated images, mount only their own loop devices
inside a private mount namespace, create normal files through exfat-fuse and
detach before cleanup. They cover real fragmentation, Unicode names, previous
deletion history, preserved content checked with Sleuth Kit, wrong confirmations
and injected known/unknown residues in free space, inactive directories and file
tails. Physical drives are never selected.

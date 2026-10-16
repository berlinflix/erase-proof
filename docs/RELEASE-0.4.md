# EraseProof 0.4

Native C I/O and offline ext4 cleanup extend the existing Ubuntu recovery,
FAT32/file erasure, media discovery and signed-evidence application.

- Aligned image/current-file writes use the descriptor-only C `O_DIRECT`
  implementation. Unaligned tails are flushed separately and reported.
- FIEMAP inventories are available in current-file plans; they never authorize
  raw writes through a mounted filesystem.
- The ext4 adapter clears selected allocations, all unallocated history and
  unused inodes, directory slack, and inactive internal journal blocks. It keeps
  supported directory indexes/checksums valid through libext2fs.
- Unrelated allocated file contents are hash-checked. Read-only fsck gates run
  before and after erasure. Remaining target references prevent certification.
- Failed residue verification retains offsets/counts/RRS in the audit event.
- The Qt targeted page and CLI expose the same operation. Setup/build scripts
  compile the native components; clean source archives include their C source.

See [ext4 restrictions and scope](OFFLINE-EXT4.md) and [native I/O](NATIVE-IO.md).
Validation: 56 automated WSL tests passed. The frozen executable performed the
four-file recovery and evidence workflow, 64 MiB of measured C direct writes,
and ext4 targeted cleanup with preserved-file hashes. Clean archive checksums,
source hygiene, native components and extracted Qt startup passed. The native
recovery screen was also visually reviewed with real recovered results.

The 0.3 live image's BIOS/UEFI and in-guest engine checks are documented separately;
the final live image will be rebuilt after the remaining software milestones.

NTFS/exFAT targeted cleanup and additional guarded physical-media methods are
still being implemented. Physical-media assurance and VirtualBox acceptance have
not been measured in this session.

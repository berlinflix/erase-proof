# EraseProof 0.3.0 native Ubuntu milestone

Target: Ubuntu x86-64, including an installed Ubuntu desktop in Oracle
VirtualBox. Build/automated verification: WSL Ubuntu 22.04, Python 3.10,
PySide6 6.8.3. VirtualBox acceptance is deferred at the user's request.

Implemented and checked:

- Seven-page native Qt desktop and matching CLI.
- Real FAT32 create/delete/recover experiment with original SHA-256 checks.
- Expanded format carving, isolated validators, bounded PNG gap recovery,
  MBR/GPT offsets and real PhotoRec/Sleuth Kit reports.
- Actual image/guest-visible overwrite, full logical read-back, known-reference
  residue checks, cancellation handling and signed records.
- Logical file/folder overwrite/unlink and allocation-aware offline FAT32
  targeted cleanup with preservation/fsck checks.
- Native NVMe/ATA discovery, all-namespace guarded NVMe submission receipts,
  and real software LUKS2 image keyslot removal.
- Expected signer fingerprints, externally stored signed audit checkpoints,
  interrupted-job visibility, and PDF/QR summaries carrying signed JSON.

Validation: 45 tests pass in a fresh isolated environment. The packaged ELF
recovers the four deleted originals with matching hashes, overwrites and
verifies the actual fixture, checks trusted signatures and PDF attachments,
compares an external audit anchor, performs targeted logical erasure, runs
PhotoRec after wiping and launches the native Qt process. A rendered two-page
PDF was visually inspected; its QR code was decoded from the rendered page.

Distribution contains bundled Python/Qt, build package versions, third-party
licenses and scope documentation. It still needs the Ubuntu system tools
installed by `install-runtime.sh`. The source package includes setup, build,
test and package verification scripts.

This is a research software milestone. Physical firmware behavior, physical
flash remanence, ATA destructive operations, HPA/DCO changes, and ext4/NTFS/exFAT
targeted journal/history cleanup are not established by these results.
Firmware/keyslot receipts are never presented as verified-erasure certificates.

The live-ISO build workflow is additional distribution work. Its actual build
and boot status is tracked separately in MILESTONES.md.

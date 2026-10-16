# Delivery milestones

Each completed software milestone is committed and pushed to
https://github.com/berlinflix/erase-proof.git after its checks pass.
VirtualBox acceptance tests are deliberately deferred at the user's request.

| Milestone | Deliverable | State |
| --- | --- | --- |
| Native foundation (0.2) | Qt/CLI, real FAT32 deletion and recovery, logical image overwrite, complete read-back, Ed25519 audit evidence, Linux bundle | Complete; 13 WSL tests plus frozen executable workflow passed |
| Targeted erasure | File/folder engine, allocation-aware FAT32 image cleanup, free-space history sweep, transparent residue findings | Complete; 20 WSL tests passed, including preservation of unrelated live files and FAT32 fsck checks |
| Forensic recovery | Expanded signatures/validation, bounded PNG gap reconstruction, independent tool results, partition offsets | Complete; 26 WSL tests passed, including actual ffmpeg/7z fixtures, real PhotoRec/TSK and GPT corruption rejection |
| Media-aware operations | NVMe/ATA discovery, controller-wide guarded NVMe submission, real LUKS2 image keyslot removal, scoped receipts | Software milestone complete; 38 WSL tests passed. Physical firmware behavior remains unverified; ATA destructive/HPA/DCO changes are not enabled |
| Evidence | Trusted signer checks, attached signed JSON in PDF/QR reports, audit anchors, interrupted-job visibility, native GUI integration | Complete; 44 WSL tests passed; two-page PDF visually reviewed and QR decoded from its rendered page |
| Native distribution (0.3) | Updated standalone executable, source/runtime installers, clean release packaging | Complete; 46 clean-environment tests, expanded frozen workflow, archive checksums/source hygiene and extracted Qt launch passed |
| Live environment | Ubuntu 24.04 ISO, BIOS/UEFI boot, responsive native interface and generated-image engine check | Complete; actual QEMU/KVM BIOS and UEFI GRUB boots, graphical screenshots at 1920×1080 and 1024×768 inspected, in-guest recovery/erase/evidence self-test passed. No hard disks attached; VirtualBox acceptance remains deferred |
| Native I/O and ext4 cleanup (0.4) | C direct I/O, FIEMAP, libext2fs allocation/inode/slack/journal cleanup, preserved-file checks, CLI/Qt integration | Complete for documented supported ext4 features; 56 WSL tests passed, standalone executable exercised 64 MiB of actual direct I/O and ext4 cleanup, packaged archive/extracted Qt checks passed |
| Ordinary deletion recovery (0.5) | Fresh-file VFS deletion tests, C ext4 journal inode recovery, PDF boundaries/incremental revisions, per-entry failure handling | Source milestone complete; 58 WSL tests passed. Fresh PNG/JPEG/PDF/ZIP/text/unknown-format files recovered with exact SHA-256 on FAT32, ext4, NTFS and exFAT after real mounted-driver unlink/rmdir; all four source images unchanged. Final executable/live rebuild follows remaining milestones |
| NTFS cleanup (0.6) | libntfs-3g target/stream removal, ntfswipe history cleanup, sparse-aware USN cleanup, complete free-cluster/USN readback, shared offline coordinator and CLI/Qt integration | Source milestone complete; 69 WSL regression tests passed, including resident/nonresident USN, stream preservation, known/unknown residue mutations and native Qt workflow. Final executable/live rebuild follows remaining milestones |
| exFAT cleanup (0.7) | Checked bitmap/FAT ownership, contiguous/fragmented chains, free allocation/metadata/slack cleanup, complete history readback and CLI/Qt integration | Source milestone complete; 77 WSL regression tests passed inside a private mount namespace, including genuine driver fragmentation, Unicode names, independent preserved-file extraction and free/directory/tail residue mutations. Final executable/live rebuild follows remaining milestones |
| Independent certification gate (0.8) | Required PhotoRec/TSK/bulk_extractor checks, source identity/hash continuity, extracted-byte matching, completion-report validation, resource/cancellation boundaries, Aho-Corasick scanning and packaged helper dependencies | Source milestone complete; 87 WSL regression tests plus the added child-process cleanup case passed. All 11 gate/worker tests passed; a Base64-encoded fresh JPEG was recovered exactly by the third scanner. Standalone Ubuntu executable passed whole-image/ext4/NTFS workflows and real-driver fragmented exFAT cleanup with all three tools completing. Upstream bulk_extractor test programs: 4/4 passed |
| FAT32 verification (0.9) | Shared offline coordinator, complete allocation ownership and history cleanup/readback, independent attack gate, Unicode and fragmentation handling | Complete; all 94 WSL regression tests passed in a private mount namespace. Standalone Ubuntu executable passed FAT32/ext4/NTFS targeted cleanup with preservation, whole-image direct I/O, recovery, signed PDF/audit and native Qt startup |
| Complete media planner | Guarded physical methods and capability/hidden-area gates | Remaining software work |
| Evaluation and final distribution | Reproducible filesystem/mutation evaluation, final source/native/live release | Remaining software work |

Software tests use generated images and mock hardware command boundaries.
Firmware behavior and physical remanence cannot be measured without spare
hardware. Such tests must stay explicitly unverified in release evidence.

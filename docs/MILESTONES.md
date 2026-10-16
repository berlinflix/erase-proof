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
| Media planner and native recovery flow (0.10) | Read-only method matrix, explicit hidden-capacity/unsupported-method gates, sysfs NVMe ownership, selectable offline files, recovery-first startup and Ubuntu Trash copies | Complete within the documented execution scope; 101 WSL regression tests passed, followed by all six new Trash/Qt tests. Actual gio Trash move and exact arbitrary-byte recovery passed. Format NVM, ATA destructive/HPA/DCO adapters remain disabled and require separate implementation/hardware evaluation |
| Larger-image evaluation (0.11) | Fresh ordinary deletion after edits/atomic saves/backups; larger four-filesystem history erasure; correctly bounded independent container outputs | Complete at 1 GiB on FAT32/ext4/NTFS/exFAT: 24/24 exact current-file recoveries, unchanged sources, all four targeted RRS-zero records with independent scanners completing and unrelated file preserved. Full regression: 107 passed; updated worker tests: 12 passed; updated native Qt/media tests: 26 passed. Standalone 0.11 recovery/erase/Trash/planner/evidence workflows passed. See EVALUATION.md |
| Ubuntu preview distribution (0.11) | Source/native/live artifacts, checksums, native and in-guest validation | Verified preview build: 110 WSL regression tests passed; the final table polish passed all 8 native Qt tests. Standalone workflow, signed JSON/PDF/audit, real 64 MiB direct I/O and extracted-package checks passed. Actual QEMU/KVM BIOS and UEFI GRUB desktops were visually reviewed at 1920×1080 and 1024×768. Expanded Noble in-guest workflow passed recovery, whole-image/FAT32/ext4/NTFS erasure, preservation, Trash, planner, evidence and Qt checks. No hard disks were attached. Release assets are published through GitHub Releases |
| Remaining proposal work | ATA destructive/Format NVM/HPA/DCO adapters, ssdeep, broader arbitrary fragment reconstruction, public-corpus comparisons, physical-media/standards evaluation | Not delivered in 0.11; physical firmware behavior is unverified. Actual VirtualBox acceptance remains deferred. The complete research proposal is not claimed finished |

Continuation milestone: streaming ssdeep and 4 KiB SHA-256 fingerprints are now
generated by the ordinary-file and offline-volume erasers. Native carving,
preserved live files and independent recovered outputs are checked for similarity;
positive findings block targeted certification. Malformed signatures and bounded
reference counts are validated before destructive writes. All **121 regression
tests passed** in a private WSL mount namespace, including actual filesystem
fixtures and Qt workflows. The focused ssdeep/erasure/independent-worker suite
passed all **27 tests**, including comparison against the independent ssdeep CLI.
The installed 0.11 release assets remain unchanged until the final rebuild.
See [proposal coverage](PROPOSAL-COVERAGE.md) for the remaining original scope.

0.12 source milestone implements bounded multi-format fragment recovery with
per-file confidence/entropy, restricted native NVMe/ATA/Format/HPA/DCO adapters,
private interruption recovery, the confirmed controller erase/attack escalation
loop, guarded host-visible overwrite/discard, encryption/TCG discovery and strict
certificate/receipt classification. Firmware command-boundary tests, native Qt
checks and an initial **172-test** root/private-mount regression passed. Subsequent
private-parser, atomic-rebuild and metadata confidence fixes passed their focused
tests; the final frozen-source regression and executable/live rebuild follow.
The [public DFRWS comparison](validation/dfrws-0.12.json) measures 10/32 exact
originals in bounded fragment mode, with its remaining search limits preserved.
Public 1 GiB Govdocs FAT32/ext4 erasure comparisons passed independent attacks and
unrelated-file preservation; NTFS/exFAT comparison runs continue. Physical media
and actual VirtualBox acceptance remain explicitly unverified.

Software tests use generated images and mock hardware command boundaries.
The supplemental QEMU block-device test also passed exact unknown-format
recovery from a generated raw disk, unchanged source reads, 64 MiB of native
direct writes, signed evidence and a complete independent host-file zero check.
Its script and [measured result](validation/virtual-block-0.11.json) are on main;
the release archives retain their recorded build provenance.
Firmware behavior and physical remanence cannot be measured without spare
hardware. Such tests must stay explicitly unverified in release evidence.

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
| NTFS/exFAT cleanup | Offline allocation and history cleanup with preserved-file checks | Remaining software work |
| Complete media planner and verification loop | Guarded physical methods, capability and hidden-area gates, independent attack integration | Remaining software work |
| Evaluation and final distribution | Reproducible filesystem/mutation evaluation, final source/native/live release | Remaining software work |

Software tests use generated images and mock hardware command boundaries.
Firmware behavior and physical remanence cannot be measured without spare
hardware. Such tests must stay explicitly unverified in release evidence.

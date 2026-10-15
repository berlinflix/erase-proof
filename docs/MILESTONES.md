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
| Evidence and distribution | Trusted signer checks, PDF/QR records, audit anchors, native GUI integration, live-image build workflow, release packaging | Planned |

Software tests use generated images and mock hardware command boundaries.
Firmware behavior and physical remanence cannot be measured without spare
hardware. Such tests must stay explicitly unverified in release evidence.

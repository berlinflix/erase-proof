# Original proposal coverage

This checklist follows the user's EraseProof artifact, Q9–Q12. The user's
subsequent native Ubuntu application requirement replaces the proposed web UI.
"Implemented" describes software behavior, not an assertion of physical-media
validation. Oracle VirtualBox acceptance is deferred by the user.

| Requirement | Implementation / evidence | Remaining acceptance |
| --- | --- | --- |
| Native Ubuntu CLI and desktop, live USB | Qt application and Ubuntu 24.04 BIOS/UEFI ISO; released 0.11; QEMU boot and frozen workflow results | Rebuild after new milestones; actual VirtualBox demo |
| Normally deleted files, independent of demo filenames or references | Metadata recovery, ext4 historical inode maps, raw carving, Ubuntu Trash copies; 24 exact fresh-file recoveries across four filesystems; public DFRWS and 16-case Govdocs measurements | Recovery depends on surviving bytes/allocation; unsupported types remain in the public recall denominator |
| File extent discovery, current-byte overwrite, metadata/history cleanup | FIEMAP and C direct I/O; offline FAT32/ext4/NTFS/exFAT global free-space, deleted metadata, journal/log/slack cleanup and preserved-file checks | Mounted-file erasure remains explicitly current-byte only; acquisition/offline cleanup required for history |
| SHA-256 per 4 KiB plus ssdeep | Streaming fingerprints in file/offline erasers; standalone `fingerprint`; native and independent recovered-byte similarity checks; 174 source tests and frozen agreement check passed | Final distribution acceptance |
| Bifragment gap carving | Bounded PNG/ZIP/PDF/JPEG search, isolated unprivileged workers, decoder-guided JPEG boundaries and structural gap inference; fresh exact-file tests and two public fragmented JPEG recoveries | Declared resource/gap/format limits remain; arbitrary fragmentation is not guaranteed |
| Validation, confidence and entropy | Isolated image/ZIP/PDF/SQLite validators; explicit validation/completeness/entropy components for recovered files; public DFRWS exact-byte comparison | Scores are structural heuristics, not calibrated original-byte probabilities; population-wide statistical calibration is not claimed |
| Controller capability discovery | Linux inventory, sysfs ancestry, native pinned NVMe identity, ATA IDENTIFY/HPA/DCO integrity checks | Physical controller behavior |
| NVMe sanitize | Allowlisted controller-wide submission, exclusive namespace opens, audited uncertain/accepted states | Spare physical controller validation; command acceptance is not certification |
| NVMe Format with cryptographic erase | C admin ioctl, OACS/FNA scope, sector-format preservation, all-namespace identity/exclusivity and post-format checks; actual QEMU SES=1 Format and full workflow passed | SES=2 crypto/physical-controller acceptance; a simulator cannot validate physical remanence |
| ATA sanitize / Enhanced Secure Erase | C SG_IO, native capability/state gates, saved private recovery credentials, audited interruption and explicit security recovery | Spare physical SATA hardware acceptance |
| HPA/DCO opening and post-wipe checks | Explicit factory-capacity confirmation, HPA/DCO transaction, legacy/ACS3 commands, full capacity/identity read-back and overwrite pre/post checks | Spare physical hidden-capacity hardware acceptance |
| HDD/USB/SD overwrite, discard and hidden-media distinction | Guarded host-device overwrite/full logical readback and independent attacks; separate discard receipts | Physical media evaluation; hidden flash/chip-off assurance is not inferred |
| Encrypted storage discovery and crypto erase | Real LUKS2 image keyslot removal; BitLocker/partition signatures and bounded native TCG Level 0 discovery | Physical SED/BitLocker evaluation; external/cached keys remain outside local deletion |
| Independent verification | Required PhotoRec/TSK/bulk_extractor, output-byte comparison, exact/fuzzy mutation checks, completeness/resource gates, source continuity | Population-wide false-positive/negative estimates require broader research |
| Ed25519 JSON, audit chain, PDF and offline QR | Implemented, signatures/anchors and attached JSON validated | Rebuilt final artifacts |
| Closed-loop escalation | Confirmed NVMe/ATA method chains, completion/action-log or observed ATA busy-transition checks, full-range attacks and zero-score certificate gate; actual QEMU NVMe Format/attack/certify run; uncertainty/incomplete attacks and post-attack identity/capacity changes block retry/certification | Physical firmware acceptance; a fast ATA sanitize with no observed busy transition requires manual inspection |
| Safety | Device allowlist, typed identity, mounted/root/holder refusal, dry-run plans; generated-image/owned-VM tests only | Regression for each newly introduced hardware command |
| E1–E5 research evaluation | Real 1–8 GiB images, residue mutations, public DFRWS/PhotoRec/Foremost comparison, 16-case Govdocs 1 GiB study and measured dd/C/pipeline overhead | Physical method measurements; broad statistical confidence calibration is not claimed |

The complete proposal is not yet accepted. Physical sanitization, hidden flash
cells and chip-off recoverability cannot be established from a software simulator
or from a firmware command returning success.

ssdeep is a similarity heuristic. The default threshold is 70/100; a positive
finding blocks a clean targeted result. Exact file, 512-byte and 4 KiB hashes
remain separate evidence. No similarity match is presented as proof of identity,
and a lack of similarity alone never establishes that data is gone. Partial final
4 KiB fingerprints are recorded; sector scanning covers complete 4 KiB windows,
with short/tail samples and whole-file comparisons covering additional cases.

Reference: [ssdeep API](https://ssdeep-project.github.io/ssdeep/doc/api/html/fuzzy_8h.html).

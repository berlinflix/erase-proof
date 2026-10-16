# Original proposal coverage

This checklist follows the user's EraseProof artifact, Q9–Q12. The user's
subsequent native Ubuntu application requirement replaces the proposed web UI.
"Implemented" describes software behavior, not an assertion of physical-media
validation. Oracle VirtualBox acceptance is deferred by the user.

| Requirement | Implementation / evidence | Remaining acceptance |
| --- | --- | --- |
| Native Ubuntu CLI and desktop, live USB | Qt application and Ubuntu 24.04 BIOS/UEFI ISO; released 0.11; QEMU boot and frozen workflow results | Rebuild after new milestones; actual VirtualBox demo |
| Normally deleted files, independent of demo filenames or references | Metadata recovery, ext4 historical inode maps, raw carving, Ubuntu Trash copies; 24 exact fresh-file recoveries across four filesystems | Public-corpus accuracy evaluation |
| File extent discovery, current-byte overwrite, metadata/history cleanup | FIEMAP and C direct I/O; offline FAT32/ext4/NTFS/exFAT global free-space, deleted metadata, journal/log/slack cleanup and preserved-file checks | Mounted-file erasure remains explicitly current-byte only; acquisition/offline cleanup required for history |
| SHA-256 per 4 KiB plus ssdeep | Streaming fingerprints in file/offline erasers; standalone `fingerprint`; native and independent recovered-byte similarity checks | New milestone full regression and distribution validation |
| Bifragment gap carving | Existing PNG chunk-boundary reconstruction | Extend inside data and to other proposed formats; public corpus |
| Validation, confidence and entropy | Isolated image/ZIP/PDF validators; structural scores | Add explicit entropy/completeness components and measured calibration |
| Controller capability discovery | Linux inventory; NVMe identify/namespaces; ATA IDENTIFY/HPA/DCO query | Expanded firmware execution adapters and immutable identity checks |
| NVMe sanitize | Allowlisted controller-wide submission, exclusive namespace opens, audited uncertain/accepted states | Spare physical controller validation; command acceptance is not certification |
| NVMe Format with cryptographic erase | Not yet implemented | Namespace scope/format preservation, execution and virtual NVMe test |
| ATA sanitize / Enhanced Secure Erase | Read-only discovery only | Capability parser, state/identity gates, commands and recovery receipts |
| HPA/DCO opening and post-wipe checks | Read-only discovery only; unknown is never absent | Explicit capacity-change transaction and read-back |
| HDD/USB/SD overwrite, discard and hidden-media distinction | Complete image/secondary virtual-disk overwrite and full logical readback | Guarded physical-device workflow and optional discard; physical media evaluation |
| Encrypted storage discovery and crypto erase | Real LUKS2 image keyslot removal, tested original-passphrase refusal | BitLocker/SED detection; external/cached keys remain outside local deletion |
| Independent verification | Required PhotoRec/TSK/bulk_extractor, output-byte comparison, completeness/resource gates, source continuity | Extend fuzzy findings to calibration and mutation measurements |
| Ed25519 JSON, audit chain, PDF and offline QR | Implemented, signatures/anchors and attached JSON validated | Rebuilt final artifacts |
| Closed-loop escalation | Failed result retained; expanded destructive scope requires a new exact confirmation | Explicit bounded same-scope retry coordinator |
| Safety | Device allowlist, typed identity, mounted/root/holder refusal, dry-run plans; generated-image/owned-VM tests only | Regression for each newly introduced hardware command |
| E1–E5 research evaluation | Real 1–8 GiB images and independent attackers; several mutation tests | Comparable deletion-method study, public Govdocs/DFRWS data, Foremost comparison, throughput/CPU report; physical methods require spare hardware |

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

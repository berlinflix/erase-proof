# EraseProof 0.11 — Ubuntu recovery and verified logical erasure

EraseProof is a native Qt desktop application with the same local engine exposed
through its CLI. Download the Ubuntu application archive or the separate live
ISO from [GitHub Releases](https://github.com/berlinflix/erase-proof/releases).

## Run in your installed Ubuntu VM

1. Extract `EraseProof-Ubuntu-x86_64-0.11.0.tar.gz` into your Ubuntu home folder.
2. Open a terminal inside the extracted `EraseProof` folder.
3. Run `bash install-runtime.sh`, then `./EraseProof`.

The archive includes Python, Qt, native filesystem/I/O helpers and the third
independent scanner. The installer obtains the remaining forensic/system tools
and Qt runtime libraries from Ubuntu. After installation, the application works
locally without a server. It also appears in Ubuntu's application menu.

The optional `EraseProof-Live-Ubuntu24.04-x86_64-0.11.0.iso` boots a separate
temporary Ubuntu environment. See [live-image instructions](LIVE-UBUNTU.md).
Actual Oracle VirtualBox acceptance remains deferred as requested by the user.

## What is available

- Ordinary deletion recovery through surviving filesystem metadata, historical
  ext4 journal inode maps and validated signature carving. Original files and
  predefined manifests are not required.
- Ubuntu Trash item/folder copies, including arbitrary unknown file formats,
  with SHA-256 measurements and unchanged originals.
- Whole-image overwrite, complete logical readback, required independent
  recovery attempts and signed evidence. Attached loop images are refused.
- Targeted offline FAT32/ext4/NTFS/exFAT cleanup that preserves unrelated
  allocated files and clears documented allocation/metadata/history regions.
- Current-byte file/folder overwrite and unlink, with an explicitly narrower
  assurance scope.
- Read-only partition/device discovery and a media decision matrix. NVMe
  ownership follows sysfs; unknown hidden-capacity checks stay unknown.
- Guarded NVMe sanitize submission and LUKS2 image keyslot removal, with scoped
  receipts and no physical erasure certificate.
- Ed25519 records, trusted signer checks, PDF/QR summaries with attached signed
  JSON, hash-chained audits, checkpoints and incomplete-job records.

The desktop starts on recovery. Offline files are selectable in a table, logical
and filesystem-history operations have separate tabs, long jobs run in background
workers, and recovered findings show unique-content counts.

## Validation and provenance

[Evaluation](EVALUATION.md) records real-driver tests with fresh random files,
atomic saves, prior versions and deleted backups. All six current files recovered
exactly on each 1 GiB FAT32/ext4/NTFS/exFAT image without references. Larger
targeted cases passed all three independent tools, full history readback and
preserved-file checks; exFAT was also exercised at 8 GiB.

The release workflow checks the source and standalone executable, signed
JSON/PDF/audit round trips, archive/source hygiene, library notices, extracted Qt
startup and actual live ISO boot. [Milestones](MILESTONES.md) gives the measured
state of those checks. `SHA256SUMS` covers release assets. The native archive
includes `BUILD-PACKAGES.txt`, `BUILD-SOURCE.json` and third-party notices. A
source-only checkout without Git records unknown provenance explicitly.

The delivered live ISO passed actual QEMU/KVM BIOS and UEFI boots with visually
reviewed desktops. Its expanded in-guest check also passed the complete frozen
workflow on Ubuntu 24.04, including FAT32/ext4/NTFS targeted cleanup and exact
preservation. No hard disks were attached. These are QEMU results; VirtualBox
acceptance has not been performed.

## Boundaries

Recovery cannot recreate overwritten, reused, discarded or unavailable encrypted
bytes. Carving and journal recovery have documented resource/fragment limits.
A zero score is bounded by the recorded references and current logical image.

This is not the entire physical-media research proposal. ATA destructive
adapters, Format NVM, HPA/DCO changes, ssdeep matching, broader arbitrary fragment
reconstruction, physical remanence experiments and independent NIST/IEEE
assessment are not delivered. Snapshots, external copies and host flash pages
are outside these records. Those limitations must remain visible when presenting
the project.

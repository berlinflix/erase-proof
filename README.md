# EraseProof — native Ubuntu software

EraseProof is a **local Linux tool**, with a native Qt desktop application, a CLI, real filesystem recovery, its own binary signature carver, direct file/device I/O, and signed verification evidence. It does not need a browser or web server.

Target: **Ubuntu x86-64 in Oracle VirtualBox**. Development and automated testing use Ubuntu 22.04 under WSL2. Ubuntu 22.04/24.04 desktop can run the source distribution; the Linux binary is built on Ubuntu 22.04. A VirtualBox hardware/device acceptance run is still required on your VM.

Get the application and optional bootable ISO from
[GitHub Releases](https://github.com/berlinflix/erase-proof/releases).
The [0.12 continuation guide](docs/RELEASE-0.12.md) and
[0.11 preview release guide](docs/RELEASE-0.11.md) cover installation, features,
validation and the physical-media research boundaries.

The [0.12.2 maintenance release](docs/RELEASE-0.12.2.md) fixes Evidence-page
selection, keyboard activation and signed JSON/PDF export, and adds confirmed
removal of independently verified zero-filled image files. It includes the
zero-only PhotoRec output correction. Use the new native archive; the older live
ISO contains the earlier application.

## Run the source distribution in Ubuntu

Copy/extract the project into your Ubuntu home directory, open a terminal there, and run:

```bash
bash scripts/setup-ubuntu.sh
bash scripts/launch-ubuntu.sh
```

Setup installs the real Ubuntu forensic/demo tools and creates an isolated Python environment. It adds an EraseProof entry to Ubuntu's application menu. Launch the desktop as your ordinary user for the image experiment.

The standalone Linux distribution, when supplied in `artifacts/`, contains a compiled launcher plus bundled Python/Qt libraries. Its README explains the remaining Ubuntu system-tool dependencies.

The optional [Ubuntu 24.04 live-image workflow](docs/LIVE-UBUNTU.md) builds a separate bootable environment. Its build/boot status is tracked in [milestones](docs/MILESTONES.md); Oracle VirtualBox acceptance remains deferred.

## The demonstration

1. **Experiment → Create FAT32 experiment.** `mkfs.fat` formats an actual 64 MiB image. `mcopy` puts a viewable PNG, a valid PDF, a ZIP and text into it. Their original SHA-256 values are recorded.
2. **Delete files normally.** `mdel` changes the real FAT32 directory entries and allocation table. It does not call EraseProof's overwriter or save an undo copy inside the image.
3. **Recover files → Scan & recover.** The Sleuth Kit's `fls`/`icat` recover deleted metadata entries. EraseProof's own carver independently scans supported signatures and validates extracted formats. Open the actual recovered files and compare hashes with the originals. Metadata and carved copies are deliberately separate findings.
4. **Erase & verify.** Choose the unattached experiment image and type its exact filename in the confirmation dialog. Attached loop images are refused before writing. The engine overwrites the actual image, flushes it with `fsync`, reads every logical byte back, checks native recovery/reference residues, and runs PhotoRec, Sleuth Kit and bulk_extractor. It issues an Ed25519 record only if the required checks pass.
5. Run recovery again. Supported signature candidates should be absent. Since the filesystem itself has been overwritten, filesystem parsing fails; this is reported explicitly, rather than counted as an independent clean forensic verdict.
6. **Evidence.** Inspect/export signed JSON, PDF/QR reports and an anchored audit export. Modified signed payloads fail validation. Expected signer fingerprints establish which operator key you trust.

The original sample files remain outside the experiment image as **ground truth**, so the recovery hashes can be checked. Erasing the experiment does not erase these intentional originals or previously extracted evidence.

Recovery also works with ordinary deletion outside this experiment. It requires
no original file list or manifest. [Normal-deletion validation](docs/ORDINARY-DELETION.md)
uses fresh, randomly named files deleted through mounted FAT32, ext4, NTFS and
exFAT drivers, including plain text and unknown file extensions. Ext4 journal
inode recovery complements signature carving when unlink has cleared current
allocation metadata.

For an ordinary Ubuntu file-manager **Move to Trash**, use **Browse Ubuntu
Trash** on Recover files. It copies existing Trash items, including unknown file
formats and folders, into a new output folder without changing the original.
[Trash recovery and permanent deletion](docs/UBUNTU-TRASH.md) explains the two
paths and the permissions needed to read a raw disk.

## CLI

```bash
source .venv/bin/activate
eraseproof doctor
eraseproof demo create ~/EraseProof/demo-01
eraseproof demo delete ~/EraseProof/demo-01
eraseproof recover ~/EraseProof/demo-01/experiment.img --output ~/EraseProof/recovered-01
eraseproof verify ~/EraseProof/demo-01/experiment.img --references ~/EraseProof/demo-01/manifest.json
eraseproof plan ~/EraseProof/demo-01/experiment.img
eraseproof erase ~/EraseProof/demo-01/experiment.img \
  --confirm experiment.img \
  --references ~/EraseProof/demo-01/manifest.json \
  --case ~/EraseProof/evidence-01
eraseproof audit ~/EraseProof/evidence-01
```

CLI results are JSON; progress goes to stderr. Verification uses exit code 2 for detected residue. Normal operational errors use 1. A standalone executable exposes the same CLI as `./EraseProof --cli ...`.

## Targeted file and folder operations

The native **Targeted erasure** page and CLI support these operations:

The desktop opens on **Recover files**. Device inventory can select a real disk
or partition for read-only recovery. In Targeted erasure, list an offline image,
select its file or folder in the table, and inspect the plan before confirming.

- `file-plan` / `erase-files`: pin each ordinary file's identity, overwrite and read back its current bytes, then unlink. Symlinks, hard links, protected system paths, cross-device trees and evidence inside the target are refused. The signed record explicitly excludes journals, snapshots and previous copies.
- `fat32-list` / `fat32-plan` / `fat32-erase`: validate an offline FAT32 volume image, remove selected allocation, and clear all free clusters, inactive directory records and file slack. Preserved-file hashes, `fsck.fat -n`, full history readback and independent attacks must pass. This removes other deleted history on the volume. See [FAT32 scope and validation](docs/OFFLINE-FAT32.md).
- `ext4-plan` / `ext4-erase`: use the C/libext2fs adapter to remove an internal image file/folder, clear all unallocated blocks and unused inodes, scrub directory slack and inactive journal payload, and hash-check unrelated allocated files. Both pre/post `e2fsck -fn` checks must pass. This also removes other deleted-file history on that volume. See [ext4 scope and supported features](docs/OFFLINE-EXT4.md).
- `ntfs-list` / `ntfs-plan` / `ntfs-erase`: remove a selected NTFS image file/folder with its named data streams, clear free clusters and MFT/index/log/USN history, and hash-check preserved user streams. Both pre/post consistency checks and complete free-cluster/USN readback must pass. This removes other deleted history on the volume. See [NTFS scope and validation](docs/OFFLINE-NTFS.md).
- `exfat-list` / `exfat-plan` / `exfat-erase`: validate exFAT allocation ownership, remove a selected path, and clear all free clusters, inactive directory records, stale free FAT links and stream slack. Preserved-file hashes, `fsck.exfat -n`, and full history readback must pass. See [exFAT scope and validation](docs/OFFLINE-EXFAT.md).

```bash
eraseproof file-plan /path/to/selected-folder
eraseproof erase-files /path/to/selected-folder --confirm selected-folder --case ~/EraseProof/evidence-files
eraseproof fat32-list ~/EraseProof/demo-01/experiment.img
eraseproof fat32-erase ~/EraseProof/demo-01/experiment.img /REPORT.PDF \
  --confirm experiment.img:/REPORT.PDF --case ~/EraseProof/evidence-targeted
```

Offline cleanup is bounded to the selected filesystem image and reference evidence. It does not imply removal of host snapshots or physical flash remnants.

The [native C I/O component](docs/NATIVE-IO.md) provides aligned `O_DIRECT` writes
for image and current-file erasure, explicit buffered tails, bounded FIEMAP
inventory, and separately gated ioctl primitives. Actual I/O counts are recorded.

## Expanded forensic recovery

The native carver recognizes PNG, PDF, JPEG, ZIP/Office, GIF, BMP, WAV/AVI, Ogg, MP4, SQLite, RTF, ELF, 7z, gzip and tar. Image decoding, strict PDF parsing, SQLite quick-check and ZIP CRC validation run in separate processes with CPU, memory and time limits. Other families report container-level checks; a score is an evidence heuristic, not a probability. Files are never executed. Candidates are limited to 256 MiB.

`--fragments` (also accepting the earlier `--fragmented-png` spelling) adds bounded
PNG/ZIP/PDF/JPEG bifragment search. It uses complete checksums where available,
decoder diagnostics and structural offsets. Reconstruction without a checksum
remains uncertain. See the public corpus measurements and search limits in the
[0.12 guide](docs/RELEASE-0.12.md). Arbitrary fragmentation remains outside the
algorithm's guarantee.

```bash
eraseproof partitions /path/to/disk.img
eraseproof recover /path/to/disk.img --sector-offset 2048 --output ~/EraseProof/recovered
eraseproof attack /path/to/disk.img --sector-offset 2048 --output ~/EraseProof/independent
```

The desktop offers partition discovery and offset selection. Primary MBR/GPT entries are checked for bounds and overlap; GPT header and entry-array CRCs are verified. Extended MBR partitions require manual offsets. Carving covers the whole source regardless of metadata offset. Independent reports preserve actual PhotoRec/Sleuth Kit/bulk_extractor results, extracted files/features, logs, missing tools, timeouts and parsing failures. An unrecognized wiped filesystem is incomplete metadata coverage. The [independent certification gate](docs/ATTACK-VERIFICATION.md) documents required completion, source integrity, limits and signed report digests.

## Actual secondary virtual disks

The core also contains a gated logical-overwrite path for a **recognized, unmounted secondary virtual disk**. It refuses mounted disks/children, read-only disks, partitions, missing serials, and unrecognized physical-drive models. It checks target identity, locks the opened target and requires both the allowlisted path and exact serial.

```bash
eraseproof devices
# Only after identifying a DISPOSABLE, UNMOUNTED secondary virtual disk:
sudo .venv/bin/eraseproof plan /dev/sdb --allow-device /dev/sdb --confirm EXACT_SERIAL
sudo .venv/bin/eraseproof erase /dev/sdb --allow-device /dev/sdb \
  --confirm EXACT_SERIAL --case /home/YOUR_USER/EraseProof/virtual-disk-evidence
```

Device names are examples, not instructions to choose `/dev/sdb` blindly. The
raw-device route passed a disposable QEMU secondary-disk test: exact recovery of
a fresh unknown-format file, unchanged source during recovery, 64 MiB of actual
direct writes, signed evidence and complete zero readback from outside the guest.
An actual VirtualBox secondary-disk overwrite remains deferred. The desktop runs
unprivileged and does not silently escalate permissions. See the
[virtual-disk acceptance notes](docs/VIRTUALBOX-DEMO.md).

## Assurance and remaining work

The **Media methods** page and CLI inspect native NVMe/ATA capabilities and software LUKS2 images. Guarded native adapters implement NVMe sanitize/Format, ATA sanitize/Enhanced Secure Erase and explicitly confirmed HPA/DCO expansion. Their signed firmware receipts distinguish command completion from independently verified erasure. LUKS2 keyslot removal has been tested on a real generated image. See [media operations and boundaries](docs/MEDIA.md) for capability, identity and scope requirements.

This release implements native recovery, logical overwrite, guarded firmware methods and independent recovery verification. A VM cannot prove physical SSD/NVMe sanitization on the host. VirtualBox snapshots, the host's image history, storage caches and physical FTL remanence are outside its evidence scope.

`media-plan TARGET` supplies the read-only method matrix used by the desktop,
including executable commands, capability failures, hidden-capacity gates and
unavailable methods. Bounded PNG/ZIP/PDF/JPEG bifragment reconstruction and public
corpus measurements are included. Physical-media evaluation and independently
assessed standards conformance remain unverified. There is no claim that this
release securely deletes every copy of a host file or fulfills NIST/IEEE
sanitization requirements.

Metadata recovery uses the real Sleuth Kit. The carver streams large sources in chunks; candidates are bounded to 256 MiB. PNG/ZIP checksums, bounded image decoding and strict PDF parsing provide format-specific evidence. Container-only checks are labelled. Confidence is a heuristic; it is not a probability or proof of semantic correctness.

RRS is available only with reference evidence: `(matched known block hashes + matched metadata patterns) / total known references`. The FAT32 experiment fingerprints aligned 512-byte sectors and deleted-name residues. Unknown inputs show RRS as unavailable. Whole-image certificates require complete zero read-back. File/folder and FAT32 records state their narrower byte/allocation scope explicitly.

Ed25519 keys require private Linux file permissions. SQLite commits signed records and their audit event together. Trusted fingerprint checks, signed checkpoints and the PDF's authoritative JSON attachment are explained in [evidence verification](docs/EVIDENCE.md). Preserve checkpoints independently to detect local history truncation.

Cancellation of a real overwrite is **not reversible**: the target may be partially overwritten. Such a job is logged as incomplete and never certified. Recovery output must be separate from a raw source disk; exclusive output creation prevents overwriting existing extracted files.

## Development

```bash
bash scripts/setup-ubuntu.sh
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q
```

Mounted-driver exFAT tests additionally need an isolated root mount namespace;
CI runs these with `unshare --mount --propagation private` and
`ERASEPROOF_TEST_PRIVATE_MOUNTS=1`. They use only newly generated loop images.

Tests exercise real FAT32 creation/deletion, TSK recovery with byte-for-byte SHA comparisons, native carving, overwrite/read-back, cancellation, signature tampering, audit tampering, virtual-disk safety guards and the native Qt background-job workflow. Source: [Sleuth Kit fls](https://www.sleuthkit.org/sleuthkit/man/fls.html), [icat](https://www.sleuthkit.org/sleuthkit/man/icat.html), [Qt for Python](https://doc.qt.io/qtforpython-6/).


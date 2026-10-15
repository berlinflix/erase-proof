# EraseProof — native Ubuntu software

EraseProof is a **local Linux tool**, with a native Qt desktop application, a CLI, real filesystem recovery, its own binary signature carver, direct file/device I/O, and signed verification evidence. It does not need a browser or web server.

Target: **Ubuntu x86-64 in Oracle VirtualBox**. Development and automated testing use Ubuntu 22.04 under WSL2. Ubuntu 22.04/24.04 desktop can run the source distribution; the Linux binary is built on Ubuntu 22.04. A VirtualBox hardware/device acceptance run is still required on your VM.

## Run the source distribution in Ubuntu

Copy/extract the project into your Ubuntu home directory, open a terminal there, and run:

```bash
bash scripts/setup-ubuntu.sh
bash scripts/launch-ubuntu.sh
```

Setup installs the real Ubuntu forensic/demo tools and creates an isolated Python environment. It adds an EraseProof entry to Ubuntu's application menu. Launch the desktop as your ordinary user for the image experiment.

The standalone Linux distribution, when supplied in `artifacts/`, contains a compiled launcher plus bundled Python/Qt libraries. Its README explains the remaining Ubuntu system-tool dependencies.

## The demonstration

1. **Experiment → Create FAT32 experiment.** `mkfs.fat` formats an actual 64 MiB image. `mcopy` puts a viewable PNG, a valid PDF, a ZIP and text into it. Their original SHA-256 values are recorded.
2. **Delete files normally.** `mdel` changes the real FAT32 directory entries and allocation table. It does not call EraseProof's overwriter or save an undo copy inside the image.
3. **Recover files → Scan & recover.** The Sleuth Kit's `fls`/`icat` recover deleted metadata entries. EraseProof's own carver independently scans supported signatures and validates extracted formats. Open the actual recovered files and compare hashes with the originals. Metadata and carved copies are deliberately separate findings.
4. **Erase & verify.** Choose the experiment image and type its exact filename in the confirmation dialog. The engine overwrites the actual image, flushes it with `fsync`, reads every logical byte back, scans for carving signatures and known reference residues, and issues an Ed25519 record only if all checks pass.
5. Run recovery again. Supported signature candidates should be absent. Since the filesystem itself has been overwritten, filesystem parsing fails; this is reported explicitly, rather than counted as an independent clean forensic verdict.
6. **Evidence.** Inspect/export signed JSON, PDF/QR reports and an anchored audit export. Modified signed payloads fail validation. Expected signer fingerprints establish which operator key you trust.

The original sample files remain outside the experiment image as **ground truth**, so the recovery hashes can be checked. Erasing the experiment does not erase these intentional originals or previously extracted evidence.

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

The native **Targeted erasure** page and CLI support two distinct operations:

- `file-plan` / `erase-files`: pin each ordinary file's identity, overwrite and read back its current bytes, then unlink. Symlinks, hard links, protected system paths, cross-device trees and evidence inside the target are refused. The signed record explicitly excludes journals, snapshots and previous copies.
- `fat32-list` / `fat32-erase`: edit an offline, unattached FAT32 volume image. The engine validates both FAT copies and allocation chains, erases selected file/folder clusters and long/short directory records, searches free clusters for known sector copies, and preserves unrelated live files. Tests run `fsck.fat` and byte-match preserved files after the operation.

```bash
eraseproof file-plan /path/to/selected-folder
eraseproof erase-files /path/to/selected-folder --confirm selected-folder --case ~/EraseProof/evidence-files
eraseproof fat32-list ~/EraseProof/demo-01/experiment.img
eraseproof fat32-erase ~/EraseProof/demo-01/experiment.img /REPORT.PDF \
  --confirm experiment.img:/REPORT.PDF --case ~/EraseProof/evidence-targeted
```

FAT32 cleanup is bounded to known image allocation and reference evidence. It does not imply ext4/NTFS journal cleanup or physical flash sanitization.

## Expanded forensic recovery

The native carver recognizes PNG, PDF, JPEG, ZIP/Office, GIF, BMP, WAV/AVI, Ogg, MP4, SQLite, RTF, ELF, 7z, gzip and tar. Image decoding, strict PDF parsing, SQLite quick-check and ZIP CRC validation run in separate processes with CPU, memory and time limits. Other families report container-level checks; a score is an evidence heuristic, not a probability. Files are never executed. Candidates are limited to 256 MiB.

`--fragmented-png` reconstructs one PNG gap at a chunk boundary within 64 KiB and checks all reconstructed CRCs. Arbitrary fragmentation remains outside this algorithm.

```bash
eraseproof partitions /path/to/disk.img
eraseproof recover /path/to/disk.img --sector-offset 2048 --output ~/EraseProof/recovered
eraseproof attack /path/to/disk.img --sector-offset 2048 --output ~/EraseProof/independent
```

The desktop offers partition discovery and offset selection. Primary MBR/GPT entries are checked for bounds and overlap; GPT header and entry-array CRCs are verified. Extended MBR partitions require manual offsets. Carving covers the whole source regardless of metadata offset. Independent reports preserve actual PhotoRec/Sleuth Kit results, extracted files, logs, missing tools, timeouts and parsing failures. An unrecognized wiped filesystem is incomplete metadata coverage.

## Actual secondary virtual disks

The core also contains a gated logical-overwrite path for a **recognized, unmounted secondary virtual disk**. It refuses mounted disks/children, read-only disks, partitions, missing serials, and unrecognized physical-drive models. It checks target identity, locks the opened target and requires both the allowlisted path and exact serial.

```bash
eraseproof devices
# Only after identifying a DISPOSABLE, UNMOUNTED secondary virtual disk:
sudo .venv/bin/eraseproof plan /dev/sdb --allow-device /dev/sdb --confirm EXACT_SERIAL
sudo .venv/bin/eraseproof erase /dev/sdb --allow-device /dev/sdb \
  --confirm EXACT_SERIAL --case /home/YOUR_USER/EraseProof/virtual-disk-evidence
```

Device names are examples, not instructions to choose `/dev/sdb` blindly. Device writes have policy tests; an actual VirtualBox secondary-disk overwrite has not been run in this environment. Use the default filesystem-image demonstration until that acceptance test is completed. The desktop runs unprivileged and does not silently escalate permissions.

## Assurance and remaining work

The **Media methods** page and CLI inspect native NVMe/ATA capabilities and software LUKS2 images. A guarded CLI adapter can submit controller-wide NVMe block/crypto sanitize with all-namespace checks, but returns an audited firmware receipt rather than an erasure certificate. LUKS2 keyslot removal has been tested on a real generated image. See [media operations and boundaries](docs/MEDIA.md) before using hardware commands. ATA destructive commands and HPA/DCO changes remain disabled.

This release implements **logical overwrite and recovery verification**, not the entire research proposal. A VM cannot prove physical SSD/NVMe sanitization on the host. VirtualBox snapshots, the host's image history, storage caches and physical FTL remanence are outside its evidence scope.

Open research work includes ext4/NTFS/exFAT targeted journal/history cleanup, ATA destructive adapters, HPA/DCO changes, arbitrary fragment reconstruction, physical-media evaluation and independently assessed standards mapping. There is no claim that this release securely deletes every copy of a host file or fulfills NIST/IEEE sanitization requirements.

Metadata recovery uses the real Sleuth Kit. The carver streams large sources in chunks; candidates are bounded to 256 MiB. PNG/ZIP checksums, bounded image decoding and strict PDF parsing provide format-specific evidence. Container-only checks are labelled. Confidence is a heuristic; it is not a probability or proof of semantic correctness.

RRS is available only with reference evidence: `(matched known block hashes + matched metadata patterns) / total known references`. The FAT32 experiment fingerprints aligned 512-byte sectors and deleted-name residues. Unknown inputs show RRS as unavailable. Whole-image certificates require complete zero read-back. File/folder and FAT32 records state their narrower byte/allocation scope explicitly.

Ed25519 keys require private Linux file permissions. SQLite commits signed records and their audit event together. Trusted fingerprint checks, signed checkpoints and the PDF's authoritative JSON attachment are explained in [evidence verification](docs/EVIDENCE.md). Preserve checkpoints independently to detect local history truncation.

Cancellation of a real overwrite is **not reversible**: the target may be partially overwritten. Such a job is logged as incomplete and never certified. Recovery output must be separate from a raw source disk; exclusive output creation prevents overwriting existing extracted files.

## Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[desktop,test]'
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q
```

Tests exercise real FAT32 creation/deletion, TSK recovery with byte-for-byte SHA comparisons, native carving, overwrite/read-back, cancellation, signature tampering, audit tampering, virtual-disk safety guards and the native Qt background-job workflow. Source: [Sleuth Kit fls](https://www.sleuthkit.org/sleuthkit/man/fls.html), [icat](https://www.sleuthkit.org/sleuthkit/man/icat.html), [Qt for Python](https://doc.qt.io/qtforpython-6/).


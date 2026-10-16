# EraseProof 0.12

This continuation implements the original proposal's remaining firmware and
forensic software paths. It is native Ubuntu x86-64 software, with a Qt desktop,
CLI and separate bootable Ubuntu 24.04 live environment. Oracle VirtualBox
acceptance remains deferred; spare physical-media evaluation is not represented
as complete.

## Run in your Ubuntu VM

Download `EraseProof-Ubuntu-x86_64-0.12.0.tar.gz` from
[GitHub Releases](https://github.com/berlinflix/erase-proof/releases) and extract
it into your Ubuntu home folder. Open a terminal in the extracted `EraseProof`
folder, then run:

```bash
bash install-runtime.sh
./EraseProof
```

The app also appears in Ubuntu's application menu. Begin on **Recover files**:
use **Browse Ubuntu Trash** for files moved to Trash, or select the unmounted
disk/image for permanent-deletion recovery. Recovered files go to a separate
destination. Neither route requires an original-file manifest.

The optional live ISO boots a temporary Ubuntu session with its dependencies
included. Export evidence before shutdown. See [live-image instructions](LIVE-UBUNTU.md)
and the [VirtualBox demonstration](VIRTUALBOX-DEMO.md).

## Changes

- Streaming ssdeep plus SHA-256/4 KiB fingerprints, retained 512-byte references,
  edited-version matching in native/independent outputs and preservation checks.
- Bounded PNG/ZIP/PDF/JPEG bifragment reconstruction. ZIP central-directory and
  PDF xref offsets infer gaps; JPEG decoder diagnostics prioritize sector pairs.
  PNG/ZIP require complete checksum-valid contents; checksum-free PDF/JPEG
  reconstruction is capped at 60/100 and remains explicitly uncertain.
- Explainable per-carving validation/completeness/entropy evidence. Confidence
  is structural evidence, not a calibrated probability of original-byte identity.
- Separate resource-limited fragment workers with read-only pinned descriptors
  and dropped root privileges; bounded searches retain ordinary recovery findings.
- Restricted C NVMe admin and ATA SG_IO adapters, native controller identity,
  format-preserving Format NVM, ATA sanitize/Enhanced Secure Erase, explicit
  HPA/DCO expansion and post-command checks.
- Private persisted ATA recovery credentials before security changes, explicit
  recovery after interruption, and no credentials in argv/audit/stdout.
- Confirmed NVMe/ATA erase/attack/escalate/certify workflows; incomplete
  status/attacks, stale ATA sanitize success and changed identity/capacity stop
  without automatic retry. Identity is checked again after recovery attacks.
- Allowlisted host-visible disk overwrite and separate discard receipts; boot,
  mounted, swap, read-only and holder checks remain required.
- Read-only LUKS/BitLocker signatures, partition signatures and bounded TCG Level 0
  discovery for device-reported self-encryption; unknown stays unknown.
- Erasure certificates require zero RRS and completed independent attacks.
  Other successful scoped work is explicitly an operation receipt. Signed records
  include method/standards references without claiming conformance certification.
- Native media method selection, status inspection and shell-quoted command copy.
- PhotoRec provisional-output rename handling, caught by the public corpus run.

## Measured evidence

The [DFRWS 2006 comparison](validation/dfrws-0.12.json) records the verified
organizer image/archive hashes and unchanged source. EraseProof's contiguous
baseline recovered 8 of 32 exact originals; the bounded fragment pass recovered
10, PhotoRec 15 and Foremost 6. Search limits and nonexact outputs are retained.
Embedded files and partial reconstructions count as nonexact in this strict
original-file-hash metric. Unsupported original file types remain in the recall
denominator. These figures are not a promise of universal fragmented recovery.

All **216 tests passed** on final committed source `3302845` in a private root
mount namespace. GitHub CI also passed. The final unknown-sanitize-status guard
passed all 36 focused firmware/workflow checks.
The standalone executable passed fresh PNG/JPEG reconstruction,
independent ssdeep agreement, recovery/erasure, filesystem preservation, trusted
signatures, attached PDF evidence, anchored audit and native Qt startup.

The [public Govdocs comparison](validation/govdocs-0.12.json) completed all 16
method/filesystem cases using 12 public files on actual 1 GiB FAT32/ext4/NTFS/exFAT
mounts. All four EraseProof cases had zero measured target references and passed
independent attacks, with the unrelated file preserved. Normal deletion, shred
and single-file overwrite retained measured history in this activity scenario.
The [confidence buckets](validation/confidence-0.12.json) retain exact original-byte
match counts per structural score range, without claiming probability calibration.

[Overhead measurements](validation/overhead-0.12.json) record dd with two flush
schedules, C direct I/O and the full signed erasure/verification pipeline on a
generated 1 GiB file. The full pipeline took 128.046 seconds in this concurrent
WSL run; approximately 19.4% followed the first verification callback. These are
single-run figures affected by the host, cache, allocation and concurrent work.
The final validation manifest separately records live/virtual-device acceptance.

## Boundaries

No software can recover bytes that have been overwritten or discarded, or prove
flash-cell/chip-off erasure solely by scanning host-visible sectors. Raw carving
has format, candidate size, gap, resource and ambiguity limits. Metadata recovery
depends on surviving allocation information; unknown formats can be recovered
through metadata and Trash without a predefined manifest.

Mounted-file erasure verifies current logical bytes; filesystem history requires
the separate offline volume workflow. Snapshots, backups, external key/header
copies, cached keys and live copies outside the confirmed scope require separate
handling. Firmware success and TCG features are device reports, not independently
validated physical assurance. Physical media, standards conformance and the user's
VirtualBox demo remain separate acceptance work.

# EraseProof 0.12

This continuation implements the original proposal's remaining firmware and
forensic software paths. It is native Ubuntu x86-64 software, with a Qt desktop,
CLI and separate bootable Ubuntu 24.04 live environment. Oracle VirtualBox
acceptance remains deferred; spare physical-media evaluation is not represented
as complete.

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
- Confirmed controller-wide erase/attack/escalate/certify workflows; incomplete
  status/attacks and changed identity stop without automatic retry.
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

The focused firmware, interruption, signature, workflow, native UI and fragment
tests and the full root/private-mount regression are recorded in the final
validation manifest. The public Govdocs sample comparison uses actual 1 GiB
FAT32/ext4/NTFS/exFAT mounts, identical create/atomic-save/backup/delete activity
and independent post-method attacks. Completion evidence is added after those
experiments finish.

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

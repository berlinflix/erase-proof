# EraseProof 0.12.2 — Evidence interaction and verified-image cleanup

The Evidence page now reliably selects one full record row, keeps the selection
visible after focus moves, and opens details with double-click or either Enter
key. View, signed JSON export and PDF/QR export use the complete selected
certificate ID. Refresh preserves that ID when records are added or reordered;
clearing selection disables the dependent actions and gives instructions.
Read-only Evidence browsing remains usable during background storage jobs.

**Delete overwritten image file…** removes the entire zero-filled image after
explicit filename confirmation and a fresh complete zero/hash/identity check.
It requires a signed successful whole-image overwrite record and completed
independent verification. Devices, attached images, symlinks, hard links,
changed files and evidence files are refused. Signed records, signing keys,
audit history, recovered outputs and reference originals are kept.

This release also includes the earlier fix for all-zero PhotoRec outputs after
complete image zero readback. Nonzero content, matching references, incomplete
scanner results or source changes continue to block verification. No recovery,
overwrite, device-safety, signing or certificate-verification algorithm was
changed for the Evidence UI fix.

## Installation

Download the native archive, source archive and SHA256SUMS from this release.
Check them with `sha256sum --check SHA256SUMS`. Extract the complete native
bundle into a new directory, install missing system tools with
`bash install-runtime.sh`, and launch `./EraseProof`.

Preserve your existing `~/EraseProof/evidence` directory, operator key and
checkpoints. Normal launch continues to use that workspace. Do not regenerate
keys or reset the database when upgrading. Whole-image records remain valid
after the optional removal of their overwritten image file.

The public release workflow builds on Ubuntu 22.04 for Ubuntu x86-64 desktops.
Locally prepared bundles identify their actual build platform in
BUILD-SOURCE.json; the local validation host was Ubuntu 26.04 LTS.
No live ISO is refreshed for this maintenance release.

## Validation and boundaries

The Evidence correction passed 245 source tests and 13 subtests, including all
27 new regression cases. Ten root/private-mount tests were skipped in the
restricted local session. Source and actual frozen executable passed eight UI
interaction groups: real viewport clicks, highlight checks, details dialogs,
real Qt JSON/PDF save dialogs, signature/audit preservation, stable-ID refresh,
keyboard navigation, background-job safety locks, both requested window sizes,
and confirmed disposable-image removal. The existing frozen acceptance workflow
and extracted archive verification also passed.

The release workflow repeats source, privileged filesystem, frozen executable,
Evidence interaction and extracted-package checks before publishing. Validation
logs and build provenance are attached in the validation archive.

Manual Oracle VirtualBox GUI acceptance remains unverified: the local execution
sandbox could not access the desktop display. Qt input tests used the offscreen
platform and exercised actual widgets and modal dialogs, not startup alone.
Physical media, snapshots, host image history and flash remnants remain outside
the demonstrated logical scope. Removing the image file does not remove other
copies or establish physical sanitization or standards compliance.

See [the detailed investigation](EVIDENCE-UI-FIX.md) for confirmed causes,
changed files, regression coverage and reproducible commands.

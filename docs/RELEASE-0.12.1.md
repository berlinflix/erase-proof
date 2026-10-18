# EraseProof 0.12.1 — verification maintenance release

Whole-image erasure can now complete verification when PhotoRec emits files
containing only zero bytes after every source byte has been read back as zero.
Version 0.12.0 rejected that result even when the full overwrite and required
scanners completed successfully.

The gate preserves every recovered file, its hash, the raw recovered-file count,
the count of nonzero bytes, and the original filesystem parser error. Any nonzero
recovered content, target-reference match, incomplete inventory, failed scanner,
or source mutation still prevents certification. This exception requires complete
zero readback and applies to the whole-image verification path.

The native NTFS adapter also builds with newer ntfs-3g headers by explicitly
including the required time declarations.

## Downloads and upgrade

Download `EraseProof-Ubuntu-x86_64-0.12.1.tar.gz`,
`EraseProof-source-0.12.1.zip`, and `SHA256SUMS` from
[GitHub Releases](https://github.com/berlinflix/erase-proof/releases/tag/v0.12.1).
Check the downloads with `sha256sum --check SHA256SUMS`. The published native
archive is built on Ubuntu 22.04 for Ubuntu x86-64 desktop installations.

Extract the native archive into a new folder. Run `bash install-runtime.sh` if
runtime tools are missing, then launch `./EraseProof`. Keep your existing
experiments, recovered files, evidence, operator keys, and audit checkpoints.
For an existing installation, replace its application bundle while preserving
those data folders. Check `./EraseProof --cli --version` reports `0.12.1`.

This maintenance release contains the native application and source archive.
The v0.12.0 live ISO contains the earlier application and has not been refreshed
for this fix.

## Validation

The corrected 0.12.0 source passed 218 ordinary tests (13 subtests), followed by
all 11 privileged disposable-image tests on Ubuntu 26.04. Its frozen executable
passed recovery of all four original demo files, 64 MiB of direct overwrite,
complete zero readback, the independent recovery gate, signed JSON and PDF
verification, anchored audit, FAT32/ext4/NTFS preservation, fragment recovery,
and offscreen Qt startup. PhotoRec produced 819 zero-only files and no nonzero
recovered files. GitHub's Linux engine and native desktop CI also passed for
commit `5d182c40e369d7b5aaa51c84f419b88f98547999`.

The 0.12.1 release workflow reruns the source suite, privileged filesystem tests,
frozen executable workflow, archive checksums, extracted CLI, and offscreen Qt
startup on Ubuntu 22.04 before publishing. CI validation logs accompany the
release as `validation-0.12.1.zip`. `BUILD-SOURCE.json` inside the native archive
records the exact source commit and build platform.

Oracle VirtualBox acceptance and physical-media sanitization remain outside
this maintenance validation. Logical overwrite does not establish removal of
snapshots, host image history, or physical flash remnants.

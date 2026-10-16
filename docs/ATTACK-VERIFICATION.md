# Independent certification gate

Whole-image overwrite and the shared FAT32/ext4/NTFS/exFAT offline coordinator require
PhotoRec, Sleuth Kit and bulk_extractor before issuing a verification record.
Dependency checks run before the first destructive write. Ordinary logical file
overwrite retains its narrower current-byte scope and excludes volume history.

The native verifier first checks the current logical image and target references.
The independent tools then receive the same pinned source descriptor. Both image
identity and size are checked before launching them. The source hash must match
the native verifier's result before and after the independent attack. Output on
the source disk is refused for block devices.

The gate compares actual extracted files and decoded features with SHA-256 block
references, head/tail/name samples and whole-file hashes. Unrelated recovered
files do not count as target residues. Identical retained target copies prevent
a successful targeted record. Features are listed separately from recovered
original files. A Base64-encoded JPEG test demonstrates bulk_extractor recovering
an exact target that raw signature carving misses.

## Completion, limits and evidence

PhotoRec and bulk_extractor must complete. Filesystem-preserving operations also
require successful Sleuth Kit metadata coverage. After whole-image overwrite,
the absence of a readable filesystem is expected: a completed exhaustive zero
readback can supersede metadata parsing. The exact parser failure remains in
the report. A timeout or unavailable tool does not become a clean result.

bulk_extractor's zero exit code alone is insufficient. Its bounded XML report
must parse, report the full source byte count and contain no reported exceptions
or scanner errors. Truncated, missing, malformed and incomplete reports fail the
gate. The original report and its SHA-256 are retained.

External processes run under prlimit with a 2 GiB address-space cap, 256 MiB
per-output-file limit and CPU/wall budgets. Output is monitored against an 8 GiB,
10,000-file ceiling. Metadata attacks share a wall-time budget. Workers run in
separate process groups so cancellation/timeout terminates their child processes.
Limits are explicit coverage boundaries: exceeding one refuses certification.
They do not claim exhaustive decoding of every compressed or encrypted format.

The case preserves extracted output, stdout/stderr logs, tool statuses, match
findings and a JSON report. Its digest and extracted-file hashes enter the signed
record. Incomplete jobs retain audit evidence and receive no successful record.

## Native pattern scanning

The carver uses a C-backed Aho-Corasick automaton. Latin-1 conversion preserves
binary byte offsets, including non-ASCII values. Chunk overlap preserves
boundary matches. Reference matching uses the same automaton for larger sets
and C-level byte search for small sets with repeated single-byte patterns.
Excessive signature or reference hits stop with an explicit incomplete-scan
error; they never produce a clean verdict.

## Building the third scanner

`scripts/build-forensic-tools.sh` downloads the pinned upstream 2.2.0 source
archive, verifies its SHA-256, builds without E01 support and runs upstream
`make check`. The native bundle collects the executable and its shared-library
dependencies. E01 is outside EraseProof's raw-source interface. Source setup and
CI run the same build recipe; the source archive includes the recipe and license
notices, while the executable is supplied in the native distribution.

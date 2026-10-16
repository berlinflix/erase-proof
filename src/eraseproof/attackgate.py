"""Independent recovered-byte checks required before image certification."""
import hashlib
import json
from pathlib import Path
import shutil

from .models import EraseProofError

from .carve import CHUNK, checkpoint
from .matching import Matcher


def scan_file(path, refs, cancel=None):
    block_size = refs["block_size"]
    hashes = set(refs["block_hashes"])
    zero_block = bytes(block_size)
    patterns = [bytes.fromhex(pattern) for pattern in refs["metadata_patterns"]]
    matcher = Matcher(patterns)
    overlap = max([block_size-512, *(len(pattern)-1 for pattern in patterns)])
    blocks, metadata, carry, offset, sha = set(), set(), b"", 0, hashlib.sha256()
    with Path(path).open("rb") as source:
        while data := source.read(CHUNK):
            checkpoint(cancel)
            sha.update(data)
            window, base = carry+data, offset-len(carry)
            if hashes:
                for at in range((-base) % 512, len(window)-block_size+1, 512):
                    block = window[at:at+block_size]
                    if block != zero_block and (value := hashlib.sha256(block).hexdigest()) in hashes:
                        blocks.add(value)
            metadata.update(index for _, index in matcher.first(window))
            carry = window[-overlap:] if overlap else b""
            offset += len(data)
    digest = sha.hexdigest()
    return {"sha256": digest, "bytes": offset, "block_hashes": sorted(blocks),
            "metadata_indices": sorted(metadata), "full_file_match": digest in refs.get("file_hashes", [])}


def require_tools():
    from .independent import bulk_tool
    missing = [tool for tool in ("photorec", "fls", "icat", "prlimit") if not shutil.which(tool)]
    if not bulk_tool():
        missing.append("bulk_extractor (scripts/build-forensic-tools.sh)")
    if missing:
        raise EraseProofError("Independent certification tools are missing: "+", ".join(missing)+". Install the Ubuntu runtime dependencies before erasing.")


def check(path, output_dir, refs, *, stream, length, expected_sha256, zero_readback=False, progress=None, cancel=None):
    from .engine import hash_stream, validate_references
    from .independent import attack
    refs = validate_references(refs)
    before = hash_stream(stream, length, cancel)
    if before != expected_sha256:
        raise EraseProofError("Source changed after native verification. Certification refused.")
    report = attack(path, output_dir, progress=progress, cancel=cancel, stream=stream)
    tools = {tool["tool"]: tool for tool in report["tools"]}
    carving_ok = tools.get("PhotoRec", {}).get("status") == "completed"
    metadata_ok = tools.get("Sleuth Kit", {}).get("status") == "completed"
    features_ok = tools.get("bulk_extractor", {}).get("status") == "completed"
    metadata_superseded = bool(zero_readback and tools.get("Sleuth Kit", {}).get("status") == "filesystem-unrecognized-or-error")
    matches, blocks, metadata, files = [], set(), set(), set()
    for tool in report["tools"]:
        for entry in tool.get("files", []):
            checkpoint(cancel)
            measured = scan_file(entry.get("path", entry.get("output")), refs, cancel)
            blocks.update(measured["block_hashes"])
            metadata.update(measured["metadata_indices"])
            if measured["full_file_match"]:
                files.add(measured["sha256"])
            entry.update({"sha256": measured["sha256"], "target_residue": bool(measured["block_hashes"] or measured["metadata_indices"] or measured["full_file_match"])})
            if entry["target_residue"] and len(matches) < 1000:
                matches.append({"tool": tool["tool"], "path": entry.get("path", entry.get("output")), **measured})
    after = hash_stream(stream, length, cancel)
    if before != after:
        raise EraseProofError("Source changed during the independent attack. Certification refused.")
    report_path = Path(output_dir)/"attack.json"
    report_path.write_text(json.dumps(report, indent=2)+"\n")
    count = len(blocks)+len(metadata)+len(files)
    no_recovery_after_zero = not zero_readback or report["recovered_files"] == 0
    return {"passed": carving_ok and features_ok and (metadata_ok or metadata_superseded) and count == 0 and no_recovery_after_zero,
            "required_tools": {tool: tools.get(tool, {}).get("status") for tool in ("PhotoRec", "Sleuth Kit", "bulk_extractor")},
            "metadata_gate": "superseded-by-complete-zero-readback" if metadata_superseded else "required-filesystem-parse",
            "target_reference_matches": count, "matching_block_hashes": sorted(blocks), "matching_metadata_indices": sorted(metadata),
            "matching_file_hashes": sorted(files), "findings": matches, "finding_limit": 1000,
            "recovered_files": report["recovered_files"], "report": str(report_path),
            "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(), "source_unchanged": True,
            "scope": "Bounded PhotoRec, Sleuth Kit and bulk_extractor output, comparing extracted bytes/features with target references. A parser error is not a clean metadata result; complete zero readback can supersede metadata parsing after whole-image overwrite."}

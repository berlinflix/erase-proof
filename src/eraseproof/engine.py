"""Native overwrite / full read-back / adversarial recovery / evidence loop."""
import hashlib
import os
from pathlib import Path
import re
import stat
import time
import uuid

from . import carve
from .evidence import EvidenceStore, now
from .models import EraseProofError
from .targets import describe, open_target, virtual_disk_policy
from . import nativeio


def validate_references(references):
    refs = references or {}
    if not isinstance(refs, dict):
        raise EraseProofError("References must be a JSON object.")
    try:
        block_size = int(refs.get("block_size", 4096))
    except (TypeError, ValueError):
        raise EraseProofError("Invalid reference block size.") from None
    if block_size not in (512, 4096):
        raise EraseProofError("Reference block size must be 512 or 4096.")
    hashes = refs.get("block_hashes", [])
    patterns = refs.get("metadata_patterns", [])
    if not isinstance(hashes, list) or any(not isinstance(h, str) or not re.fullmatch(r"[0-9a-f]{64}", h) for h in hashes):
        raise EraseProofError("Reference hashes must be lowercase SHA-256 values.")
    if not isinstance(patterns, list) or any(not isinstance(p, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,65536}", p) for p in patterns):
        raise EraseProofError("Metadata patterns must be hex strings containing 1–65536 bytes.")
    return {"block_size": block_size, "block_hashes": sorted(set(hashes)), "metadata_patterns": sorted(set(p.lower() for p in patterns))}


def hash_stream(stream, length, cancel=None):
    stream.seek(0)
    remaining, digest = length, hashlib.sha256()
    while remaining:
        carve.checkpoint(cancel)
        block = stream.read(min(carve.CHUNK, remaining))
        if not block:
            raise EraseProofError("Short read while hashing.")
        digest.update(block)
        remaining -= len(block)
    return digest.hexdigest()


def verify(path, references=None, progress=None, cancel=None, stream=None, length=None):
    refs = validate_references(references)
    owned = stream is None
    if owned:
        info = describe(path)
        stream, length = open_target(path), info["size"]
    block_size = int(refs.get("block_size", 4096))
    if block_size not in (512, 4096):
        raise EraseProofError("Reference block size must be 512 or 4096.")
    block_hashes = set(refs.get("block_hashes", []))
    patterns = [bytes.fromhex(p) for p in refs.get("metadata_patterns", [])]
    if any(not p or len(p) > 65536 for p in patterns):
        raise EraseProofError("Metadata patterns must contain 1–65536 bytes.")
    matched_hashes, matched_patterns = set(), set()
    block_findings, pattern_findings = [], []
    nonzero, checked, carry = 0, 0, b""
    digest = hashlib.sha256()
    try:
        stream.seek(0)
        while checked < length:
            carve.checkpoint(cancel)
            data = stream.read(min(carve.CHUNK, length-checked))
            if not data:
                raise EraseProofError("Short read during complete verification.")
            digest.update(data)
            nonzero += len(data)-data.count(0)
            if block_hashes:
                for offset in range(0, len(data), block_size):
                    block = data[offset:offset+block_size]
                    if any(block):
                        hash_value = hashlib.sha256(block).hexdigest()
                        if hash_value in block_hashes:
                            if hash_value not in matched_hashes and len(block_findings) < 1000:
                                block_findings.append({"sha256": hash_value, "offset": checked+offset})
                            matched_hashes.add(hash_value)
            window = carry+data
            for i, pattern in enumerate(patterns):
                at = window.find(pattern)
                if at >= 0:
                    if i not in matched_patterns and len(pattern_findings) < 1000:
                        pattern_findings.append({"pattern_index": i, "offset": checked-len(carry)+at, "length": len(pattern)})
                    matched_patterns.add(i)
            overlap = max((len(p)-1 for p in patterns), default=0)
            carry = window[-overlap:] if overlap else b""
            checked += len(data)
            if progress:
                progress("Verify", .6*checked/max(length, 1), f"Read back {checked:,} bytes; {nonzero:,} nonzero bytes")
        files = carve.scan(path, stream=stream, length=length, cancel=cancel,
                           progress=(lambda _, p, m: progress("Attack", .6+.4*p, m)) if progress else None)
        denominator = len(block_hashes)+len(patterns)
        return {"passed": nonzero == 0 and not files and not matched_hashes and not matched_patterns,
                "bytes_checked": checked, "nonzero_bytes": nonzero, "sha256": digest.hexdigest(),
                "carved_candidates": [c.to_dict() for c in files], "matched_reference_blocks": len(matched_hashes),
                "metadata_residues": len(matched_patterns), "reference_count": denominator,
                "reference_block_findings": block_findings, "metadata_findings": pattern_findings,
                "finding_limit": 1000,
                "rrs": (len(matched_hashes)+len(matched_patterns))/denominator if denominator else None,
                "scope": "Full logical-range zero read-back plus contiguous carving and provided aligned references; not physical storage, snapshots, hidden areas or firmware verification."}
    finally:
        if owned:
            stream.close()


def plan(path, allow_device=None, confirmation=None):
    target = describe(path)
    if target["size"] == 0:
        raise EraseProofError("Empty targets are refused.")
    if target["kind"] == "block-device":
        target = virtual_disk_policy(path, confirmation, allow_device)
    elif Path(path).suffix.lower() not in (".img", ".raw", ".dd", ".bin"):
        raise EraseProofError("Image overwrite requires a .img, .raw, .dd or .bin target.")
    return {"target": target, "method": "single-pass-zero-overwrite", "verification": "complete-readback-and-recovery-attack",
            "confirmation": target["serial"], "physical_sanitization": False,
            "warning": "This changes the actual selected file or guest-visible virtual disk, including its filesystem."}


def erase(path, confirmation, evidence_dir, references=None, allow_device=None, progress=None, cancel=None):
    started_at, started = now(), time.monotonic()
    references = validate_references(references)  # Reject invalid jobs before the first destructive write.
    prepared = plan(path, allow_device, confirmation)
    target = prepared["target"]
    if confirmation != target["serial"]:
        raise EraseProofError("Type the exact image filename or virtual-device serial to confirm.")
    store = EvidenceStore(evidence_dir)
    if not store.check():
        raise EraseProofError("Audit history is damaged. No overwrite was started.")
    store.key()  # Fail signing-readiness checks before destructive I/O.
    # Evidence must not reside on the target being erased (for virtual devices,
    # an unmounted target cannot contain the case folder).
    if Path(evidence_dir).resolve() == Path(path).resolve():
        raise EraseProofError("Evidence path cannot equal the erasure target.")
    original_identity = os.stat(path, follow_symlinks=False)
    with open_target(path, writable=True) as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_rdev) != (original_identity.st_dev, original_identity.st_ino, original_identity.st_rdev):
            raise EraseProofError("Target identity changed while opening. No write was started.")
        if stat.S_ISREG(opened.st_mode) and opened.st_size != target["size"]:
            raise EraseProofError("Image size changed while opening.")
        if target["kind"] == "virtual-block-device":
            virtual_disk_policy(path, confirmation, allow_device)  # Fresh mount/identity check after open.
        if progress:
            progress("Discover", 0, f"Identity pinned: {target['path']}")
        before = hash_stream(stream, target["size"], cancel)
        job = "ep-"+str(uuid.uuid4())
        store.append("erasure.started", {"job": job, "target": target, "before_sha256": before, "method": prepared["method"]})
        stream.seek(0)
        written, zeros = 0, bytes(carve.CHUNK)
        native = nativeio.library() is not None
        direct_bytes, tail_bytes = 0, 0
        try:
            while written < target["size"]:
                carve.checkpoint(cancel)
                length = min(len(zeros), target["size"]-written)
                if native:
                    aligned = length-length % nativeio.ALIGN
                    if aligned:
                        nativeio.zero(stream.fileno(), written, aligned)
                        written += aligned
                        direct_bytes += aligned
                    if length != aligned:
                        nativeio.zero(stream.fileno(), written, length-aligned, direct=False)
                        written += length-aligned
                        tail_bytes += length-aligned
                else:
                    part = memoryview(zeros)[:length]
                    while part:
                        count = stream.write(part)
                        if not count:
                            raise EraseProofError("Short or failed write; target may be partially overwritten.")
                        written += count
                        part = part[count:]
                if progress:
                    progress("Erase", written/target["size"], f"Overwrote {written:,} / {target['size']:,} bytes")
            os.fsync(stream.fileno())
            if hasattr(os, "posix_fadvise"):
                os.posix_fadvise(stream.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            result = verify(path, references, progress, cancel, stream, target["size"])
            result["io"] = {"implementation": "C/O_DIRECT" if native else "Python/buffered-fsync",
                            "direct_bytes": direct_bytes, "buffered_tail_bytes": tail_bytes,
                            "fsync_completed": True}
            if not result["passed"]:
                raise EraseProofError("Residue detected after overwrite. No certificate issued.")
            if stat.S_ISREG(opened.st_mode) and os.fstat(stream.fileno()).st_size != target["size"]:
                raise EraseProofError("Image size changed during verification. Certification refused.")
        except BaseException as error:
            os.fsync(stream.fileno())
            store.append("erasure.incomplete", {"job": job, "target": target["path"], "bytes_written": written, "reason": str(error)})
            raise
        record = store.certify({"schema": "eraseproof.native-evidence.v1", "id": job,
                                "started_at": started_at, "issued_at": now(), "duration_seconds": time.monotonic()-started,
                                "target": target, "plan": prepared, "before_sha256": before, "verification": result,
                                "assurance": "Self-signed local operator evidence. Logical overwrite only; not a NIST/IEEE compliance or physical-media sanitization certificate."})
    if progress:
        progress("Certify", 1, "Full read-back and recovery checks passed. Ed25519 evidence committed.")
    return record

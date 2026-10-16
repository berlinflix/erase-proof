"""Shared offline-image fingerprinting, preservation and evidence coordinator."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import uuid

from .carve import checkpoint
from .engine import verify
from .evidence import EvidenceStore, digest, now
from .models import EraseProofError
from .runtime import system_environment
from .targets import describe, open_target


def backend(filesystem):
    from . import fat, ext4, ntfs, exfat
    try:
        return {"fat32": fat, "ext4": ext4, "ntfs": ntfs, "exfat": exfat}[filesystem.lower()]
    except KeyError:
        raise EraseProofError("Unsupported offline filesystem.") from None


def run(arguments, *, fd=None, timeout=600):
    try:
        result = subprocess.run(list(map(str, arguments)), stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout,
                                pass_fds=() if fd is None else (fd,), env=system_environment())
    except subprocess.TimeoutExpired:
        raise EraseProofError("Offline filesystem tool timed out; inspect the image before retrying.") from None
    if result.returncode:
        detail = (result.stdout+result.stderr).decode(errors="replace")[-4000:]
        raise EraseProofError(detail or "Offline filesystem tool failed.")
    return result.stdout


def inventory(image, fd, filesystem="ext4"):
    data = run(["fls", "-u", "-r", "-p", image], fd=fd).decode("utf-8", errors="strict")
    result = []
    for line in data.splitlines():
        match = re.fullmatch(r"([a-zV])/([a-zV])\s+(\d[\d-]*):\t(.+)", line)
        if not match:
            raise EraseProofError("Unsupported filesystem inventory entry: "+line[:200])
        kind, _, inode, name = match.groups()
        if kind == "V":
            continue
        if filesystem == "ntfs" and (int(inode.split("-", 1)[0]) < 16 or name.split("/", 1)[0] == "$Extend"):
            continue
        parts = PurePosixPath(name).parts
        if any(p in (".", "..") for p in parts) or any(c in name for c in "\\\r\n\t") or name.startswith("/"):
            raise EraseProofError("Ambiguous/escaped filesystem path; writes refused.")
        entry = {"path": "/"+name, "inode": inode, "kind": kind}
        if filesystem == "ntfs":
            entry.update({"base_path": entry["path"].split(":", 1)[0], "stream": ":" in name})
        result.append(entry)
    return result


def fingerprint_data(entry, chunks):
    from .fingerprints import measure
    sha, blocks, head, tail, pending, length = hashlib.sha256(), set(), b"", b"", b"", 0
    def feed():
        nonlocal head, tail, pending, length
        for data in chunks:
            sha.update(data)
            length += len(data)
            head, tail = (head+data)[:64], (tail+data)[-64:]
            pending += data
            full = len(pending)//512*512
            for at in range(0, full, 512):
                block = pending[at:at+512]
                if any(block):
                    blocks.add(hashlib.sha256(block).hexdigest())
            pending = pending[full:]
            yield data
    measured = measure(feed())
    samples = {sample.hex() for sample in (head, tail) if any(sample)}
    return {"path": entry["path"], "inode": entry["inode"], **measured}, blocks, samples


def content(image, entry, fd):
    # Stream large files to a temporary file instead of capturing them in RAM.
    with tempfile.TemporaryFile() as out:
        result = subprocess.run(["icat", image, entry["inode"]], stdout=out,
                                stderr=subprocess.PIPE, timeout=600, pass_fds=(fd,), env=system_environment())
        if result.returncode:
            raise EraseProofError("Cannot read an allocated file: "+result.stderr.decode(errors="replace")[-1000:])
        out.seek(0)
        return fingerprint_data(entry, iter(lambda: out.read(4*1024*1024), b""))


def checked_image(path):
    info = describe(path)
    if info["kind"] != "image" or info["size"] < 8*1024*1024:
        raise EraseProofError("Select an offline filesystem volume image, at offset zero.")
    if run(["losetup", "--associated", info["path"]]).strip():
        raise EraseProofError("Detach all loop devices associated with the image first.")
    return info


def erase_with(adapter, path, internal_path, confirmation, evidence_dir, progress=None, cancel=None):
    from . import attackgate
    info = checked_image(path)
    root = Path(evidence_dir).expanduser().resolve()
    if root == Path(info["path"]):
        raise EraseProofError("Evidence destination conflicts with the image.")
    store = EvidenceStore(root)
    if not store.check():
        raise EraseProofError("Audit history is damaged.")
    store.key()
    with open_target(path, writable=True) as stream:
        opened = os.fstat(stream.fileno())
        current = os.stat(info["path"], follow_symlinks=False)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (current.st_dev, current.st_ino, info["size"]):
            raise EraseProofError("Image identity/size changed before preparation.")
        prepared, entries = adapter.prepare(stream, info, internal_path)
        if confirmation != prepared["confirmation"]:
            raise EraseProofError("Confirmation must match the image filename, colon, and exact internal path: "+prepared["confirmation"])
        attackgate.require_tools()
        fd, selected = stream.fileno(), {e["path"] for e in prepared["selected"]}
        preserved, hashes = [], set()
        selected_files = []
        patterns = set()
        for index, entry in enumerate(entries):
            checkpoint(cancel)
            if entry["kind"] == "r":
                measure, blocks, samples = adapter.fingerprint(stream, entry)
                if entry["path"] in selected:
                    selected_files.append(measure)
                    hashes.update(blocks)
                    # Samples also detect short, tail and unaligned copies.
                    patterns.update(samples)
                else:
                    preserved.append(measure)
            if entry["path"] in selected:
                for encoding in ("utf-8", "utf-16-le"):
                    patterns.add(PurePosixPath(entry["path"]).name.encode(encoding).hex())
            if progress:
                progress("Fingerprint", (index+1)/max(len(entries), 1), "Hashing selected and preserved allocated files")
        file_hashes = {entry["sha256"] for entry in selected_files if entry["size"]}
        references = {"block_size": 512, "block_hashes": sorted(hashes), "metadata_patterns": sorted(patterns),
                      "file_hashes": sorted(file_hashes),
                      "block_hashes_4096": sorted({h for f in selected_files for h in f["block_hashes_4096"]}),
                      "fuzzy_hashes": sorted({f["ssdeep"] for f in selected_files if f["size"]}), "fuzzy_threshold": 70}
        from .engine import validate_references
        references = validate_references(references)
        job = "ep-"+uuid.uuid4().hex
        prepared["target_files"] = selected_files
        prepared["reference_manifest_sha256"] = digest(references)
        reference_path = store.root/(job+".references.json")
        with reference_path.open("x") as reference_file:
            json.dump(references, reference_file, sort_keys=True)
            reference_file.flush()
            os.fsync(reference_file.fileno())
        store.append(adapter.name+"-erasure.started", {"job": job, "plan": prepared})
        result = None
        try:
            for entry in sorted(prepared["selected"], key=lambda e: len(PurePosixPath(e["path"]).parts), reverse=True):
                checkpoint(cancel)
                adapter.remove(stream, entry)
            checkpoint(cancel)
            if progress:
                progress("Clean "+adapter.name+" history", 0, adapter.cleanup_description)
            cleaned = adapter.scrub(stream, store.root, job, progress, cancel)
            os.fsync(fd)
            adapter.check(stream)
            after_entries = adapter.entries(stream)
            after_paths = {entry["path"]: entry for entry in after_entries}
            if selected.intersection(after_paths):
                raise EraseProofError("A selected path remains allocated.")
            for expected in preserved:
                checkpoint(cancel)
                if expected["path"] not in after_paths or adapter.fingerprint(stream, after_paths[expected["path"]])[0] != expected:
                    raise EraseProofError("An unrelated allocated file changed. Certification refused.")
            result = verify(path, references, progress, cancel, stream, info["size"])
            duplicate_files = [entry for entry in preserved if entry["size"] and entry["sha256"] in file_hashes]
            duplicate_hashes = {entry["sha256"] for entry in duplicate_files}
            result["reference_count"] += len(file_hashes)
            similar_files = []
            from .fingerprints import matches
            for entry in preserved:
                if found := matches(entry["ssdeep"], references["fuzzy_hashes"], references["fuzzy_threshold"]):
                    similar_files.append({"path": entry["path"], "matches": found})
            result["similar_live_files"] = similar_files
            result["matching_live_file_hashes"] = duplicate_files
            result["rrs"] = (result["matched_reference_blocks"]+len(result["matched_4096_blocks"])+result["metadata_residues"]+len(duplicate_hashes)+len(similar_files)+len(result["fuzzy_findings"]))/max(1, result["reference_count"])
            result["history_verification"] = adapter.verify_history(stream)
            result["passed"] = result["rrs"] == 0 and not similar_files and not result["fuzzy_findings"] and result["history_verification"]["passed"]
            if os.fstat(fd).st_size != info["size"]:
                raise EraseProofError("Image size changed during the operation.")
            result["volume_nonzero_bytes"] = result.pop("nonzero_bytes")
            result.update({"scope": prepared["scope"], "cleanup": cleaned,
                           "preserved_files_hash_checked": len(preserved), "all_filesystem_copies_verified": False,
                           "filesystem_consistency": adapter.consistency})
            if not result["passed"]:
                raise EraseProofError("Target content/name or unallocated history residue remains in the image. No certificate issued.")
            result["independent_attack"] = attackgate.check(path, store.root/(job+".attack"), references,
                stream=stream, length=info["size"], expected_sha256=result["sha256"], progress=progress, cancel=cancel)
            result["rrs"] = result["independent_attack"]["target_reference_matches"]/max(1, result["reference_count"])
            result["passed"] &= result["independent_attack"]["passed"]
            if not result["passed"]:
                raise EraseProofError("Independent recovery check failed or target residue remains. No certificate issued.")
            return store.certify({"schema": "eraseproof.native-evidence.v1", "id": job,
                                  "operation": "offline-"+adapter.name+"-targeted-erasure", "issued_at": now(), "target": info,
                                  "plan": prepared, "verification": result, "assurance": prepared["scope"]})
        except BaseException as error:
            os.fsync(fd)
            store.append(adapter.name+"-erasure.incomplete", {"job": job, "reason": str(error), "verification": result})
            raise

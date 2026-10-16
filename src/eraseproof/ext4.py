"""Offline ext4 image erasure with libext2fs and full-volume residue checks.

Global unallocated history, unused inodes, directory slack and inactive journal
blocks are cleared. Allocated unrelated file contents are hash checked before
and after. Mounted filesystems and physical devices never enter this adapter.
"""
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


def helper():
    path = Path(__file__).parent/"resources"/"native"/"eraseproof-ext4"
    if not path.is_file():
        raise EraseProofError("Build the ext4 adapter with scripts/build-native.sh.")
    return str(path)


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


def inventory(image, fd):
    data = run(["fls", "-u", "-r", "-p", image], fd=fd).decode("utf-8", errors="strict")
    result = []
    for line in data.splitlines():
        match = re.fullmatch(r"([a-zV])/([a-zV])\s+(\d+):\t(.+)", line)
        if not match:
            raise EraseProofError("Unsupported filesystem inventory entry: "+line[:200])
        kind, _, inode, name = match.groups()
        if kind == "V":
            continue
        parts = PurePosixPath(name).parts
        if any(p in (".", "..") for p in parts) or any(c in name for c in "\\\r\n\t") or name.startswith("/"):
            raise EraseProofError("Ambiguous/escaped filesystem path; writes refused.")
        result.append({"path": "/"+name, "inode": inode, "kind": kind})
    return result


def content(image, entry, fd):
    # Stream large files to a temporary file instead of capturing them in RAM.
    digest, blocks = hashlib.sha256(), set()
    with tempfile.TemporaryFile() as out:
        result = subprocess.run(["icat", image, entry["inode"]], stdout=out,
                                stderr=subprocess.PIPE, timeout=600, pass_fds=(fd,), env=system_environment())
        if result.returncode:
            raise EraseProofError("Cannot read an allocated file: "+result.stderr.decode(errors="replace")[-1000:])
        length = out.tell()
        out.seek(0)
        while data := out.read(512):
            digest.update(data)
            if len(data) == 512 and any(data):
                blocks.add(hashlib.sha256(data).hexdigest())
        samples = set()
        for at in {0, max(0, length-64)}:
            out.seek(at)
            sample = out.read(min(64, length))
            if any(sample):
                samples.add(sample.hex())
        return {"path": entry["path"], "inode": entry["inode"], "sha256": digest.hexdigest(), "size": length}, blocks, samples


def checked_image(path):
    info = describe(path)
    if info["kind"] != "image" or info["size"] < 8*1024*1024:
        raise EraseProofError("Select an offline ext4 volume image, at offset zero.")
    if run(["losetup", "--associated", info["path"]]).strip():
        raise EraseProofError("Detach all loop devices associated with the image first.")
    return info


def prepare(stream, info, internal_path):
    fd = stream.fileno()
    image = f"/proc/self/fd/{fd}"
    if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != (os.stat(info["path"]).st_dev, os.stat(info["path"]).st_ino):
        raise EraseProofError("Image identity changed.")
    normalized = "/"+internal_path.strip("/")
    if normalized == "/" or any(p in (".", "..") for p in normalized.split("/")):
        raise EraseProofError("Select a specific internal file or folder.")
    # Read-only fsck is a gate, never an automatic repair of caller data.
    run(["e2fsck", "-f", "-n", image], fd=fd)
    geometry = json.loads(run([helper(), "info", image], fd=fd))
    entries = inventory(image, fd)
    selected = [e for e in entries if e["path"] == normalized or e["path"].startswith(normalized+"/")]
    if not any(e["path"] == normalized for e in selected):
        raise EraseProofError("Internal path does not exist.")
    for entry in selected:
        metadata = json.loads(run([helper(), "info", image, entry["path"]], fd=fd))
        if entry["kind"] not in ("r", "d") or (entry["kind"] == "r" and metadata["links"] != 1) or metadata["external_xattrs"]:
            raise EraseProofError("Selected tree contains special files, hard links or external extended attributes.")
    return {"target": info, "internal_path": normalized, "confirmation": Path(info["path"]).name+":"+normalized,
            "selected": selected, "geometry": geometry,
            "method": "libext2fs-unlink-and-global-offline-history-cleanup",
            "scope": "Current ext4 image: selected allocation, all free blocks/unused inodes, directory slack and clean internal journal history. Unrelated allocated files are preserved. All deleted history on this volume is removed; snapshots, changed live copies and physical remnants are outside this proof."}, entries


def plan_path(path, internal_path):
    info = checked_image(path)
    with open_target(path) as stream:
        return prepare(stream, info, internal_path)[0]


def list_paths(path):
    info = checked_image(path)
    with open_target(path) as stream:
        image = f"/proc/self/fd/{stream.fileno()}"
        run([helper(), "info", image], fd=stream.fileno())
        return inventory(image, stream.fileno())


def erase_path(path, internal_path, confirmation, evidence_dir, progress=None, cancel=None):
    info = checked_image(path)
    root = Path(evidence_dir).expanduser().resolve()
    if root == Path(info["path"]):
        raise EraseProofError("Evidence destination conflicts with the image.")
    store = EvidenceStore(root)
    if not store.check():
        raise EraseProofError("Audit history is damaged.")
    store.key()
    with open_target(path, writable=True) as stream:
        prepared, entries = prepare(stream, info, internal_path)
        if confirmation != prepared["confirmation"]:
            raise EraseProofError("Confirm the image filename, colon, and exact internal path: "+prepared["confirmation"])
        fd, selected = stream.fileno(), {e["path"] for e in prepared["selected"]}
        image, preserved, hashes = f"/proc/self/fd/{fd}", [], set()
        selected_files = []
        patterns = set()
        for index, entry in enumerate(entries):
            checkpoint(cancel)
            if entry["kind"] == "r":
                measure, blocks, samples = content(image, entry, fd)
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
        references = {"block_size": 512, "block_hashes": sorted(hashes), "metadata_patterns": sorted(patterns)}
        job = "ep-"+uuid.uuid4().hex
        prepared["target_files"] = selected_files
        prepared["reference_manifest_sha256"] = digest(references)
        reference_path = store.root/(job+".references.json")
        with reference_path.open("x") as reference_file:
            json.dump(references, reference_file, sort_keys=True)
            reference_file.flush()
            os.fsync(reference_file.fileno())
        store.append("ext4-erasure.started", {"job": job, "plan": prepared})
        result = None
        try:
            for entry in sorted(prepared["selected"], key=lambda e: len(PurePosixPath(e["path"]).parts), reverse=True):
                checkpoint(cancel)
                run([helper(), "remove", image, entry["path"]], fd=fd)
            checkpoint(cancel)
            if progress:
                progress("Clean ext4 history", 0, "Clearing free allocation, unused inodes, directory slack and inactive journal")
            cleaned = json.loads(run([helper(), "scrub", image], fd=fd))
            os.fsync(fd)
            run(["e2fsck", "-f", "-n", image], fd=fd)
            after_entries = inventory(image, fd)
            after_paths = {entry["path"]: entry for entry in after_entries}
            if selected.intersection(after_paths):
                raise EraseProofError("A selected path remains allocated.")
            for expected in preserved:
                checkpoint(cancel)
                if expected["path"] not in after_paths or content(image, after_paths[expected["path"]], fd)[0] != expected:
                    raise EraseProofError("An unrelated allocated file changed. Certification refused.")
            result = verify(path, references, progress, cancel, stream, info["size"])
            result["passed"] = result["matched_reference_blocks"] == 0 and result["metadata_residues"] == 0
            result["volume_nonzero_bytes"] = result.pop("nonzero_bytes")
            result.update({"scope": prepared["scope"], "cleanup": cleaned,
                           "preserved_files_hash_checked": len(preserved), "all_filesystem_copies_verified": False,
                           "filesystem_consistency": "e2fsck -fn passed"})
            if not result["passed"]:
                raise EraseProofError("Target content/name residue remains in the image. No certificate issued.")
            return store.certify({"schema": "eraseproof.native-evidence.v1", "id": job,
                                  "operation": "offline-ext4-targeted-erasure", "issued_at": now(), "target": info,
                                  "plan": prepared, "verification": result, "assurance": prepared["scope"]})
        except BaseException as error:
            os.fsync(fd)
            store.append("ext4-erasure.incomplete", {"job": job, "reason": str(error), "verification": result})
            raise

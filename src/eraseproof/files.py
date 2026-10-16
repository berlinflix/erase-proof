"""Pinned-identity logical erasure of ordinary files and directory trees.

This engine never represents a file overwrite as whole-device sanitization.
Offline filesystem residue cleanup is a separate operation.
"""
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import json
import time
import uuid

from .carve import CHUNK, checkpoint
from .evidence import EvidenceStore, now
from .models import EraseProofError
from . import nativeio

PROTECTED = tuple(Path(p) for p in ("/", "/boot", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/proc", "/sys", "/dev", "/run"))


def filesystem(path):
    result = subprocess.run(["findmnt", "--json", "--target", str(path), "--output", "SOURCE,FSTYPE,TARGET,OPTIONS"], capture_output=True, text=True, timeout=15)
    if result.returncode:
        return {"fstype": "unknown", "source": "unknown", "target": "unknown"}
    return json.loads(result.stdout)["filesystems"][0]


def _identity(info):
    return {"device": info.st_dev, "inode": info.st_ino, "size": info.st_size, "mtime_ns": info.st_mtime_ns}


def plan_files(path):
    raw = Path(path).expanduser().absolute()
    if raw.is_symlink():
        raise EraseProofError("Symlinks are refused for file erasure.")
    root = raw.resolve(strict=True)
    if root in PROTECTED or any(parent in PROTECTED[1:] for parent in root.parents):
        raise EraseProofError("Protected system paths cannot be selected for file erasure.")
    if root == Path.home():
        raise EraseProofError("Select specific files or a child folder, not the entire home directory.")
    info = root.stat()
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise EraseProofError("File erasure accepts ordinary files and directories only.")
    paths, folders = [], []
    if root.is_file():
        paths = [root]
    else:
        for directory, dirs, names in os.walk(root, followlinks=False):
            folders.append(Path(directory))
            for name in dirs+names:
                candidate = Path(directory)/name
                entry = candidate.lstat()
                if stat.S_ISLNK(entry.st_mode):
                    raise EraseProofError("Tree contains a symlink. Nothing was erased.")
                if entry.st_dev != info.st_dev:
                    raise EraseProofError("Tree crosses a filesystem or mount boundary.")
                if stat.S_ISREG(entry.st_mode):
                    paths.append(candidate)
                elif not stat.S_ISDIR(entry.st_mode):
                    raise EraseProofError("Tree contains a special file. Nothing was erased.")
    entries = []
    for candidate in sorted(paths):
        entry = candidate.stat()
        if entry.st_nlink != 1:
            raise EraseProofError(f"Hard-linked file refused: {candidate}")
        item = {"path": str(candidate), **_identity(entry)}
        if nativeio.library() is not None:
            try:
                fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    item["extent_inventory"] = nativeio.extents(fd)
                finally:
                    os.close(fd)
            except (EraseProofError, OSError) as error:
                item["extent_inventory_error"] = str(error)
        entries.append(item)
    if not entries:
        raise EraseProofError("No ordinary files were selected.")
    return {"root": str(root), "confirmation": root.name, "files": entries,
            "directories": [str(p) for p in sorted(folders, key=lambda p: len(p.parts), reverse=True)],
            "bytes": sum(item["size"] for item in entries), "filesystem": filesystem(root),
            "scope": "Current logical file contents only. Journals, names, previous versions, snapshots, hard copies, swap, caches and FTL remnants are outside this operation.",
            "method": "pinned-file-zero-overwrite-fsync-readback-unlink", "physical_sanitization": False}


def erase_files(path, confirmation, evidence_dir, progress=None, cancel=None, unlink=True):
    prepared = plan_files(path)
    if confirmation != prepared["confirmation"]:
        raise EraseProofError("Confirmation must exactly match the selected file or folder name.")
    root = Path(prepared["root"])
    evidence = Path(evidence_dir).expanduser().resolve()
    if evidence == root or root in evidence.parents:
        raise EraseProofError("Evidence must be outside the selected file/folder tree.")
    store = EvidenceStore(evidence)
    if not store.check():
        raise EraseProofError("Audit history failed integrity validation.")
    store.key()  # Signing readiness is checked before any destructive write.
    started, started_at = time.monotonic(), now()
    job = "ep-"+str(uuid.uuid4())
    store.append("file-erasure.started", {"job": job, "plan": prepared})
    measurements, total_written = [], 0
    try:
        for index, item in enumerate(prepared["files"]):
            checkpoint(cancel)
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open(item["path"], flags)
            with os.fdopen(fd, "r+b", buffering=0) as stream:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                opened = os.fstat(stream.fileno())
                if _identity(opened) != {key: item[key] for key in ("device", "inode", "size", "mtime_ns")} or opened.st_nlink != 1:
                    raise EraseProofError("A selected file changed after planning. Operation stopped.")
                before = hashlib.sha256()
                for block in iter(lambda: stream.read(CHUNK), b""):
                    checkpoint(cancel)
                    before.update(block)
                stream.seek(0)
                written, zeros = 0, bytes(CHUNK)
                native = nativeio.library() is not None
                direct_bytes, tail_bytes = 0, 0
                while written < opened.st_size:
                    checkpoint(cancel)
                    length = min(CHUNK, opened.st_size-written)
                    if native:
                        aligned = length-length % nativeio.ALIGN
                        if aligned:
                            nativeio.zero(stream.fileno(), written, aligned)
                            written += aligned
                            direct_bytes += aligned
                            total_written += aligned
                        if length != aligned:
                            nativeio.zero(stream.fileno(), written, length-aligned, direct=False)
                            written += length-aligned
                            tail_bytes += length-aligned
                            total_written += length-aligned
                    else:
                        data = memoryview(zeros)[:length]
                        while data:
                            count = stream.write(data)
                            if not count:
                                raise EraseProofError("File write failed; current target may be partially overwritten.")
                            written += count
                            total_written += count
                            data = data[count:]
                    if progress:
                        progress("Erase files", total_written/max(prepared["bytes"], 1), f"Overwriting {Path(item['path']).name}")
                os.fsync(stream.fileno())
                if hasattr(os, "posix_fadvise"):
                    os.posix_fadvise(stream.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
                if os.fstat(stream.fileno()).st_size != opened.st_size:
                    raise EraseProofError("File size changed during overwrite.")
                stream.seek(0)
                checked, nonzero, after = 0, 0, hashlib.sha256()
                while checked < opened.st_size:
                    checkpoint(cancel)
                    data = stream.read(min(CHUNK, opened.st_size-checked))
                    if not data:
                        raise EraseProofError("Short file read-back.")
                    checked += len(data)
                    nonzero += len(data)-data.count(0)
                    after.update(data)
                if nonzero:
                    raise EraseProofError("File byte read-back failed; no completion record issued.")
                if unlink:
                    parent = Path(item["path"]).parent
                    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        current = os.stat(Path(item["path"]).name, dir_fd=parent_fd, follow_symlinks=False)
                        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                            raise EraseProofError("Directory entry changed; unlink refused.")
                        os.unlink(Path(item["path"]).name, dir_fd=parent_fd)
                        os.fsync(parent_fd)
                    finally:
                        os.close(parent_fd)
                measurements.append({"path": item["path"], "bytes_checked": checked, "before_sha256": before.hexdigest(),
                                     "after_sha256": after.hexdigest(), "unlinked": unlink, "nonzero_bytes": 0,
                                     "io": {"implementation": "C/O_DIRECT" if native else "Python/buffered-fsync",
                                            "direct_bytes": direct_bytes, "buffered_tail_bytes": tail_bytes}})
        if unlink:
            for folder in prepared["directories"]:
                os.rmdir(folder)  # Refuses any new/unplanned children rather than recursively deleting them.
        result = {"passed": True, "bytes_checked": sum(m["bytes_checked"] for m in measurements), "nonzero_bytes": 0,
                  "rrs": None, "files": measurements, "scope": prepared["scope"], "all_filesystem_copies_verified": False}
        record = store.certify({"schema": "eraseproof.native-evidence.v1", "id": job,
                                "operation": "logical-file-erasure", "started_at": started_at, "issued_at": now(),
                                "duration_seconds": time.monotonic()-started, "target": {"path": prepared["root"], "kind": "file-tree", "size": prepared["bytes"]},
                                "plan": prepared, "verification": result,
                                "assurance": "Verified current logical file-byte overwrite only. This record explicitly does not establish secure removal of filesystem history or physical-media copies."})
        return record
    except BaseException as error:
        store.append("file-erasure.incomplete", {"job": job, "root": prepared["root"], "completed_files": len(measurements), "bytes_written": total_written, "reason": str(error)})
        raise

"""Offline ext4 image erasure with libext2fs and full-volume residue checks.

Global unallocated history, unused inodes, directory slack and inactive journal
blocks are cleared. Allocated unrelated file contents are hash checked before
and after. Mounted filesystems and physical devices never enter this adapter.
"""
import json
import os
from pathlib import Path, PurePosixPath

from .models import EraseProofError
from .targets import open_target
from .offline import run, content, checked_image, inventory, erase_with


def helper():
    path = Path(__file__).parent/"resources"/"native"/"eraseproof-ext4"
    if not path.is_file():
        raise EraseProofError("Build the ext4 adapter with scripts/build-native.sh.")
    return str(path)


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


name = "ext4"
consistency = "e2fsck -fn passed"
cleanup_description = "Clearing free allocation, unused inodes, directory slack and inactive journal"


def entries(stream):
    return inventory(f"/proc/self/fd/{stream.fileno()}", stream.fileno())


def fingerprint(stream, entry):
    return content(f"/proc/self/fd/{stream.fileno()}", entry, stream.fileno())


def remove(stream, entry):
    run([helper(), "remove", f"/proc/self/fd/{stream.fileno()}", entry["path"]], fd=stream.fileno())


def scrub(stream, evidence, job, progress=None, cancel=None):
    return json.loads(run([helper(), "scrub", f"/proc/self/fd/{stream.fileno()}"], fd=stream.fileno()))


def check(stream):
    run(["e2fsck", "-f", "-n", f"/proc/self/fd/{stream.fileno()}"], fd=stream.fileno())


def verify_history(stream):
    return json.loads(run([helper(), "verify-free", f"/proc/self/fd/{stream.fileno()}"], fd=stream.fileno()))


def erase_path(path, internal_path, confirmation, evidence_dir, progress=None, cancel=None):
    import sys
    return erase_with(sys.modules[__name__], path, internal_path, confirmation, evidence_dir, progress, cancel)

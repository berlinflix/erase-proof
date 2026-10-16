"""Offline NTFS target deletion, MFT/index/log/USN and free-space cleanup."""
import hashlib
import json
from pathlib import Path
import sys

from .models import EraseProofError
from .offline import checked_image, content, erase_with, inventory, run
from .targets import open_target

name = "ntfs"
consistency = "ntfsfix --no-action and ntfsresize --info --no-action passed"
cleanup_description = "Clearing MFT/index history, $LogFile, allocated $UsnJrnl payload and free clusters"


def helper():
    path = Path(__file__).parent/"resources"/"native"/"eraseproof-ntfs"
    if not path.is_file():
        raise EraseProofError("Build the NTFS adapter with scripts/build-native.sh.")
    return str(path)


def source(stream):
    return f"/proc/self/fd/{stream.fileno()}"


def check(stream):
    run(["ntfsfix", "--no-action", source(stream)], fd=stream.fileno())
    run(["ntfsresize", "--info", "--no-action", "--no-progress-bar", source(stream)], fd=stream.fileno())


def entries(stream):
    return inventory(source(stream), stream.fileno(), "ntfs")


def fingerprint(stream, entry):
    return content(source(stream), entry, stream.fileno())


def prepare(stream, info, internal_path):
    normalized = "/"+internal_path.strip("/")
    if normalized == "/" or ":" in normalized or any(part in (".", "..") or part.startswith("$") for part in normalized.split("/") if part):
        raise EraseProofError("Select an ordinary internal file/folder, without system or stream path components.")
    geometry = json.loads(run([helper(), "info", source(stream)], fd=stream.fileno()))
    check(stream)
    found = entries(stream)
    selected = [entry for entry in found if entry["base_path"] == normalized or entry["base_path"].startswith(normalized+"/")]
    if not any(entry["path"] == normalized for entry in selected):
        raise EraseProofError("Internal path does not exist.")
    for entry in selected:
        if entry["stream"]:
            continue
        metadata = json.loads(run([helper(), "info", source(stream), entry["path"]], fd=stream.fileno()))
        if entry["kind"] not in ("r", "d") or metadata["links"] != 1:
            raise EraseProofError("Special files, reparse points, EFS targets and hard-linked files are refused.")
    return {"target": info, "internal_path": normalized, "confirmation": Path(info["path"]).name+":"+normalized,
            "geometry": geometry, "selected": selected, "method": "libntfs-unlink-and-global-offline-history-cleanup",
            "scope": "Current offline NTFS image: selected file/folder and its named data streams, unallocated clusters, unused MFT/index space, $LogFile and allocated $UsnJrnl:$J payload. All deleted history on this volume is removed. Unrelated allocated user streams are hash-checked. Snapshots, changed live copies and physical remnants are outside this proof."}, found


def plan_path(path, internal_path):
    info = checked_image(path)
    with open_target(path) as stream:
        return prepare(stream, info, internal_path)[0]


def list_paths(path):
    checked_image(path)
    with open_target(path) as stream:
        run([helper(), "info", source(stream)], fd=stream.fileno())
        return entries(stream)


def remove(stream, entry):
    if not entry["stream"]:
        run([helper(), "remove", source(stream), entry["path"]], fd=stream.fileno())


def scrub(stream, evidence, job, progress=None, cancel=None):
    usn = json.loads(run([helper(), "clean-usn", source(stream)], fd=stream.fileno()))
    output = run(["ntfswipe", "--directory", "--logfile", "--mft", "--unused", "--tails", "--bytes", "0", source(stream)], fd=stream.fileno())
    log = evidence/(job+".ntfswipe.log")
    with log.open("xb") as file:
        file.write(output)
    return {**usn, "ntfswipe_log": str(log), "ntfswipe_log_sha256": hashlib.sha256(output).hexdigest(),
            "all_unallocated_history_cleared": True}


def verify_history(stream):
    return json.loads(run([helper(), "verify-free", source(stream)], fd=stream.fileno()))


def erase_path(path, internal_path, confirmation, evidence_dir, progress=None, cancel=None):
    return erase_with(sys.modules[__name__], path, internal_path, confirmation, evidence_dir, progress, cancel)

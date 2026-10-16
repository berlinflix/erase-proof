"""FAT32 backend for shared preservation, global cleanup and attack gates."""
import os
from pathlib import Path
import struct
import sys

from . import nativeio
from .carve import checkpoint
from .fat32 import Fat32, _selection
from .models import EraseProofError
from .offline import checked_image, erase_with, fingerprint_data, run
from .targets import open_target

name = "fat32"
consistency = "fsck.fat -n passed"
cleanup_description = "Clearing free allocation, deleted directory records and allocated file slack"


def volume(stream, fresh=False):
    if fresh or not hasattr(stream, "_eraseproof_fat32"):
        v = Fat32(stream, os.fstat(stream.fileno()).st_size)
        v.files = {entry["path"]: entry for entry in v.walk() if not entry["deleted"]}
        stream._eraseproof_fat32 = v
    return stream._eraseproof_fat32


def summary(v):
    return [{"path": entry["path"], "inode": str(entry["slots"][-1]), "kind": "d" if entry["directory"] else "r", "size": entry["size"]}
            for entry in v.files.values()]


def check(stream):
    run(["fsck.fat", "-n", f"/proc/self/fd/{stream.fileno()}"], fd=stream.fileno())


def entries(stream):
    return summary(volume(stream, fresh=True))


def prepare(stream, info, internal_path):
    # Parse/mirroring checks precede fsck so corruption remains explicit.
    v = volume(stream, fresh=True)
    check(stream)
    _, chosen, _ = _selection(v, internal_path)
    status = struct.unpack_from("<I", v.fat, 4)[0]
    if status & 0x0C000000 != 0x0C000000:
        raise EraseProofError("Dirty or failed-I/O FAT32 volumes are refused.")
    ownership = {cluster for cluster in v.chain(v.root)}
    for entry in v.files.values():
        ownership.update(v.chain(entry["cluster"]))
    for cluster in range(2, v.clusters+2):
        if v.value(cluster) and cluster not in ownership:
            raise EraseProofError("Orphaned, bad or reserved FAT allocations are refused.")
    normalized = "/"+internal_path.strip("/")
    found = summary(v)
    paths = {entry["path"] for entry in chosen}
    return {"target": info, "internal_path": normalized, "confirmation": Path(info["path"]).name+":"+normalized,
            "selected": [entry for entry in found if entry["path"] in paths],
            "geometry": {"sector_size": v.bps, "cluster_size": v.cluster_size, "clusters": v.clusters, "fat_copies": v.copies},
            "method": "fat32-allocation-and-global-offline-history-cleanup",
            "scope": "Current offline FAT32 image: selected allocation, all free clusters, deleted directory records and directory/file slack. All deleted history on this volume is removed. Unrelated allocated files are hash-checked. Retained identical/shared copies can prevent certification; snapshots and physical remnants are outside this proof."}, found


def plan_path(path, internal_path):
    info = checked_image(path)
    with open_target(path) as stream:
        return prepare(stream, info, internal_path)[0]


def list_paths(path):
    checked_image(path)
    with open_target(path) as stream:
        return entries(stream)


def fingerprint(stream, entry):
    v = volume(stream)
    current = v.files[entry["path"]]
    def chunks():
        remaining = current["size"]
        for cluster in v.chain(current["cluster"]):
            count = min(remaining, v.cluster_size)
            if count:
                yield v.read_cluster(cluster)[:count]
                remaining -= count
        if remaining:
            raise EraseProofError("Short FAT32 file content.")
    return fingerprint_data(entry, chunks())


def write(stream, offset, data):
    stream.seek(offset)
    if stream.write(data) != len(data):
        raise EraseProofError("Short FAT32 image write.")


def status(v, value):
    struct.pack_into("<I", v.fat, 4, value)
    for copy in range(v.copies):
        write(v.stream, (v.reserved+copy*v.fat_sectors)*v.bps+4, struct.pack("<I", value))
    os.fsync(v.stream.fileno())


def remove(stream, entry):
    v = volume(stream)
    if not hasattr(v, "original_status"):
        v.original_status = struct.unpack_from("<I", v.fat, 4)[0]
        status(v, v.original_status & ~0x08000000)
    current = v.files[entry["path"]]
    for cluster in v.chain(current["cluster"]):
        struct.pack_into("<I", v.fat, cluster*4, 0)
    for offset in current["slots"]:
        write(stream, offset, b"\xe5"+bytes(31))


def free_runs(v, cancel=None):
    first = None
    maximum = max(1, 4*1024*1024//v.cluster_size)
    for cluster in range(2, v.clusters+3):
        if (cluster-2) % maximum == 0:
            checkpoint(cancel)
        free = cluster < v.clusters+2 and v.value(cluster) == 0
        if first is not None and (not free or cluster-first == maximum):
            yield first, cluster-first
            first = None
        if free and first is None:
            first = cluster


def zero(stream, offset, length, io):
    if nativeio.library() is None:
        write(stream, offset, bytes(length))
        io["buffered_bytes"] += length
        return
    prefix = min(length, (-offset) % nativeio.ALIGN)
    if prefix:
        nativeio.zero(stream.fileno(), offset, prefix, direct=False)
        offset, length = offset+prefix, length-prefix
        io["buffered_bytes"] += prefix
    aligned = length-length % nativeio.ALIGN
    if aligned:
        nativeio.zero(stream.fileno(), offset, aligned)
        offset, length = offset+aligned, length-aligned
        io["direct_bytes"] += aligned
    if length:
        nativeio.zero(stream.fileno(), offset, length, direct=False)
        io["buffered_bytes"] += length


def live_directories(v):
    yield v.chain(v.root)
    for entry in v.files.values():
        if entry["directory"] and v.value(entry["cluster"]):
            yield v.chain(entry["cluster"])


def scrub(stream, evidence, job, progress=None, cancel=None):
    v = volume(stream)
    io = {"direct_bytes": 0, "buffered_bytes": 0}
    cleared = directory_bytes = slack = 0
    for first, count in free_runs(v, cancel):
        zero(stream, v.offset(first), count*v.cluster_size, io)
        cleared += count
        if progress:
            progress("Clean FAT32 history", (first+count-2)/v.clusters, "Clearing every confirmed free cluster")
    for chain in live_directories(v):
        ended = False
        for cluster in chain:
            checkpoint(cancel)
            data = bytearray(v.read_cluster(cluster))
            changed = False
            for at in range(0, len(data), 32):
                ended |= data[at] == 0
                if ended or data[at] == 0xE5:
                    data[at:at+32] = bytes(32) if ended else b"\xe5"+bytes(31)
                    directory_bytes += 32
                    changed = True
            if changed:
                write(stream, v.offset(cluster), data)
    for entry in v.files.values():
        if entry["directory"] or not entry["cluster"] or not v.value(entry["cluster"]):
            continue
        for index, cluster in enumerate(v.chain(entry["cluster"])):
            at = max(0, entry["size"]-index*v.cluster_size)
            if at < v.cluster_size:
                zero(stream, v.offset(cluster)+at, v.cluster_size-at, io)
                slack += v.cluster_size-at
    for copy in range(v.copies):
        write(stream, (v.reserved+copy*v.fat_sectors)*v.bps, v.fat)
    for sector in (v.fsinfo, v.backup+v.fsinfo):
        if 0 < sector < v.reserved:
            stream.seek(sector*v.bps)
            data = bytearray(stream.read(v.bps))
            if data[:4] == b"RRaA" and data[484:488] == b"rrAa":
                data[488:496] = b"\xff"*8  # Let filesystem tools recalculate hints.
                write(stream, sector*v.bps, data)
    os.fsync(stream.fileno())
    status(v, v.original_status)
    return {"free_clusters_cleared": cleared, "directory_bytes_cleared": directory_bytes,
            "file_slack_bytes_cleared": slack, "io": io, "all_unallocated_history_cleared": True}


def verify_history(stream):
    v = volume(stream)
    checked = nonzero = dirty = metadata = slack = 0
    for first, count in free_runs(v):
        stream.seek(v.offset(first))
        data = stream.read(count*v.cluster_size)
        if len(data) != count*v.cluster_size:
            raise EraseProofError("Short FAT32 free-space readback.")
        value = len(data)-data.count(0)
        nonzero += value
        checked += count
        if value:
            dirty += sum(any(data[at:at+v.cluster_size]) for at in range(0, len(data), v.cluster_size))
    for chain in live_directories(v):
        ended = False
        for cluster in chain:
            data = v.read_cluster(cluster)
            for at in range(0, len(data), 32):
                entry = data[at:at+32]
                ended |= entry[0] == 0
                if ended or entry[0] == 0xE5:
                    payload = entry if ended else entry[1:]
                    metadata += len(payload)-payload.count(0)
    for entry in v.files.values():
        if entry["directory"]:
            continue
        for index, cluster in enumerate(v.chain(entry["cluster"])):
            at = max(0, entry["size"]-index*v.cluster_size)
            if at < v.cluster_size:
                payload = v.read_cluster(cluster)[at:]
                slack += len(payload)-payload.count(0)
    return {"passed": not (nonzero or metadata or slack), "free_clusters_checked": checked,
            "nonzero_free_bytes": nonzero, "nonzero_free_clusters": dirty,
            "nonzero_deleted_directory_bytes": metadata, "nonzero_file_slack_bytes": slack}


def erase_path(path, internal_path, confirmation, evidence_dir, progress=None, cancel=None):
    return erase_with(sys.modules[__name__], path, internal_path, confirmation, evidence_dir, progress, cancel)

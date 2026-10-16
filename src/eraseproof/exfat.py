"""Allocation-checked offline exFAT cleanup (single FAT, revision 1.0).

Layout follows Microsoft's public exFAT specification. No live mounts, repair,
TexFAT writes, vendor allocations or guessed cluster chains are accepted.
"""
import os
from pathlib import Path
import struct
import sys

from .carve import checkpoint
from .models import EraseProofError
from .offline import checked_image, erase_with, fingerprint_data, run
from .targets import open_target

name = "exfat"
consistency = "fsck.exfat -n passed"
cleanup_description = "Clearing free clusters, stale FAT links, inactive directory entries and file slack"


def require(condition, message):
    if not condition:
        raise EraseProofError(message)


def checksum(data, bits=16, skip=()):
    value, mask = 0, (1 << bits)-1
    for index, byte in enumerate(data):
        if index not in skip:
            value = (((value & 1) << (bits-1))+(value >> 1)+byte) & mask
    return value


class Volume:
    def __init__(self, stream):
        self.stream = stream
        self.length = os.fstat(stream.fileno()).st_size
        boot = self.read(0, 512)
        require(boot[3:11] == b"EXFAT   " and boot[510:512] == b"\x55\xaa", "Not an exFAT volume at offset zero.")
        require(9 <= boot[108] <= 12 and boot[109] <= 25-boot[108], "Invalid exFAT sector/cluster shifts.")
        self.bps, self.cluster_size = 1 << boot[108], 1 << (boot[108]+boot[109])
        self.sectors = struct.unpack_from("<Q", boot, 72)[0]
        self.fat_at, self.fat_sectors, self.heap, self.count, self.root = struct.unpack_from("<IIIII", boot, 80)
        self.flags = struct.unpack_from("<H", boot, 106)[0]
        require(boot[110] == 1 and struct.unpack_from("<H", boot, 104)[0] == 0x100,
                "Only single-FAT exFAT revision 1.0 is supported; TexFAT is refused.")
        require(not self.flags, "Dirty, failed-media, active-second-FAT or unknown volume flags are refused.")
        require(self.count and self.count <= 32*1024*1024 and self.fat_at >= 24 and
                self.heap >= self.fat_at+self.fat_sectors and
                (self.count+2)*4 <= self.fat_sectors*self.bps <= 256*1024*1024 and
                self.heap*self.bps+self.count*self.cluster_size <= self.sectors*self.bps <= self.length,
                "Invalid, truncated or excessively large exFAT allocation metadata.")
        regions = [self.read(at*self.bps, 12*self.bps) for at in (0, 12)]
        for region in regions:
            expected = checksum(region[:11*self.bps], 32, (106, 107, 112))
            require(region[11*self.bps:] == struct.pack("<I", expected)*(self.bps//4), "Invalid exFAT boot checksum.")
        require(all(a == b for index, (a, b) in enumerate(zip(*regions)) if index not in (106, 107, 112)),
                "Main/backup exFAT boot regions differ.")
        self.fat = bytearray(self.read(self.fat_at*self.bps, self.fat_sectors*self.bps))
        self.bitmap = None
        self.system, self.directories, self.files = [], [], {}
        self.root_chain = self.chain(self.root)
        root_entries = self.directory(self.root_chain)
        root_entries = root_entries[:next((index for index, (_, entry) in enumerate(root_entries) if entry[0] == 0), len(root_entries))]
        bitmap_entries = [entry for _, entry in root_entries if entry[0] == 0x81]
        upcase_entries = [entry for _, entry in root_entries if entry[0] == 0x82]
        require(len(bitmap_entries) == len(upcase_entries) == 1, "Expected exactly one bitmap and up-case table.")
        for entry in (bitmap_entries[0], upcase_entries[0]):
            first, size = struct.unpack_from("<IQ", entry, 20)
            require(size > 0 and size <= max((self.count+7)//8, 128*1024), "Invalid exFAT system allocation length.")
            chain = self.chain(first, size)
            payload = b"".join(self.cluster(cluster) for cluster in chain)[:size]
            if entry[0] == 0x81:
                require(entry[1] == 0 and size == (self.count+7)//8, "Invalid allocation bitmap flags/length.")
                self.bitmap = bytearray(payload)
                self.bitmap_chain = chain
            else:
                require(checksum(payload, 32) == struct.unpack_from("<I", entry, 4)[0], "Invalid up-case table checksum.")
            self.system.append((chain, size))
        self.claimed = bytearray(len(self.bitmap))
        for chain, _ in self.system:
            self.claim(chain)
        pending = [("", self.root_chain)]
        count = 0
        while pending:
            parent, chain = pending.pop()
            self.claim(chain)
            self.directories.append((parent, chain))
            slots = self.directory(chain)
            index = 0
            while index < len(slots):
                offset, entry = slots[index]
                if entry[0] == 0:
                    break
                if not entry[0] & 0x80:
                    index += 1
                    continue
                if entry[0] in (0x81, 0x82, 0x83) and not parent:
                    index += 1
                    continue
                require(entry[0] == 0x85 and 2 <= entry[1] <= 18, "Unsupported active exFAT directory entry/vendor allocation.")
                group = slots[index:index+entry[1]+1]
                require(len(group) == entry[1]+1, "Truncated exFAT entry set.")
                raw = b"".join(value for _, value in group)
                require(checksum(raw, skip=(2, 3)) == struct.unpack_from("<H", entry, 2)[0], "Invalid exFAT entry-set checksum.")
                stream_entry = group[1][1]
                name_entries = group[2:]
                require(stream_entry[0] == 0xC0 and stream_entry[1] in (1, 3) and
                        all(value[0] == 0xC1 for _, value in name_entries), "Unsupported exFAT stream/name entries.")
                units = stream_entry[3]
                require(1 <= units <= 255 and len(name_entries) == (units+14)//15, "Invalid exFAT filename length.")
                filename = b"".join(value[2:] for _, value in name_entries)[:units*2].decode("utf-16-le", errors="strict")
                require(filename not in (".", "..") and not any(ord(c) < 32 or c in '/\\:*?"<>|' for c in filename),
                        "Ambiguous exFAT filename; writes refused.")
                path = parent+"/"+filename
                require(path not in self.files, "Duplicate exFAT path.")
                valid = struct.unpack_from("<Q", stream_entry, 8)[0]
                first, size = struct.unpack_from("<IQ", stream_entry, 20)
                attributes = struct.unpack_from("<H", entry, 4)[0]
                require(valid <= size and not attributes & ~0x37, "Invalid exFAT stream length or attributes.")
                allocated = self.chain(first, size, bool(stream_entry[1] & 2))
                kind = "d" if attributes & 0x10 else "r"
                require(kind != "d" or size and valid == size, "Invalid exFAT directory stream length.")
                self.files[path] = {"path": path, "inode": str(offset), "kind": kind, "size": size,
                                    "valid": valid, "chain": allocated, "slots": [at for at, _ in group]}
                if kind == "d":
                    pending.append((path, allocated))
                else:
                    self.claim(allocated)
                count += 1
                require(count <= 1_000_000, "exFAT inventory exceeds the bounded entry limit.")
                index += len(group)
        require(all(a == b for a, b in zip(self.claimed[:-1], self.bitmap[:-1])) and
                all(self.allocated(cluster) == self.bit(self.claimed, cluster) for cluster in range(2, self.count+2)),
                "Allocation bitmap contains orphaned, overlapping or unsupported allocations.")

    def read(self, offset, size):
        require(0 <= offset <= self.length and 0 <= size <= self.length-offset, "exFAT read outside image.")
        self.stream.seek(offset)
        data = self.stream.read(size)
        require(len(data) == size, "Short exFAT read.")
        return data

    def write(self, offset, data):
        require(0 <= offset <= self.length and len(data) <= self.length-offset, "exFAT write outside image.")
        self.stream.seek(offset)
        require(self.stream.write(data) == len(data), "Short exFAT write.")

    def offset(self, cluster):
        require(2 <= cluster < self.count+2, "Cluster outside exFAT heap.")
        return self.heap*self.bps+(cluster-2)*self.cluster_size

    def cluster(self, cluster):
        return self.read(self.offset(cluster), self.cluster_size)

    def chain(self, first, length=None, contiguous=False):
        wanted = None if length is None else (length+self.cluster_size-1)//self.cluster_size
        if wanted == 0:
            require(first == 0, "Empty exFAT stream has allocated clusters.")
            return []
        self.offset(first)
        if contiguous:
            require(wanted and wanted <= self.count+2-first, "Contiguous exFAT allocation outside heap.")
            return list(range(first, first+wanted))
        result, seen = [], set()
        cluster = first
        while True:
            self.offset(cluster)
            require(cluster not in seen, "Cyclic exFAT chain.")
            seen.add(cluster)
            result.append(cluster)
            next_cluster = struct.unpack_from("<I", self.fat, cluster*4)[0]
            if next_cluster >= 0xFFFFFFF8:
                break
            require(next_cluster not in (0, 1, 0xFFFFFFF7), "Broken exFAT allocation chain.")
            cluster = next_cluster
        require(wanted is None or len(result) == wanted, "exFAT stream/chain lengths differ.")
        return result

    @staticmethod
    def bit(bitmap, cluster):
        return bool(bitmap[(cluster-2)//8] & (1 << ((cluster-2)%8)))

    def allocated(self, cluster):
        return self.bit(self.bitmap, cluster)

    def claim(self, chain):
        for cluster in chain:
            require(self.allocated(cluster) and not self.bit(self.claimed, cluster), "Free/overlapping cluster in allocated exFAT stream.")
            self.claimed[(cluster-2)//8] |= 1 << ((cluster-2)%8)

    def directory(self, chain):
        require(len(chain)*self.cluster_size <= 64*1024*1024, "Directory exceeds the bounded 64 MiB parser limit.")
        return [(self.offset(cluster)+at, data[at:at+32]) for cluster in chain
                for data in (self.cluster(cluster),) for at in range(0, len(data), 32)]

    def dirty(self, value):
        for base in (0, 12*self.bps):
            self.write(base+106, struct.pack("<H", self.flags | (2 if value else 0)))
        os.fsync(self.stream.fileno())

    def summary(self):
        return [{key: entry[key] for key in ("path", "inode", "kind", "size")} for entry in self.files.values()]


def volume(stream, fresh=False):
    if fresh or not hasattr(stream, "_eraseproof_exfat"):
        stream._eraseproof_exfat = Volume(stream)
    return stream._eraseproof_exfat


def check(stream):
    run(["fsck.exfat", "-n", f"/proc/self/fd/{stream.fileno()}"], fd=stream.fileno())


def entries(stream):
    return volume(stream, fresh=True).summary()


def prepare(stream, info, internal_path):
    normalized = "/"+internal_path.strip("/")
    require(normalized != "/" and all(part not in ("", ".", "..") for part in normalized.split("/")[1:]),
            "Select an exact, ordinary internal exFAT file/folder path.")
    check(stream)
    v = volume(stream, fresh=True)
    require(normalized in v.files, "Internal path does not exist.")
    found = v.summary()
    selected = [entry for entry in found if entry["path"] == normalized or entry["path"].startswith(normalized+"/")]
    return {"target": info, "internal_path": normalized, "confirmation": Path(info["path"]).name+":"+normalized,
            "selected": selected, "geometry": {"cluster_size": v.cluster_size, "clusters": v.count},
            "method": "exfat-allocation-and-global-offline-history-cleanup",
            "scope": "Current offline exFAT image: selected allocation, all free clusters/stale free FAT links, inactive directory entries and allocated stream slack. All deleted history on this volume is removed. Unrelated allocated file contents are hash-checked. Snapshots, changed live copies and physical remnants are outside this proof."}, found


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
        remaining, valid = current["size"], current["valid"]
        for cluster in current["chain"]:
            count = min(remaining, v.cluster_size)
            data = v.cluster(cluster)[:min(valid, count)]+bytes(max(0, count-valid))
            valid = max(0, valid-count)
            remaining -= count
            yield data
    return fingerprint_data(current, chunks())


def remove(stream, entry):
    v = volume(stream)
    if not getattr(v, "writing", False):
        v.dirty(True)
        v.writing = True
    current = v.files[entry["path"]]
    for cluster in current["chain"]:
        v.bitmap[(cluster-2)//8] &= ~(1 << ((cluster-2)%8))
        struct.pack_into("<I", v.fat, cluster*4, 0)
    for offset in current["slots"]:
        v.write(offset, b"\x01"+bytes(31))  # Inactive, not end-of-directory.


def scrub(stream, evidence, job, progress=None, cancel=None):
    v = volume(stream)
    cleared, directory_bytes, tail_bytes = 0, 0, 0
    # Check the bitmap, never infer free state from a possibly unused FAT entry.
    batch = max(1, 4*1024*1024//v.cluster_size)
    for first in range(2, v.count+2, batch):
        checkpoint(cancel)
        count = min(batch, v.count+2-first)
        run_start = None
        for index in range(count):
            cluster = first+index
            if not v.allocated(cluster):
                if run_start is None:
                    run_start = cluster
                struct.pack_into("<I", v.fat, cluster*4, 0)
                cleared += 1
            elif run_start is not None:
                v.write(v.offset(run_start), bytes((cluster-run_start)*v.cluster_size))
                run_start = None
        if run_start is not None:
            v.write(v.offset(run_start), bytes((first+count-run_start)*v.cluster_size))
        if progress:
            progress("Clean exFAT history", (first+count-2)/v.count, "Clearing every bitmap-confirmed free cluster")
    for _, chain in v.directories:
        if not all(v.allocated(cluster) for cluster in chain):
            continue
        ended = False
        for offset, entry in v.directory(chain):
            ended |= entry[0] == 0
            if ended or not entry[0] & 0x80:
                v.write(offset, bytes(32) if ended else b"\x01"+bytes(31))
                directory_bytes += 32
    for current in v.files.values():
        if current["kind"] == "r" and all(v.allocated(cluster) for cluster in current["chain"]):
            for index, cluster in enumerate(current["chain"]):
                start = max(0, current["valid"]-index*v.cluster_size)
                if start < v.cluster_size:
                    v.write(v.offset(cluster)+start, bytes(v.cluster_size-start))
                    tail_bytes += v.cluster_size-start
    for chain, size in v.system:
        if size % v.cluster_size:
            v.write(v.offset(chain[-1])+size % v.cluster_size, bytes(v.cluster_size-size % v.cluster_size))
    v.write(v.fat_at*v.bps, v.fat)
    for index, cluster in enumerate(v.bitmap_chain):
        data = v.bitmap[index*v.cluster_size:(index+1)*v.cluster_size]
        v.write(v.offset(cluster), data)
    used = sum(v.allocated(cluster) for cluster in range(2, v.count+2))
    for base in (0, 12*v.bps):
        v.write(base+112, bytes([used*100//v.count]))
    os.fsync(stream.fileno())
    v.dirty(False)
    return {"free_clusters_cleared": cleared, "directory_bytes_cleared": directory_bytes,
            "stream_slack_bytes_cleared": tail_bytes, "all_unallocated_history_cleared": True}


def verify_history(stream):
    v = volume(stream)
    checked = nonzero = dirty = stale = metadata_nonzero = slack_nonzero = 0
    def count_nonzero(data):
        return len(data)-data.count(0)
    for cluster in range(2, v.count+2):
        if not v.allocated(cluster):
            count = count_nonzero(v.cluster(cluster))
            nonzero += count
            dirty += bool(count)
            checked += 1
            stale += struct.unpack_from("<I", v.fat, cluster*4)[0] != 0
    for _, chain in v.directories:
        ended = False
        for _, entry in v.directory(chain):
            ended |= entry[0] == 0
            if ended or not entry[0] & 0x80:
                metadata_nonzero += count_nonzero(entry if ended else entry[1:])
    streams = [(entry["chain"], entry["valid"]) for entry in v.files.values() if entry["kind"] == "r"]+v.system
    for chain, valid in streams:
        for index, cluster in enumerate(chain):
            start = max(0, valid-index*v.cluster_size)
            if start < v.cluster_size:
                slack_nonzero += count_nonzero(v.cluster(cluster)[start:])
    return {"passed": not (nonzero or stale or metadata_nonzero or slack_nonzero), "free_clusters_checked": checked,
            "nonzero_free_clusters": dirty, "nonzero_free_bytes": nonzero, "stale_free_fat_links": stale,
            "nonzero_inactive_directory_bytes": metadata_nonzero, "nonzero_stream_slack_bytes": slack_nonzero}


def erase_path(path, internal_path, confirmation, evidence_dir, progress=None, cancel=None):
    return erase_with(sys.modules[__name__], path, internal_path, confirmation, evidence_dir, progress, cancel)

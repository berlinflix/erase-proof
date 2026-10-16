"""Offline FAT32 file/folder erasure with allocation-aware residue cleanup.

Only regular, unmounted images are writable here. No guessed cluster chains,
live-filesystem block writes, journal edits or automatic filesystem repair.
"""
import struct

from .carve import checkpoint
from .models import EraseProofError


class Fat32:
    def __init__(self, stream, length):
        self.stream, self.length = stream, length
        stream.seek(0)
        boot = stream.read(512)
        if len(boot) != 512 or boot[510:512] != b"\x55\xaa":
            raise EraseProofError("Not a FAT32 volume image (partition images only; offset zero).")
        self.bps = struct.unpack_from("<H", boot, 11)[0]
        self.spc = boot[13]
        self.reserved = struct.unpack_from("<H", boot, 14)[0]
        self.copies = boot[16]
        self.fat_sectors = struct.unpack_from("<I", boot, 36)[0]
        self.total_sectors = struct.unpack_from("<I", boot, 32)[0]
        self.root = struct.unpack_from("<I", boot, 44)[0]
        self.fsinfo = struct.unpack_from("<H", boot, 48)[0]
        self.backup = struct.unpack_from("<H", boot, 50)[0]
        flags = struct.unpack_from("<H", boot, 40)[0]
        if self.bps not in (512, 1024, 2048, 4096) or self.spc not in (1, 2, 4, 8, 16, 32, 64, 128):
            raise EraseProofError("Unsupported FAT sector/cluster geometry.")
        if not self.reserved or self.copies not in (1, 2) or not self.fat_sectors or flags & 0x80:
            raise EraseProofError("Unsupported FAT32 mirroring or layout.")
        if struct.unpack_from("<H", boot, 17)[0] or struct.unpack_from("<H", boot, 22)[0] or struct.unpack_from("<H", boot, 42)[0]:
            raise EraseProofError("FAT12/FAT16 or nonzero FAT32 version is not supported for targeted writes.")
        self.data_sector = self.reserved+self.copies*self.fat_sectors
        self.cluster_size = self.bps*self.spc
        self.clusters = (self.total_sectors-self.data_sector)//self.spc
        if self.clusters < 65525 or self.total_sectors*self.bps > length or (self.clusters+2)*4 > self.fat_sectors*self.bps:
            raise EraseProofError("Invalid or truncated FAT32 layout.")
        stream.seek(self.reserved*self.bps)
        self.fat = bytearray(stream.read(self.fat_sectors*self.bps))
        if len(self.fat) != self.fat_sectors*self.bps:
            raise EraseProofError("Short FAT read.")
        for copy in range(1, self.copies):
            stream.seek((self.reserved+copy*self.fat_sectors)*self.bps)
            if stream.read(len(self.fat)) != self.fat:
                raise EraseProofError("FAT copies differ. Targeted writes require a consistent volume.")

    def value(self, cluster):
        if not 2 <= cluster < self.clusters+2:
            raise EraseProofError("Cluster address is outside the volume.")
        return struct.unpack_from("<I", self.fat, cluster*4)[0] & 0x0fffffff

    def offset(self, cluster):
        self.value(cluster)
        return (self.data_sector+(cluster-2)*self.spc)*self.bps

    def chain(self, cluster):
        if cluster == 0:
            return []
        result, seen = [], set()
        while True:
            if cluster in seen:
                raise EraseProofError("Cyclic FAT chain. Writes refused.")
            seen.add(cluster)
            result.append(cluster)
            value = self.value(cluster)
            if value >= 0x0ffffff8:
                return result
            if value in (0, 1, 0x0ffffff7):
                raise EraseProofError("Broken/bad/free cluster in an allocated chain. Writes refused.")
            cluster = value

    def read_cluster(self, cluster):
        self.stream.seek(self.offset(cluster))
        data = self.stream.read(self.cluster_size)
        if len(data) != self.cluster_size:
            raise EraseProofError("Short cluster read.")
        return data

    def free_sectors(self, cancel=None, progress=None):
        batch = max(1, 4*1024*1024//self.cluster_size)
        for first in range(2, self.clusters+2, batch):
            checkpoint(cancel)
            count = min(batch, self.clusters+2-first)
            self.stream.seek(self.offset(first))
            data = self.stream.read(count*self.cluster_size)
            if len(data) != count*self.cluster_size:
                raise EraseProofError("Short read during free-space sweep.")
            if any(data):
                for index in range(count):
                    cluster = first+index
                    if self.value(cluster) != 0:
                        continue
                    for at in range(0, self.cluster_size, self.bps):
                        part = data[index*self.cluster_size+at:index*self.cluster_size+at+self.bps]
                        if any(part):
                            yield self.offset(cluster)+at, part
            if progress:
                progress("History sweep", (first+count-2)/self.clusters, "Scanning proven unallocated clusters for known sector copies")

    @staticmethod
    def long_fragment(entry):
        raw = entry[1:11]+entry[14:26]+entry[28:32]
        return raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0].replace("\uffff", "")

    def entries(self, cluster):
        pending = []
        for allocated in self.chain(cluster):
            data = self.read_cluster(allocated)
            for at in range(0, len(data), 32):
                entry = data[at:at+32]
                if entry[0] == 0:
                    return
                if entry[0] == 0xe5 and not any(entry[1:]):
                    pending = []
                    continue
                offset = self.offset(allocated)+at
                if entry[11] == 0x0f:
                    pending.append((offset, entry))
                    continue
                slots = [p[0] for p in pending]+[offset]
                raw_name = b"".join(p[1][1:11]+p[1][14:26]+p[1][28:32] for p in reversed(pending))
                long_name = raw_name.decode("utf-16-le", errors="strict").split("\x00", 1)[0].replace("\uffff", "")
                pending = []
                if entry[11] & 8 or entry[:1] == b".":
                    continue
                short_raw = entry[:11]
                stem = short_raw[:8].decode("cp437").rstrip()
                ext = short_raw[8:].decode("cp437").rstrip()
                short_name = stem+("."+ext if ext else "")
                if entry[0] == 0xe5:
                    short_name = "_"+short_name[1:]
                start = struct.unpack_from("<H", entry, 26)[0] | struct.unpack_from("<H", entry, 20)[0] << 16
                yield {"name": long_name or short_name, "short_name": short_name, "short_hex": short_raw.hex(),
                       "cluster": start, "directory": bool(entry[11] & 0x10), "deleted": entry[0] == 0xe5,
                       "size": struct.unpack_from("<I", entry, 28)[0], "slots": slots}

    def walk(self):
        seen = set()
        def visit(cluster, parent):
            if cluster in seen:
                raise EraseProofError("A directory cluster is cross-linked. Writes refused.")
            seen.add(cluster)
            for entry in self.entries(cluster):
                item = {**entry, "path": parent+"/"+entry["name"]}
                yield item
                if item["directory"] and not item["deleted"]:
                    yield from visit(item["cluster"], item["path"])
        yield from visit(self.root, "")


def _selection(volume, internal_path):
    wanted = "/"+internal_path.strip("/")
    if wanted == "/" or any(part in (".", "..") for part in wanted.split("/")[1:]):
        raise EraseProofError("Select a file/folder inside the FAT32 image, not the root or a traversal path.")
    entries = list(volume.walk())
    found = next((e for e in entries if not e["deleted"] and e["path"].casefold() == wanted.casefold()), None)
    if found is None:
        raise EraseProofError("Live target path was not found in the FAT32 directory tree.")
    chosen = [e for e in entries if not e["deleted"] and (e is found or e["path"].casefold().startswith(found["path"].casefold()+"/"))]
    clusters, ownership = set(), {c: "/" for c in volume.chain(volume.root)}
    for entry in entries:
        if entry["deleted"]:
            continue
        chain = volume.chain(entry["cluster"])
        if not entry["directory"] and len(chain)*volume.cluster_size < entry["size"]:
            raise EraseProofError("File chain is shorter than its advertised size.")
        for cluster in chain:
            if cluster in ownership:
                raise EraseProofError("Cross-linked file/directory clusters. Targeted writes refused.")
            ownership[cluster] = entry["path"]
        if entry in chosen:
            clusters.update(chain)
    if volume.root in clusters:
        raise EraseProofError("Root directory cannot be erased by a targeted operation.")
    return entries, chosen, sorted(clusters)


def erase_path(image, internal_path, confirmation, evidence_dir, progress=None, cancel=None):
    from .fat import erase_path as operation
    return operation(image, internal_path, confirmation, evidence_dir, progress, cancel)

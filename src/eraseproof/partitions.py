"""Read-only MBR/GPT partition discovery with bounds and GPT checksum checks."""
import struct
import uuid
import zlib

from .models import EraseProofError
from .targets import describe, open_target


def inspect(path, sector_size=512):
    if sector_size not in (512, 4096):
        raise EraseProofError("Logical sector size must be 512 or 4096 bytes.")
    info = describe(path)
    total = info["size"]//sector_size
    result = {"source": info, "sector_size": sector_size, "table": "volume-or-unknown", "partitions": [], "warnings": []}
    with open_target(path) as stream:
        mbr = stream.read(512)
        if len(mbr) < 512 or mbr[510:] != b"\x55\xaa":
            return result
        primary = []
        for index in range(4):
            entry = mbr[446+16*index:462+16*index]
            kind = entry[4]
            start, sectors = struct.unpack_from("<II", entry, 8)
            if kind and sectors:
                primary.append((index+1, kind, start, sectors))
        if not primary:
            return result
        if any(kind == 0xee for _, kind, _, _ in primary):
            stream.seek(sector_size)
            header = stream.read(sector_size)
            if header[:8] != b"EFI PART":
                raise EraseProofError("Protective MBR exists but the primary GPT is missing.")
            size, expected_crc = struct.unpack_from("<II", header, 12)
            if not 92 <= size <= sector_size:
                raise EraseProofError("Invalid GPT header size.")
            checked = bytearray(header[:size])
            checked[16:20] = bytes(4)
            if zlib.crc32(checked) & 0xffffffff != expected_crc:
                raise EraseProofError("GPT header checksum failed.")
            current, backup, first, last = struct.unpack_from("<QQQQ", header, 24)
            table_lba, count, entry_size, expected_array_crc = struct.unpack_from("<QIII", header, 72)
            if current != 1 or not 1 < backup < total or not 1 < first <= last < total or not 1 <= count <= 4096 or not 128 <= entry_size <= 4096 or entry_size % 8 or count*entry_size > 16*1024*1024 or table_lba < 2 or table_lba*sector_size+count*entry_size > first*sector_size:
                raise EraseProofError("GPT partition table has invalid bounds.")
            stream.seek(table_lba*sector_size)
            array = stream.read(count*entry_size)
            if zlib.crc32(array) & 0xffffffff != expected_array_crc:
                raise EraseProofError("GPT entry-array checksum failed.")
            result["table"] = "GPT"
            for index in range(count):
                entry = array[index*entry_size:(index+1)*entry_size]
                if entry[:16] == bytes(16):
                    continue
                start, end = struct.unpack_from("<QQ", entry, 32)
                if not first <= start <= end <= last:
                    raise EraseProofError("GPT partition extends beyond usable sectors.")
                result["partitions"].append({"number": index+1, "start_sector": start, "sectors": end-start+1,
                    "type": str(uuid.UUID(bytes_le=entry[:16])), "name": entry[56:128].decode("utf-16-le", errors="replace").rstrip("\x00")})
            result["warnings"].append("Primary GPT and its entry array checked; backup GPT consistency is not evaluated.")
        else:
            result["table"] = "MBR"
            for number, kind, start, sectors in primary:
                if start < 1 or start+sectors > total:
                    # A volume boot sector may resemble an MBR. Never return a guessed offset.
                    raise EraseProofError("MBR entries exceed source bounds; select a volume offset explicitly.")
                if kind in (5, 0xf, 0x85):
                    result["warnings"].append(f"Extended partition {number}: logical EBR entries require manual inspection with mmls.")
                    continue
                result["partitions"].append({"number": number, "start_sector": start, "sectors": sectors, "type": f"0x{kind:02x}", "name": f"Partition {number}"})
        ordered = sorted(result["partitions"], key=lambda p: p["start_sector"])
        if any(a["start_sector"]+a["sectors"] > b["start_sector"] for a, b in zip(ordered, ordered[1:])):
            raise EraseProofError("Overlapping partitions: offset selection is blocked.")
    # TSK uses 512-byte sectors unless -b is supplied. Expose the equivalent
    # offset explicitly so a 4Kn GPT is never silently misinterpreted.
    for partition in result["partitions"]:
        partition["tsk_offset"] = partition["start_sector"]*(sector_size//512)
    return result

"""JPEG marker and ZIP central-directory boundaries, independent of filenames."""
import struct

from .models import Candidate


def jpeg(stream, offset, limit):
    def read(at, size):
        if at < offset or at+size > limit:
            return b""
        stream.seek(at)
        return stream.read(size)
    if read(offset, 2) != b"\xff\xd8":
        return None
    pos, framed, scanned = offset+2, False, False
    for _ in range(100000):
        if read(pos, 1) != b"\xff":
            return None
        pos += 1
        fills = 0
        marker = read(pos, 1)
        while marker == b"\xff" and fills < 4096:
            pos += 1
            fills += 1
            marker = read(pos, 1)
        if not marker or fills >= 4096:
            return None
        pos += 1
        code = marker[0]
        if code == 0xd9:
            return Candidate(offset, pos-offset, "JPEG", 95,
                             ["JPEG application segments and scan markers parsed", "Outer image EOI reached; embedded thumbnail footers ignored"]) if framed and scanned else None
        if code in (0, 0xd8) or 0xd0 <= code <= 0xd7:
            return None
        if code == 1:
            continue
        header = read(pos, 2)
        if len(header) != 2:
            return None
        length = struct.unpack(">H", header)[0]
        if length < 2 or pos+length > limit:
            return None
        if code in (0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf):
            if length < 8:
                return None
            frame = read(pos+2, 5)
            if len(frame) != 5 or not int.from_bytes(frame[1:3], "big") or not int.from_bytes(frame[3:5], "big"):
                return None
            framed = True
        pos += length
        if code != 0xda:
            continue
        scanned = True
        # Skip entropy byte stuffing and restart markers in bounded chunks.
        found = False
        while pos < limit:
            block = read(pos, min(4*1024*1024, limit-pos))
            at = block.find(b"\xff")
            while at >= 0:
                end = at+1
                while end < len(block) and block[end] == 0xff:
                    end += 1
                if end == len(block):
                    if pos+len(block) == limit or end-at >= 4096:
                        return None
                    pos += at
                    break
                if block[end] != 0 and not 0xd0 <= block[end] <= 0xd7:
                    pos += at
                    found = True
                    break
                at = block.find(b"\xff", end+1)
            else:
                pos += len(block)
                continue
            if found:
                break
        if not found:
            return None
    return None


def zip_archive(stream, offset, limit):
    def read(at, size):
        if at < offset or size < 0 or at+size > limit:
            return b""
        stream.seek(at)
        return stream.read(size)
    def central(eocd):
        header = read(eocd, 22)
        if len(header) != 22:
            return None
        _, disk, cd_disk, disk_count, count, size, start, comment = struct.unpack("<4s4H2IH", header)
        if disk or cd_disk or disk_count != count or eocd+22+comment > limit:
            return None
        boundary = eocd
        if count == 65535 or size == 0xffffffff or start == 0xffffffff:
            locator = read(eocd-20, 20)
            if len(locator) != 20 or locator[:4] != b"PK\x06\x07":
                return None
            _, locator_disk, record_at, disks = struct.unpack("<4sIQI", locator)
            record = read(offset+record_at, 56)
            if locator_disk or disks != 1 or len(record) != 56 or record[:4] != b"PK\x06\x06":
                return None
            _, record_size, _, _, disk, cd_disk, disk_count, count, size, start = struct.unpack("<4sQ2H2I4Q", record)
            if disk or cd_disk or count != disk_count or record_size < 44 or offset+record_at+12+record_size > eocd-20:
                return None
            boundary = offset+record_at
        if not 1 <= count <= 100000 or size > limit-offset or start > limit-offset:
            return None
        at, end = offset+start, offset+start+size
        if end > boundary:
            return None
        for _ in range(count):
            entry = read(at, 46)
            if len(entry) != 46 or entry[:4] != b"PK\x01\x02":
                return None
            name, extra, note = struct.unpack_from("<3H", entry, 28)
            local = struct.unpack_from("<I", entry, 42)[0]
            if struct.unpack_from("<H", entry, 34)[0] or at+46+name+extra+note > end:
                return None
            if local == 0xffffffff:
                payload = read(at+46+name, extra)
                field_at, resolved = 0, False
                while field_at+4 <= len(payload):
                    tag, length = struct.unpack_from("<HH", payload, field_at)
                    value = payload[field_at+4:field_at+4+length]
                    if len(value) != length:
                        return None
                    if tag == 1:
                        skip = 8*(struct.unpack_from("<I", entry, 24)[0] == 0xffffffff)+8*(struct.unpack_from("<I", entry, 20)[0] == 0xffffffff)
                        if skip+8 > len(value):
                            return None
                        local = struct.unpack_from("<Q", value, skip)[0]
                        resolved = True
                        break
                    field_at += 4+length
                if not resolved:
                    return None
            if read(offset+local, 4) != b"PK\x03\x04":
                return None
            at += 46+name+extra+note
        if at != end:
            signature = read(at, 6)
            if len(signature) != 6 or signature[:4] != b"PK\x05\x05" or at+6+struct.unpack_from("<H", signature, 4)[0] != end:
                return None
        return Candidate(offset, eocd+22+comment-offset, "ZIP", 95,
                         ["ZIP central directory, entry count and local header offsets agree", "End marker inside member data is not used as the archive boundary"])
    cursor, carry, attempts = offset+4, b"", 0
    while cursor < limit and attempts < 100000:
        data = read(cursor, min(4*1024*1024, limit-cursor))
        if not data:
            break
        window, base = carry+data, cursor-len(carry)
        at = window.find(b"PK\x05\x06")
        while at >= 0:
            attempts += 1
            result = central(base+at)
            if result:
                return result
            if attempts >= 100000:
                return None
            at = window.find(b"PK\x05\x06", at+4)
        carry = window[-3:]
        cursor += len(data)
    return None

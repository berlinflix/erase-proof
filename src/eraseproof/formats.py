"""Length/structure parsers for additional forensic carving families."""
import struct
import zlib

from .models import Candidate

SIGNATURES = ((b"GIF87a", "GIF"), (b"GIF89a", "GIF"), (b"BM", "BMP"),
              (b"RIFF", "RIFF"), (b"OggS", "OGG"), (b"ftyp", "MP4"),
              (b"SQLite format 3\x00", "SQLITE"), (b"{\\rtf", "RTF"),
              (b"\x7fELF", "ELF"), (b"7z\xbc\xaf\x27\x1c", "7Z"),
              (b"\x1f\x8b\x08", "GZIP"), (b"ustar", "TAR"))


def identify(stream, offset, kind, total, maximum):
    limit = min(total, offset+maximum)
    def read(at, size):
        if at < offset or at+size > limit:
            return b""
        stream.seek(at)
        return stream.read(size)
    def result(end, family=None, confidence=85, evidence="Container length and boundaries valid"):
        if offset < end <= limit:
            return Candidate(offset, end-offset, family or kind, confidence, [evidence])
        return None
    header = read(offset, min(64, limit-offset))
    if kind == "BMP" and len(header) >= 26:
        size = struct.unpack_from("<I", header, 2)[0]
        pixel = struct.unpack_from("<I", header, 10)[0]
        dib = struct.unpack_from("<I", header, 14)[0]
        if dib in (12, 40, 52, 56, 64, 108, 124) and 14+dib <= pixel < size:
            return result(offset+size, confidence=90)
    elif kind == "RIFF" and len(header) >= 12 and header[8:12] in (b"WAVE", b"AVI "):
        end = offset+8+struct.unpack_from("<I", header, 4)[0]
        pos = offset+12
        if end > limit:
            return None
        chunks = []
        while pos+8 <= end:
            head = read(pos, 8)
            size = struct.unpack_from("<I", head, 4)[0]
            if pos+8+size > end:
                return None
            chunks.append(head[:4])
            if head[:4] == b"LIST" and size >= 4:
                chunks.append(read(pos+8, 4))
            pos += 8+size+(size%2)
        avi = header[8:12] == b"AVI "
        if pos == end and (b"hdrl" in chunks and b"movi" in chunks if avi else b"fmt " in chunks and b"data" in chunks):
            return result(end, "AVI" if avi else "WAV", 85 if avi else 95)
    elif kind == "SQLITE" and len(header) >= 64:
        page = struct.unpack_from(">H", header, 16)[0]
        page = 65536 if page == 1 else page
        pages = struct.unpack_from(">I", header, 28)[0]
        if page >= 512 and page <= 65536 and page & (page-1) == 0 and header[18] in (1, 2) and header[19] in (1, 2) and pages:
            return result(offset+page*pages, confidence=90)
    elif kind == "7Z" and len(header) >= 32:
        crc = struct.unpack_from("<I", header, 8)[0]
        if zlib.crc32(header[12:32]) & 0xffffffff != crc:
            return None
        next_offset, next_size, next_crc = struct.unpack_from("<QQI", header, 12)
        end = offset+32+next_offset+next_size
        if next_size > 16*1024*1024 or end > limit:
            return None
        data = read(offset+32+next_offset, next_size)
        if zlib.crc32(data) & 0xffffffff == next_crc:
            return result(end, confidence=96, evidence="7z start-header and next-header CRCs valid")
    elif kind == "GIF" and len(header) >= 13:
        pos = offset+13+(3*(1 << ((header[10] & 7)+1)) if header[10] & 0x80 else 0)
        frames = 0
        while pos < limit:
            marker = read(pos, 1)
            if marker == b";" and frames:
                return result(pos+1, confidence=95)
            if marker == b"!":
                pos += 2
            elif marker == b",":
                image = read(pos, 10)
                if len(image) != 10:
                    return None
                pos += 10+(3*(1 << ((image[9] & 7)+1)) if image[9] & 0x80 else 0)+1
                frames += 1
            else:
                return None
            while pos < limit:
                length = read(pos, 1)
                if not length:
                    return None
                pos += 1
                if length == b"\x00":
                    break
                pos += length[0]
    elif kind == "OGG":
        pos, serial, sequence = offset, None, None
        while pos+27 <= limit:
            page = read(pos, 27)
            if page[:4] != b"OggS" or page[4] != 0:
                return None
            current = struct.unpack_from("<I", page, 14)[0]
            if serial is None:
                serial = current
            if current != serial:
                return None
            number = struct.unpack_from("<I", page, 18)[0]
            if sequence is None and not page[5] & 2 or sequence is not None and number != (sequence+1) & 0xffffffff:
                return None
            sequence = number
            segments = read(pos+27, page[26])
            if len(segments) != page[26]:
                return None
            end = pos+27+len(segments)+sum(segments)
            if end > limit:
                return None
            # Ogg CRC uses a different polynomial from zlib's CRC32.
            body = bytearray(read(pos, end-pos))
            expected = struct.unpack_from("<I", body, 22)[0]
            body[22:26] = bytes(4)
            crc = 0
            for byte in body:
                crc ^= byte << 24
                for _ in range(8):
                    crc = ((crc << 1) ^ (0x04c11db7 if crc & 0x80000000 else 0)) & 0xffffffff
            if crc != expected:
                return None
            if page[5] & 4:
                return result(end, confidence=98, evidence="Ogg page sequence and CRCs valid; EOS present")
            pos = end
    elif kind == "MP4":
        pos, atoms = offset, []
        while pos+8 <= limit and len(atoms) < 100000:
            atom = read(pos, 8)
            size = struct.unpack_from(">I", atom)[0]
            name = atom[4:8]
            head_length = 8
            if size == 1:
                extra = read(pos+8, 8)
                if len(extra) != 8:
                    return None
                size, head_length = struct.unpack(">Q", extra)[0], 16
            if size < head_length or pos+size > limit or any(c < 32 or c > 126 for c in name):
                break
            atoms.append(name)
            pos += size
        if atoms and atoms[0] == b"ftyp" and b"mdat" in atoms and (b"moov" in atoms or b"moof" in atoms):
            return result(pos, confidence=85, evidence="ISO BMFF box boundaries valid; ftyp and media/movie boxes present")
    elif kind == "RTF":
        pos, depth, escaped = offset, 0, False
        while pos < limit:
            data = read(pos, min(65536, limit-pos))
            for index, byte in enumerate(data):
                if escaped:
                    escaped = False
                elif byte == 92:
                    escaped = True
                elif byte == 123:
                    depth += 1
                    if depth > 4096:
                        return None
                elif byte == 125:
                    depth -= 1
                    if depth == 0:
                        return result(pos+index+1, confidence=70, evidence="Balanced RTF group boundaries; binary-control extensions not validated")
            pos += len(data)
    elif kind == "GZIP":
        obj, pos, expanded = zlib.decompressobj(31), offset, 0
        try:
            while pos < limit:
                data = read(pos, min(65536, limit-pos))
                produced = obj.decompress(data, 4*1024*1024)
                expanded += len(produced)
                if expanded > 256*1024*1024 or obj.unconsumed_tail:
                    return None
                pos += len(data)
                if obj.eof:
                    return result(pos-len(obj.unused_data), confidence=99, evidence="Gzip member decompressed; checksum and trailer valid")
        except zlib.error:
            return None
    elif kind == "ELF" and len(header) >= 52 and header[4] in (1, 2) and header[5] in (1, 2):
        endian, width = ("<" if header[5] == 1 else ">"), header[4]
        if width == 2 and len(header) >= 64:
            phoff, shoff = struct.unpack_from(endian+"QQ", header, 32)
            ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(endian+"HHHHH", header, 52)
        else:
            phoff, shoff = struct.unpack_from(endian+"II", header, 28)
            ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(endian+"HHHHH", header, 40)
        if phnum > 16384 or shnum > 16384 or ehsize not in (52, 64) or phnum and phentsize < (56 if width == 2 else 32) or shnum and shentsize < (64 if width == 2 else 40):
            return None
        end = max(ehsize, phoff+phentsize*phnum, shoff+shentsize*shnum)
        if offset+end > limit:
            return None
        for index in range(phnum):
            data = read(offset+phoff+index*phentsize, phentsize)
            if width == 2:
                at, size = struct.unpack_from(endian+"Q", data, 8)[0], struct.unpack_from(endian+"Q", data, 32)[0]
            else:
                at, size = struct.unpack_from(endian+"I", data, 4)[0], struct.unpack_from(endian+"I", data, 16)[0]
            end = max(end, at+size)
        for index in range(shnum):
            data = read(offset+shoff+index*shentsize, shentsize)
            if struct.unpack_from(endian+"I", data, 4)[0] == 8:
                continue
            at, size = struct.unpack_from(endian+("QQ" if width == 2 else "II"), data, 24 if width == 2 else 16)
            end = max(end, at+size)
        return result(offset+end, confidence=95, evidence="ELF program/section bounds validated; file was never executed")
    elif kind == "TAR":
        pos, entries = offset, 0
        while pos+512 <= limit:
            data = read(pos, 512)
            if data == bytes(512):
                if entries and read(pos+512, 512) == bytes(512):
                    return result(pos+1024, confidence=97, evidence="Tar header checksums and two-block terminator valid")
                return None
            if data[257:262] != b"ustar":
                return None
            try:
                checksum = int(data[148:156].strip(b"\x00 ") or b"0", 8)
                size = int(data[124:136].strip(b"\x00 ") or b"0", 8)
            except ValueError:
                return None
            if sum(data[:148])+8*32+sum(data[156:]) != checksum:
                return None
            entries += 1
            pos += 512+((size+511)//512)*512
    return None

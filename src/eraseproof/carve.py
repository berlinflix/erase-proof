"""Bounded-memory contiguous carving. Sources are opened read-only."""
import hashlib
import os
from pathlib import Path
import struct
import zipfile
import zlib
import io
import re

from .models import Candidate, Cancelled, EraseProofError
from .targets import describe, open_target
from . import formats

CHUNK = 4 * 1024 * 1024
MAX_CANDIDATE = 256 * 1024 * 1024
SIGNATURES = ((b"\x89PNG\r\n\x1a\n", "PNG"), (b"%PDF-", "PDF"),
              (b"\xff\xd8\xff", "JPEG"), (b"PK\x03\x04", "ZIP")) + formats.SIGNATURES


def checkpoint(cancel):
    if cancel and cancel():
        raise Cancelled("Operation cancelled. A partially overwritten target is not certified.")


def identify_pdf(stream, offset, limit):
    """Require a resolving startxref, preserve EOF EOL, follow contiguous updates."""
    cursor, carry, previous = offset+5, b"", None
    while cursor < limit:
        stream.seek(cursor)
        data = stream.read(min(CHUNK, limit-cursor))
        if not data:
            break
        window, base = carry+data, cursor-len(carry)
        at = window.find(b"%%EOF")
        while at >= 0:
            end = base+at+5
            start = max(offset, end-256)
            stream.seek(start)
            trailer = stream.read(end-start)
            match = re.search(rb"startxref\s+(\d+)\s+%%EOF$", trailer)
            valid = False
            if match:
                xref = offset+int(match[1])
                if offset < xref < end:
                    stream.seek(xref)
                    head = stream.read(min(32, end-xref))
                    valid = head.startswith(b"xref") or bool(re.match(rb"\d+\s+\d+\s+obj\b", head))
            if valid:
                stream.seek(end)
                eol = stream.read(min(2, limit-end))
                end += 2 if eol.startswith(b"\r\n") else 1 if eol[:1] in (b"\r", b"\n") else 0
                previous = Candidate(offset, end-offset, "PDF", 80,
                                     ["PDF trailer has a resolving startxref", "Final EOF line ending preserved"])
                stream.seek(end)
                following = stream.read(min(4096, limit-end)).lstrip(b" \t\r\n")
                if not re.match(rb"(?:\d+\s+\d+\s+obj\b|xref\b|trailer\b)", following):
                    return previous
            at = window.find(b"%%EOF", at+5)
        carry = window[-4:]
        cursor += len(data)
    if previous:
        previous.method = "pdf-earlier-revision"
        previous.confidence = 55
        previous.evidence.append("A contiguous incremental update is incomplete; this is an earlier valid revision, not the complete original file")
    return previous


def identify(stream, offset, kind, total, max_candidate=MAX_CANDIDATE):
    if kind not in ("PNG", "PDF", "JPEG", "ZIP"):
        return formats.identify(stream, offset, kind, total, max_candidate)
    limit = min(total, offset + max_candidate)
    stream.seek(offset)
    if kind == "PDF":
        return identify_pdf(stream, offset, limit)
    if kind == "PNG":
        if stream.read(8) != SIGNATURES[0][0]:
            return None
        pos = offset + 8
        crc_valid, first, chunks = True, True, 0
        while pos + 12 <= limit and chunks < 100000:
            stream.seek(pos)
            head = stream.read(8)
            if len(head) != 8:
                return None
            length, name = struct.unpack(">I4s", head)
            if pos + 12 + length > limit or length > 64 * 1024 * 1024:
                return None
            if first and (name != b"IHDR" or length != 13):
                return None
            first = False
            crc = zlib.crc32(name)
            remaining = length
            while remaining:
                data = stream.read(min(remaining, CHUNK))
                if not data:
                    return None
                remaining -= len(data)
                crc = zlib.crc32(data, crc)
            expected = stream.read(4)
            if len(expected) != 4:
                return None
            crc_valid &= crc & 0xffffffff == struct.unpack(">I", expected)[0]
            pos += length + 12
            chunks += 1
            if name == b"IEND":
                if length:
                    return None
                return Candidate(offset, pos-offset, kind, 99 if crc_valid else 45,
                                 ["PNG boundaries complete", "Chunk CRCs match" if crc_valid else "CRC mismatch"])
        return None
    marker = {"PDF": b"%%EOF", "JPEG": b"\xff\xd9", "ZIP": b"PK\x05\x06"}[kind]
    stream.seek(offset + 4)
    pos, carry = offset + 4, b""
    while pos < limit:
        data = stream.read(min(CHUNK, limit-pos))
        if not data:
            break
        window = carry + data
        found = window.find(marker)
        if found >= 0:
            end = pos-len(carry)+found+len(marker)
            if kind == "ZIP":
                stream.seek(end)
                tail = stream.read(18)
                if len(tail) != 18:
                    return None
                comment_len = struct.unpack_from("<H", tail, 16)[0]
                end += 18 + comment_len
                if end > limit:
                    return None
            return Candidate(offset, end-offset, kind, {"PDF": 70, "JPEG": 60, "ZIP": 65}[kind],
                             ["Header and end marker present", "Contiguous candidate; complete format semantics not validated"])
        carry = window[-(len(marker)-1):]
        pos += len(data)
    return None


def reassemble_png(stream, offset, total, maximum_gap=65536):
    # One missing chunk-boundary gap, limited to 64 KiB; no unconstrained
    # permutation search and no claim of arbitrary fragment reconstruction.
    stream.seek(offset)
    data = stream.read(min(total-offset, 8*1024*1024+maximum_gap))
    if data[:8] != SIGNATURES[0][0]:
        return None
    pos, valid_chunks = 8, 0
    while pos+12 <= len(data):
        size = struct.unpack_from(">I", data, pos)[0]
        if size > 8*1024*1024 or pos+12+size > len(data):
            break
        crc = zlib.crc32(data[pos+4:pos+8+size]) & 0xffffffff
        if crc != struct.unpack_from(">I", data, pos+8+size)[0]:
            break
        if valid_chunks == 0 and data[pos+4:pos+8] != b"IHDR":
            return None
        if data[pos+4:pos+8] == b"IEND":
            return None
        valid_chunks += 1
        pos += 12+size
    if not valid_chunks:
        return None
    for suffix in range(pos+1, min(len(data)-12, pos+maximum_gap)+1):
        if data[suffix+4:suffix+8] not in (b"IDAT", b"IEND", b"PLTE", b"tEXt", b"iTXt", b"zTXt", b"pHYs", b"gAMA", b"sRGB"):
            continue
        reconstructed = data[:pos]+data[suffix:]
        result = identify(io.BytesIO(reconstructed), 0, "PNG", len(reconstructed), len(reconstructed))
        if result and result.confidence == 99:
            return Candidate(offset, result.length, "PNG", 98,
                             ["One PNG chunk-boundary gap reconstructed", "All reconstructed chunk CRCs valid", f"Skipped {suffix-pos} bytes; search bounded to 64 KiB"],
                             method="png-gap-reconstruction", segments=[[offset, pos], [offset+suffix, result.length-pos]])
    return None


def scan(path, progress=None, cancel=None, max_candidate=MAX_CANDIDATE, stream=None, length=None, fragmented=False):
    owned = stream is None
    if owned:
        target = describe(path)
        stream, length = open_target(path), target["size"]
    candidates, seen, offset, carry = [], set(), 0, b""
    try:
        while offset < length:
            checkpoint(cancel)
            stream.seek(offset)
            data = stream.read(min(CHUNK, length-offset))
            if not data:
                raise EraseProofError("Short read while scanning; source changed or media read failed.")
            window, base = carry + data, offset-len(carry)
            hits = []
            for signature, kind in SIGNATURES:
                at = window.find(signature)
                while at >= 0:
                    candidate_offset = base+at-(4 if kind == "MP4" else 257 if kind == "TAR" else 0)
                    if candidate_offset >= 0:
                        hits.append((candidate_offset, kind))
                    at = window.find(signature, at+1)
            for at, kind in sorted(hits):
                if at in seen or any(any(start <= at < start+size for start, size in c.segments or [[c.offset, c.length]]) for c in candidates):
                    continue
                seen.add(at)
                result = identify(stream, at, kind, length, max_candidate)
                if fragmented and kind == "PNG" and (not result or result.confidence < 90):
                    rebuilt = reassemble_png(stream, at, length)
                    result = rebuilt or result
                if result:
                    result.name = f"carved_{at:012x}.{kind.lower()}"
                    candidates.append(result)
            offset += len(data)
            carry = window[-264:]
            if progress:
                progress("Recover", offset/max(length, 1), f"Scanned {offset:,} / {length:,} bytes; {len(candidates)} candidates")
        return candidates
    finally:
        if owned:
            stream.close()


def extract(path, candidate, output_dir):
    directory = Path(output_dir).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)
    name = Path(candidate.name).name.replace("\x00", "") or f"carved_{candidate.offset:x}.bin"
    destination = directory / name
    # Exclusive creation prevents overwriting any existing evidence or source.
    with open_target(path) as source, destination.open("xb") as output:
        digest = hashlib.sha256()
        try:
            for offset, length in candidate.segments or [[candidate.offset, candidate.length]]:
                source.seek(offset)
                remaining = length
                while remaining:
                    data = source.read(min(CHUNK, remaining))
                    if not data:
                        raise EraseProofError("Short read during extraction.")
                    output.write(data)
                    digest.update(data)
                    remaining -= len(data)
            output.flush()
            os.fsync(output.fileno())
        except BaseException:
            output.close()
            destination.unlink(missing_ok=True)
            raise
    candidate.output, candidate.sha256 = str(destination), digest.hexdigest()
    if candidate.file_type == "ZIP":
        try:
            with zipfile.ZipFile(destination) as archive:
                names = set(archive.namelist())
            for prefix, family in (("word/", "DOCX"), ("xl/", "XLSX"), ("ppt/", "PPTX")):
                if "[Content_Types].xml" in names and any(name.startswith(prefix) for name in names):
                    candidate.file_type = family
                    candidate.evidence.append("Office Open XML package identified: "+family)
                    break
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError):
            candidate.evidence.append("Archive validation failed or encryption unsupported")
    from .validators import isolated
    validation = isolated(destination, candidate.file_type)
    candidate.evidence.append(validation["detail"])
    if validation["status"] == "valid":
        candidate.confidence = max(candidate.confidence, 98) if candidate.method != "pdf-earlier-revision" else min(candidate.confidence, 55)
    elif validation["status"] == "invalid":
        candidate.confidence = min(candidate.confidence, 35)
    return candidate

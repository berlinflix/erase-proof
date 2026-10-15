"""Bounded-memory contiguous carving. Sources are opened read-only."""
import hashlib
import os
from pathlib import Path
import struct
import zipfile
import zlib

from .models import Candidate, Cancelled, EraseProofError
from .targets import describe, open_target

CHUNK = 4 * 1024 * 1024
MAX_CANDIDATE = 256 * 1024 * 1024
SIGNATURES = ((b"\x89PNG\r\n\x1a\n", "PNG"), (b"%PDF-", "PDF"),
              (b"\xff\xd8\xff", "JPEG"), (b"PK\x03\x04", "ZIP"))


def checkpoint(cancel):
    if cancel and cancel():
        raise Cancelled("Operation cancelled. A partially overwritten target is not certified.")


def identify(stream, offset, kind, total, max_candidate=MAX_CANDIDATE):
    limit = min(total, offset + max_candidate)
    stream.seek(offset)
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


def scan(path, progress=None, cancel=None, max_candidate=MAX_CANDIDATE, stream=None, length=None):
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
                    hits.append((base+at, kind))
                    at = window.find(signature, at+1)
            for at, kind in sorted(hits):
                if at in seen or any(c.offset <= at < c.offset+c.length for c in candidates):
                    continue
                seen.add(at)
                result = identify(stream, at, kind, length, max_candidate)
                if result:
                    result.name = f"carved_{at:012x}.{kind.lower()}"
                    candidates.append(result)
            offset += len(data)
            carry = window[-7:]
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
        source.seek(candidate.offset)
        remaining, digest = candidate.length, hashlib.sha256()
        try:
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
                valid = archive.testzip() is None
            candidate.evidence.append("ZIP members and CRCs valid" if valid else "ZIP member CRC failed")
            candidate.confidence = 98 if valid else 35
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError):
            candidate.evidence.append("Archive validation failed or encryption unsupported")
    return candidate

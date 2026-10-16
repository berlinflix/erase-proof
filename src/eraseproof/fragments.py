"""Bounded two-fragment reconstruction, with format-specific acceptance gates.

No file names, source hashes or demo ground truth participate in the search.
Missing/overwritten bytes and arbitrary permutations are not reconstructible.
"""
import io
import itertools
import struct
import time
import zipfile
import zlib

from .models import Candidate, EraseProofError

MAX_FILE = 8*1024*1024
MAX_GAP = 64*1024
MAX_PREFIX = 256*1024
MAX_STRUCTURAL_GAP = 1024*1024
MAX_STRUCTURAL_PREFIX = 8*1024*1024


class Budget:
    def __init__(self, attempts=65536, seconds=60):
        self.attempts = attempts
        self.deadline = time.monotonic()+seconds

    def take(self, cancel=None):
        from .carve import checkpoint
        checkpoint(cancel)
        if self.attempts <= 0 or time.monotonic() >= self.deadline:
            raise EraseProofError("Bifragment search resource limit reached. Recovery is incomplete; narrow the source range or disable fragment search.")
        self.attempts -= 1


def zip_gap(data):
    """The physical central directory shift supplies a gap hypothesis."""
    cursor = 0
    for _ in range(512):
        at = data.find(b"PK\x05\x06", cursor)
        if at < 0:
            break
        cursor = at+4
        if at+22 > len(data):
            break
        _, disk, cd_disk, disk_count, count, size, start, comment = struct.unpack_from("<4s4H2IH", data, at)
        gap = at-size-start
        if not disk and not cd_disk and disk_count == count and 0 < count <= 512 and 0 < gap <= MAX_STRUCTURAL_GAP and at+22+comment <= len(data):
            return gap
    return None


def pdf_gap(data):
    import re
    for match in re.finditer(rb"startxref\s+(\d+)\s+%%EOF", data):
        expected = int(match[1])
        if expected >= len(data):
            continue
        at = data.find(b"xref", expected, min(len(data), expected+MAX_GAP+4))
        if at > expected and at < match.start() and at+4 <= len(data) and data[at+4:at+5] in b"\r\n ":
            return at-expected
    return None


def zip_valid(data):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if not entries or len(entries) > 512 or sum(e.file_size for e in entries) > 32*1024*1024:
                return False
            if any(e.flag_bits & 1 or e.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) for e in entries):
                return False
            return archive.testzip() is None
    except (ValueError, OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error):
        return False


def pdf_offsets_valid(data):
    """Require classic xref entries to resolve exact object/generation headers."""
    import re
    trailers = list(re.finditer(rb"startxref\s+(\d+)\s+%%EOF", data))
    if not trailers:
        return False
    xref = int(trailers[-1][1])
    if data[xref:xref+4] != b"xref":
        return False  # compressed xref reconstruction needs another strategy
    checked = 0
    for section in re.finditer(rb"(?:^|[\r\n])(\d+)\s+(\d+)\s*[\r\n]+((?:\d{10} \d{5} [nf][ \r\n]+)+)", data[xref:]):
        base, count = int(section[1]), int(section[2])
        entries = re.findall(rb"(\d{10}) (\d{5}) ([nf])", section[3])
        if count != len(entries) or checked+count > 10000:
            return False
        for index, (at, generation, status) in enumerate(entries):
            if status == b"n":
                position = int(at)
                if not re.match(str(base+index).encode()+rb"\s+"+str(int(generation)).encode()+rb"\s+obj\b", data[position:position+64]):
                    return False
                checked += 1
    return checked > 0


def png_valid(payload):
    import tempfile
    from pathlib import Path
    from .validators import check
    with tempfile.TemporaryDirectory(prefix='eraseproof-png-') as folder:
        path = Path(folder)/'candidate.png'
        path.write_bytes(payload)
        return check(path, 'PNG')['status'] == 'valid'


def reconstruct(stream, offset, kind, total, budget, cancel=None):
    from .carve import identify
    if kind not in ("PNG", "ZIP", "PDF", "JPEG"):
        return None
    stream.seek(offset)
    maximum_gap = MAX_STRUCTURAL_GAP if kind in ('ZIP', 'PDF') else MAX_GAP
    data = stream.read(min(total-offset, MAX_FILE+maximum_gap))
    if len(data) < 512:
        return None
    gap = zip_gap(data) if kind == "ZIP" else pdf_gap(data) if kind == "PDF" else None
    if kind in ("ZIP", "PDF") and gap is None:
        return None
    gaps = [gap] if gap else range(512, MAX_GAP+1, 512)
    # Filesystem fragment boundaries are sector-aligned in the source; the
    # signature need not itself start at a sector boundary.
    first = (-offset) % 512 or 512
    maximum_prefix = MAX_STRUCTURAL_PREFIX if gap or kind == 'JPEG' else MAX_PREFIX
    splits = list(range(first, min(maximum_prefix, len(data)-12)+1, 512))
    inferred = []
    if kind == 'JPEG':
        from .jpegcheck import probe
        _, failure = probe(data[:MAX_FILE])
        if 0 < failure < first:
            return None  # Invalid header before any eligible sector boundary.
        if failure:
            nearest = max(first, (failure//512)*512+first%512)
            splits.sort(key=lambda split: abs(split-nearest))
            splits = splits[:1024]
            # A decoder often notices inserted bytes at the next real marker.
            # Try that inferred gap across nearby sector boundaries before the
            # general search. No original-file hash or benchmark layout is used.
            for split in splits:
                estimate = ((failure-split+511)//512)*512
                inferred.extend((split, estimate+delta) for delta in (0, -512, 512, -1024, 1024)
                                if 0 < estimate+delta <= MAX_GAP)
    hypotheses = itertools.chain(inferred, ((split, skip) for split in splits for skip in gaps))
    seen = set()
    for split, skip in hypotheses:
            if (split, skip) in seen:
                continue
            seen.add((split, skip))
            budget.take(cancel)
            if split+skip >= len(data):
                continue
            rebuilt = data[:split]+data[split+skip:]
            result = identify(io.BytesIO(rebuilt), 0, kind, len(rebuilt), MAX_FILE)
            if result is None or (kind == "PNG" and result.confidence != 99):
                continue
            payload = rebuilt[:result.length]
            if split >= result.length or result.length > MAX_FILE:
                continue
            if kind == "ZIP" and not zip_valid(payload):
                continue
            if kind == "PNG" and not png_valid(payload):
                continue
            if kind == "PDF" and not pdf_offsets_valid(payload):
                continue
            if kind == "JPEG":
                from .jpegcheck import valid
                if not valid(payload):
                    continue
            strong = kind in ("PNG", "ZIP")
            return Candidate(offset, result.length, kind, 98 if strong else 60,
                ["Two source fragments reconstructed at a sector boundary", f"Skipped {skip} unrelated bytes",
                 "All chunk/member CRCs valid" if strong else "Structurally plausible reconstruction; no checksum authenticates the original PDF content/JPEG pixels",
                 "Search limits: 8 MiB file; PNG 256 KiB prefix/64 KiB gap, ZIP 8 MiB prefix/1 MiB inferred gap, JPEG decoder-guided sector hypotheses/64 KiB gap; bounded work and time"],
                method="bifragment-gap-reconstruction", segments=[[offset, split], [offset+split+skip, result.length-split]])
    return None


def isolated(stream, offset, kind, total, budget, cancel=None):
    """One restricted, unprivileged parser process for each fragment search."""
    import json
    import os
    from pathlib import Path
    import subprocess
    import sys
    from . import external
    budget.take(cancel)
    # Reopen the pinned inode read-only even when the parent owns a writable
    # erase/verify descriptor. The parsing worker never inherits write access.
    fd = os.open(f'/proc/self/fd/{stream.fileno()}', os.O_RDONLY | os.O_CLOEXEC)
    try:
        executable = [sys.executable, '--cli', '_fragments'] if getattr(sys, 'frozen', False) else [sys.executable, '-m', 'eraseproof.fragments']
        environment = dict(os.environ)
        if not getattr(sys, 'frozen', False):
            environment['PYTHONPATH'] = str(Path(__file__).resolve().parent.parent)
        remaining = max(.1, min(10, budget.deadline-time.monotonic()))
        process = subprocess.Popen([*executable, str(fd), str(offset), kind, str(total), str(budget.attempts), str(remaining)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   pass_fds=(fd,), start_new_session=True, env=environment)
        try:
            while process.poll() is None:
                from .carve import checkpoint
                checkpoint(cancel)
                if time.monotonic() >= budget.deadline+1:
                    raise EraseProofError('Bifragment worker exceeded its time limit; recovery is incomplete.')
                time.sleep(.05)
            out, err = process.communicate(timeout=2)
            if process.returncode or len(out) > 1024*1024:
                raise EraseProofError('Bifragment parser stopped or exceeded resource limits; recovery is incomplete.')
            report = json.loads(out)
            budget.attempts = min(budget.attempts, int(report['attempts_remaining']))
            if report.get('error'):
                raise EraseProofError(report['error'])
            return Candidate(**report['candidate']) if report.get('candidate') else None
        finally:
            external.stop(process)
    finally:
        os.close(fd)


def worker(fd, offset, kind, total, attempts, seconds):
    import json
    import os
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (1024*1024*1024, 1024*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU, (32, 32))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Load trusted codec modules before dropping root: a source installation's
    # venv may be in a private operator cache directory. No media is parsed
    # until privileges have been dropped and only the read-only FD remains.
    from PIL import Image
    Image.init()
    # Preload our trusted parser code too: root may run a source installation
    # under a private home directory which nobody cannot traverse after setuid.
    from .carve import identify, reassemble_png
    from .validators import check
    from .jpegcheck import library as jpeg_library
    jpeg_library()
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
    budget = Budget(attempts, seconds)
    result, error = None, None
    try:
        with os.fdopen(fd, 'rb', buffering=0) as stream:
            current = identify(stream, offset, kind, total)
            valid = current is not None and current.confidence >= 90
            if valid and kind == 'JPEG' and current.length <= 8*1024*1024:
                from .jpegcheck import valid as jpeg_valid
                stream.seek(offset)
                valid = jpeg_valid(stream.read(current.length))
            if not valid:
                if kind == 'PNG':
                    result = reassemble_png(stream, offset, total, budget=budget)
                    if result:
                        payload = bytearray()
                        for start, size in result.segments:
                            stream.seek(start)
                            payload.extend(stream.read(size))
                        if not png_valid(bytes(payload)):
                            result = None
                if result is None:
                    result = reconstruct(stream, offset, kind, total, budget)
    except Exception as exception:
        error = str(exception)[:1000]
    print(json.dumps({'candidate': result.to_dict() if result else None, 'attempts_remaining': budget.attempts, 'error': error}))


if __name__ == '__main__':
    import sys
    worker(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), float(sys.argv[6]))

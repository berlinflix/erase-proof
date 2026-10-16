"""Run risky format parsers in a bounded, separate process."""
import json
import os
from pathlib import Path
import subprocess
import sys
from functools import lru_cache


@lru_cache(maxsize=1)
def sqlite_library():
    import ctypes
    library = ctypes.CDLL(str(Path(__file__).parent/'resources/native/liberaseproof_sqlite.so'))
    library.ep_sqlite_valid.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
    library.ep_sqlite_valid.restype = ctypes.c_int
    return library


def check(path, family):
    try:
        if family in ("PNG", "JPEG", "GIF", "BMP"):
            import warnings
            from PIL import Image
            Image.MAX_IMAGE_PIXELS = 25_000_000
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(path) as image:
                    image.verify()
                with Image.open(path) as image:
                    frames = getattr(image, "n_frames", 1)
                    if frames > 500:
                        return {"status": "bounded", "detail": "Animation exceeds 500-frame validation limit"}
                    for index in range(frames):
                        image.seek(index)
                        image.load()
            return {"status": "valid", "detail": "Image decoded successfully within parser resource limits"}
        if family == "PDF":
            from pypdf import PdfReader
            reader = PdfReader(path, strict=True)
            if reader.is_encrypted:
                return {"status": "bounded", "detail": "Encrypted PDF: structure detected, content not decrypted"}
            if len(reader.pages) > 10000:
                return {"status": "bounded", "detail": "PDF exceeds 10,000-page validation limit"}
            for page in reader.pages:
                tuple(page.mediabox)
            return {"status": "valid", "detail": "PDF xref/object/page graph parsed in strict mode"}
        if family == "SQLITE":
            if str(path).startswith('/proc/self/fd/'):
                library = sqlite_library()
                data = Path(path).read_bytes()
                valid = bool(library.ep_sqlite_valid(data, len(data)))
                return {'status': 'valid' if valid else 'invalid', 'detail': 'SQLite immutable in-memory quick_check after privilege drop'}
            import sqlite3
            with sqlite3.connect(Path(path).absolute().as_uri()+"?mode=ro&immutable=1", uri=True) as db:
                rows = db.execute("PRAGMA quick_check").fetchall()
            return {"status": "valid" if rows == [("ok",)] else "invalid", "detail": "SQLite quick_check: "+str(rows[:3])}
        if family in ("ZIP", "DOCX", "XLSX", "PPTX"):
            import zipfile
            with zipfile.ZipFile(path) as archive:
                members = archive.infolist()
                if len(members) > 10000 or sum(m.file_size for m in members) > 128*1024*1024:
                    return {"status": "bounded", "detail": "Archive exceeds validation member/expanded-byte limit"}
                bad = archive.testzip()
            return {"status": "valid" if bad is None else "invalid", "detail": "ZIP members and CRCs valid" if bad is None else "ZIP member CRC mismatch"}
        return {"status": "structural-only", "detail": "Native container boundary checks applied"}
    except Exception as error:
        return {"status": "invalid", "detail": str(error)[:300]}


def isolated(path, family):
    if family not in ("PNG", "JPEG", "GIF", "BMP", "PDF", "SQLITE", "ZIP", "DOCX", "XLSX", "PPTX"):
        return {"status": "structural-only", "detail": "Native container boundary checks applied"}
    command = [sys.executable, "--cli", "_validate", str(path), family] if getattr(sys, "frozen", False) else [sys.executable, "-m", "eraseproof.validators", str(path), family]
    try:
        environment = dict(os.environ)
        if not getattr(sys, "frozen", False):
            environment["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)+os.pathsep+environment.get("PYTHONPATH", "")
        result = subprocess.run(command, capture_output=True, text=True, timeout=9, env=environment)
        if result.returncode:
            return {"status": "bounded", "detail": "Validation worker stopped or exceeded resource limits"}
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, ValueError):
        return {"status": "bounded", "detail": "Format validation exceeded 9-second time limit"}


def worker(path, family):
    import resource
    import stat
    resource.setrlimit(resource.RLIMIT_AS, (768*1024*1024, 768*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU, (6, 6))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    anonymous = None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 256*1024*1024:
            raise ValueError('Validation source must be an ordinary bounded candidate file')
        if os.geteuid() == 0:
            # A sealed anonymous copy permits parsing private evidence without
            # granting the codec worker root or filesystem write privileges.
            import fcntl
            from PIL import Image
            from pypdf import PdfReader
            import zipfile
            import sqlite3
            sqlite_library()
            Image.init()
            anonymous = os.memfd_create('eraseproof-parser', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            while data := os.read(fd, 4*1024*1024):
                view = memoryview(data)
                while view:
                    written = os.write(anonymous, view)
                    if not written:
                        raise OSError('Short parser copy write')
                    view = view[written:]
            os.fchmod(anonymous, 0o444)
            fcntl.fcntl(anonymous, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
            path = f'/proc/self/fd/{anonymous}'
            os.close(fd)
            fd = -1
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
        print(json.dumps(check(path, family)))
    except Exception as error:
        print(json.dumps({'status': 'bounded', 'detail': str(error)[:300]}))
    finally:
        if fd >= 0:
            os.close(fd)
        if anonymous is not None:
            os.close(anonymous)


if __name__ == "__main__":
    worker(sys.argv[1], sys.argv[2])

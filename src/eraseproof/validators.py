"""Run risky format parsers in a bounded, separate process."""
import json
import os
from pathlib import Path
import subprocess
import sys


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
            import sqlite3
            with sqlite3.connect(Path(path).resolve().as_uri()+"?mode=ro&immutable=1", uri=True) as db:
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
    resource.setrlimit(resource.RLIMIT_AS, (768*1024*1024, 768*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU, (6, 6))
    print(json.dumps(check(path, family)))


if __name__ == "__main__":
    worker(sys.argv[1], sys.argv[2])

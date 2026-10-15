"""Independent filesystem recovery through the real Sleuth Kit executables."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess

from .models import Candidate, EraseProofError


def available():
    return all(shutil.which(name) for name in ("fls", "icat"))


def deleted(path, sector_offset=0):
    if not available():
        raise EraseProofError("The Sleuth Kit is not installed. Install Ubuntu package 'sleuthkit'.")
    command = ["fls", "-d", "-r", "-p", "-F", "-o", str(sector_offset), str(Path(path).resolve())]
    if sector_offset < 0:
        raise EraseProofError("Sector offset cannot be negative.")
    try:
        result = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=120)
    except subprocess.TimeoutExpired:
        raise EraseProofError("fls exceeded its 120-second time limit.") from None
    if result.returncode:
        raise EraseProofError(result.stderr.strip() or "fls could not parse this filesystem.")
    candidates = []
    for line in result.stdout.splitlines():
        match = re.match(r"^\S+\s+\*\s+(\d[\d-]*)(?:\(realloc\))?:\s*(.*)$", line)
        if match:
            inode, name = match.groups()
            candidates.append(Candidate(0, 0, Path(name).suffix.lstrip(".").upper() or "FILE", 0,
                                        ["Deleted filesystem directory entry reported by fls", "Recoverability requires extraction; fragments may be missing"],
                                        name=name, method="sleuthkit-metadata", inode=inode))
    return candidates


def recover(path, candidate, output_dir, sector_offset=0):
    if not re.fullmatch(r"\d[\d-]*", candidate.inode):
        raise EraseProofError("Invalid metadata address.")
    root = Path(output_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^\w.() -]", "_", Path(candidate.name).name)[:180] or "recovered.bin"
    destination = root / f"inode_{candidate.inode}_{safe_name}"
    with destination.open("xb") as output:
        try:
            result = subprocess.run(["icat", "-r", "-o", str(sector_offset), str(Path(path).resolve()), candidate.inode],
                                    stdout=output, stderr=subprocess.PIPE, timeout=180)
        except subprocess.TimeoutExpired:
            output.close()
            destination.unlink(missing_ok=True)
            raise EraseProofError("icat exceeded its 180-second time limit; partial extraction removed.") from None
        output.flush()
        os.fsync(output.fileno())
    if result.returncode:
        destination.unlink(missing_ok=True)
        raise EraseProofError(result.stderr.decode(errors="replace").strip() or "icat failed")
    digest = hashlib.sha256()
    with destination.open("rb") as stream:
        for block in iter(lambda: stream.read(4*1024*1024), b""):
            digest.update(block)
    candidate.output, candidate.sha256, candidate.length = str(destination), digest.hexdigest(), destination.stat().st_size
    candidate.evidence.append("Bytes extracted by icat -r; compare with ground truth when available")
    return candidate

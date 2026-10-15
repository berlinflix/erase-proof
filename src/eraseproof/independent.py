"""Independent PhotoRec and Sleuth Kit attack reports with explicit failures."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from . import tsk
from .carve import checkpoint
from .targets import describe
from .models import EraseProofError
from .runtime import system_environment


def attack(path, output_dir, sector_offset=0, progress=None, cancel=None, timeout=180):
    source = describe(path)
    if sector_offset < 0:
        raise EraseProofError("Sector offset cannot be negative.")
    if source["kind"] != "image":
        raise EraseProofError("Independent attack extraction currently requires an acquired image, not a live device.")
    root = Path(output_dir).resolve()
    root.mkdir(parents=True, exist_ok=False)
    report = {"source": source, "tools": [], "complete": True, "recovered_files": 0,
              "scope": "Independent tool outputs and errors are preserved. Unrecognized filesystems are not counted as a clean forensic result."}
    checkpoint(cancel)
    if shutil.which("photorec"):
        destination = root/"photorec"
        log = root/"photorec.log"
        command = ["photorec", "/log", "/logname", str(log), "/d", str(destination), "/cmd", source["path"],
                   "partition_none,options,mode_ext2,fileopt,everything,enable,wholespace,search"]
        started = time.monotonic()
        try:
            result = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                                    env={**system_environment(), "TERM": "dumb"})
            (root/"photorec.stdout.log").write_bytes(result.stdout)
            (root/"photorec.stderr.log").write_bytes(result.stderr)
            files = [p for directory in root.glob("photorec.*") if directory.is_dir() for p in directory.rglob("*") if p.is_file() and p.name != "report.xml"]
            tool = {"tool": "PhotoRec", "status": "completed" if result.returncode == 0 else "failed", "returncode": result.returncode,
                    "files": [{"path": str(p), "bytes": p.stat().st_size} for p in files], "recovered_files": len(files),
                    "duration_seconds": time.monotonic()-started, "log": str(log)}
        except subprocess.TimeoutExpired:
            tool = {"tool": "PhotoRec", "status": "timeout", "recovered_files": None, "duration_seconds": time.monotonic()-started}
        report["tools"].append(tool)
        report["complete"] &= tool["status"] == "completed"
        report["recovered_files"] += tool.get("recovered_files") or 0
    else:
        report["tools"].append({"tool": "PhotoRec", "status": "unavailable", "recovered_files": None})
        report["complete"] = False
    checkpoint(cancel)
    if progress:
        progress("Independent attack", .7, "PhotoRec result collected; checking deleted filesystem metadata")
    if tsk.available():
        try:
            candidates = tsk.deleted(path, sector_offset)
            extracted = []
            for candidate in candidates:
                checkpoint(cancel)
                extracted.append(tsk.recover(path, candidate, root/"sleuthkit", sector_offset).to_dict())
            report["tools"].append({"tool": "Sleuth Kit", "status": "completed", "recovered_files": len(extracted), "files": extracted})
            report["recovered_files"] += len(extracted)
        except EraseProofError as error:
            report["tools"].append({"tool": "Sleuth Kit", "status": "filesystem-unrecognized-or-error", "recovered_files": None, "detail": str(error)})
            report["metadata_coverage"] = "Not established by Sleuth Kit: see exact error"
            report["complete"] = False
    else:
        report["tools"].append({"tool": "Sleuth Kit", "status": "unavailable", "recovered_files": None})
        report["complete"] = False
    (root/"attack.json").write_text(json.dumps(report, indent=2)+"\n")
    return report

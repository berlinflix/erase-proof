"""Independent PhotoRec and Sleuth Kit attack reports with explicit failures."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import time
import xml.etree.ElementTree as ET

from . import tsk
from .carve import checkpoint
from .targets import describe, open_target, find_device, descendants
from .models import EraseProofError
from . import external


def bulk_tool():
    bundled = Path(__file__).parent/"resources"/"native"/"bulk_extractor"
    return str(bundled) if bundled.is_file() else shutil.which("bulk_extractor")


def bulk_completion(destination, expected_bytes):
    path = destination/"report.xml"
    try:
        if path.stat().st_size > 16*1024*1024:
            raise ValueError("Completion report exceeds the 16 MiB bound")
        data = path.read_bytes()
        if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
            raise ValueError("Unexpected XML declarations")
        tree = ET.fromstring(data)
        total = tree.find(".//{*}total_bytes")
        actual = int(total.text) if total is not None else None
        exceptions = [element for element in tree.iter() if element.tag.rsplit("}", 1)[-1] == "exception"]
        alerts = destination/"alerts.txt"
        scanner_errors = False
        if alerts.is_file():
            with alerts.open("rb") as file:
                scanner_errors = any(b"<exception>" in line or b"<unknown_exception>" in line for line in file)
        complete = actual == expected_bytes and not exceptions and not scanner_errors
        return {"complete": complete, "bytes_reported": actual, "expected_bytes": expected_bytes,
                "reported_exceptions": len(exceptions), "scanner_errors": bool(scanner_errors),
                "report_sha256": hashlib.sha256(data).hexdigest()}
    except (OSError, ValueError, ET.ParseError) as error:
        return {"complete": False, "detail": str(error)}


def attack(path, output_dir, sector_offset=0, progress=None, cancel=None, timeout=180, *, stream=None):
    source = describe(path)
    if sector_offset < 0:
        raise EraseProofError("Sector offset cannot be negative.")
    if source["kind"] == "block-device":
        ancestor = Path(output_dir).expanduser().resolve()
        while not ancestor.exists():
            ancestor = ancestor.parent
        root, _ = find_device(path)
        if any(os.stat(child["name"]).st_rdev == ancestor.stat().st_dev for child in descendants(root)):
            raise EraseProofError("Independent recovery output is on the source disk; select a different disk.")
    if stream is None:
        with open_target(path) as pinned:
            return attack(path, output_dir, sector_offset, progress, cancel, timeout, stream=pinned)
    opened = os.fstat(stream.fileno())
    current = os.stat(path, follow_symlinks=False)
    if (opened.st_dev, opened.st_ino, opened.st_rdev) != (current.st_dev, current.st_ino, current.st_rdev):
        raise EraseProofError("Source identity changed before independent recovery.")
    if stat.S_ISREG(opened.st_mode) and opened.st_size != source["size"]:
        raise EraseProofError("Source size changed before independent recovery.")
    fd = stream.fileno()
    image = f"/proc/self/fd/{fd}"
    root = Path(output_dir).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"source": source, "tools": [], "complete": True, "recovered_files": 0,
              "scope": "Independent tool outputs and errors are preserved. Unrecognized filesystems are not counted as a clean forensic result."}
    # PhotoRec's FAT handler can extract the filesystem as one .fat container.
    # Let a 1–8 GiB volume finish without removing that attack or suppressing
    # its output. All tool outputs share the same bounded case budget.
    output_budget = max(8*1024**3, min(16*1024**3, source['size']*2+64*1024**2))
    container_limit = min(output_budget, max(256*1024**2, source['size']))
    checkpoint(cancel)
    if progress:
        progress("Independent attack", 0, "Running PhotoRec against the pinned source")
    if shutil.which("photorec"):
        destination = root/"photorec"
        log = root/"photorec.log"
        command = ["photorec", "/log", "/logname", str(log), "/d", str(destination), "/cmd", image,
                   "partition_none,options,mode_ext2,fileopt,everything,enable,wholespace,search"]
        result = external.run(command, root, "photorec", timeout, cancel, fd,
                              output_limit=output_budget, per_file_limit=container_limit)
        files = [p for directory in root.glob("photorec.*") if directory.is_dir() for p in directory.rglob("*") if p.is_file() and p.name != "report.xml"]
        tool = {"tool": "PhotoRec", **result, "files": [{"path": str(p), "bytes": p.stat().st_size} for p in files],
                "recovered_files": len(files), "log": str(log)}
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
        extracted = []
        metadata_status = "filesystem-unrecognized-or-error"
        try:
            started = time.monotonic()
            listing = external.run(["fls", "-d", "-r", "-p", "-F", "-o", str(sector_offset), image],
                                   root, "sleuthkit-list", timeout, cancel, fd, output_limit=output_budget)
            if listing["status"] != "completed":
                if listing["status"] != "failed" or listing.get("returncode") != 1:
                    metadata_status = listing["status"]
                detail = Path(listing["stderr_log"]).read_bytes()[-4000:].decode(errors="replace") if listing.get("stderr_log") else listing["status"]
                raise EraseProofError(detail or "Sleuth Kit listing failed")
            candidates = tsk.parse_deleted(Path(listing["stdout_log"]).read_text(errors="replace"))
            if len(candidates) > 10_000:
                metadata_status = "candidate-limit"
                raise EraseProofError("Independent metadata candidate limit exceeded.")
            folder = root/"sleuthkit"
            folder.mkdir()
            for candidate in candidates:
                checkpoint(cancel)
                remaining = timeout-int(time.monotonic()-started)
                if remaining <= 0:
                    metadata_status = "timeout"
                    raise EraseProofError("Sleuth Kit metadata attack time budget exhausted.")
                worker = external.run(["icat", "-r", "-o", str(sector_offset), image, candidate.inode],
                                      folder, "inode-"+candidate.inode, remaining, cancel, fd)
                recovered = {**candidate.to_dict(), "path": worker.get("stdout_log"), "worker": worker}
                recovered["bytes"] = Path(worker["stdout_log"]).stat().st_size if worker.get("stdout_log") else 0
                extracted.append(recovered)
                if worker["status"] != "completed":
                    metadata_status = worker["status"]
                    raise EraseProofError("Sleuth Kit extraction incomplete: "+worker["status"])
                total, count = external.usage(root)
                if total > 8*1024**3 or count > 10_000:
                    metadata_status = "output-limit"
                    raise EraseProofError("Independent metadata output limit exceeded.")
            report["tools"].append({"tool": "Sleuth Kit", "status": "completed", "recovered_files": len(extracted), "files": extracted})
            report["recovered_files"] += len(extracted)
        except EraseProofError as error:
            report["tools"].append({"tool": "Sleuth Kit", "status": metadata_status, "recovered_files": len(extracted),
                                    "files": [entry for entry in extracted if entry["path"]], "detail": str(error)})
            report["metadata_coverage"] = "Not established by Sleuth Kit: see exact error"
            report["complete"] = False
    else:
        report["tools"].append({"tool": "Sleuth Kit", "status": "unavailable", "recovered_files": None})
        report["complete"] = False
    checkpoint(cancel)
    if progress:
        progress("Independent attack", .85, "Checking decoded content with bulk_extractor")
    if bulk_tool():
        destination = root/"bulk-extractor"
        result = external.run([bulk_tool(), "-j", "2", "-o", str(destination), image], root,
                              "bulk-extractor", timeout, cancel, fd, output_limit=output_budget, bundled=True)
        if result["status"] == "completed":
            result["completion"] = bulk_completion(destination, source["size"])
            if not result["completion"]["complete"]:
                result["status"] = "incomplete-report"
        features = [p for p in destination.rglob("*") if p.is_file() and p.name != "report.xml"]
        report["tools"].append({"tool": "bulk_extractor", **result, "feature_files": len(features),
                                "files": [{"path": str(p), "bytes": p.stat().st_size} for p in features],
                                "recovered_files": 0, "scope": "Feature/decompression output; feature files are not counted as recovered original files."})
        report["complete"] &= result["status"] == "completed"
    else:
        report["tools"].append({"tool": "bulk_extractor", "status": "unavailable", "recovered_files": None})
        report["complete"] = False
    (root/"attack.json").write_text(json.dumps(report, indent=2)+"\n")
    return report

"""Command-line interface for native Ubuntu execution."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import os
import platform
import shutil
import sys

from . import __version__, carve, demo, tsk
from .engine import erase, plan, verify
from .evidence import EvidenceStore, verify_record
from .models import EraseProofError
from .targets import describe, devices, descendants, find_device


def references(path):
    if not path:
        return None
    source = Path(path)
    if source.stat().st_size > 8*1024*1024:
        raise EraseProofError("Reference manifest exceeds 8 MiB.")
    value = json.loads(source.read_text())
    return value.get("references", value)


def recover(path, output, mode="both", sector_offset=0, progress=None, cancel=None):
    target = describe(path)
    if target["kind"] == "block-device":
        # An output on the source device can overwrite the evidence being recovered.
        ancestor = Path(output).expanduser().resolve()
        while not ancestor.exists():
            ancestor = ancestor.parent
        destination_device = ancestor.stat().st_dev
        root, _ = find_device(path)
        for child in descendants(root):
            if os.stat(child["name"]).st_rdev == destination_device:
                raise EraseProofError("Recovery output is on the source disk. Select a different destination disk.")
    # Metadata and carving remain separate findings; duplicates are evidence,
    # rather than silently merged or counted as independently recovered files.
    candidates, warnings = [], []
    if mode in ("deleted", "both"):
        try:
            found = tsk.deleted(path, sector_offset)
            for index, candidate in enumerate(found):
                carve.checkpoint(cancel)
                candidates.append(tsk.recover(path, candidate, Path(output)/"filesystem", sector_offset))
                if progress:
                    progress("Recover", (index+1)/max(len(found), 1), f"Recovered deleted metadata entry: {candidate.name}")
        except (EraseProofError, FileNotFoundError) as error:
            if mode == "deleted":
                raise
            warnings.append(str(error))
    if mode in ("carve", "both"):
        for candidate in carve.scan(path, progress=progress, cancel=cancel):
            carve.checkpoint(cancel)
            candidates.append(carve.extract(path, candidate, Path(output)/"carved"))
    report = {"source": describe(path), "mode": mode, "sector_offset": sector_offset,
              "candidates": [asdict(c) for c in candidates], "warnings": warnings,
              "limits": "Contiguous carving has a 256 MiB per-candidate limit. Metadata recovery depends on the filesystem and surviving allocation data. Confidence is a structural heuristic."}
    folder = Path(output)
    folder.mkdir(parents=True, exist_ok=True)
    with (folder/"recovery.json").open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    return report


def parser():
    result = argparse.ArgumentParser(prog="eraseproof", description="Native Linux recovery and verified logical erasure.")
    result.add_argument("--version", action="version", version=__version__)
    sub = result.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="Inspect Linux runtime and installed forensic tools")
    sub.add_parser("devices", help="Read-only Linux block-device inventory")
    sub.add_parser("desktop", help="Launch the native Qt application")
    ds = sub.add_parser("demo", help="Create or normally delete files in a real FAT32 demo image")
    ds.add_argument("action", choices=["create", "delete"])
    ds.add_argument("directory")
    ds.add_argument("--deleted", action="store_true", help="Delete demo files after creation")
    rs = sub.add_parser("recover", help="Recover deleted filesystem files and/or carve bytes")
    rs.add_argument("target")
    rs.add_argument("--output", required=True)
    rs.add_argument("--mode", choices=["deleted", "carve", "both"], default="both")
    rs.add_argument("--sector-offset", type=int, default=0)
    vs = sub.add_parser("verify", help="Full zero read-back and adversarial residue scan")
    vs.add_argument("target")
    vs.add_argument("--references")
    ps = sub.add_parser("plan", help="Read-only erasure plan, with target eligibility checks")
    ps.add_argument("target")
    ps.add_argument("--confirm")
    ps.add_argument("--allow-device")
    es = sub.add_parser("erase", help="Overwrite the actual selected image or secondary virtual disk")
    es.add_argument("target")
    es.add_argument("--confirm", required=True)
    es.add_argument("--allow-device")
    es.add_argument("--references")
    es.add_argument("--case", required=True)
    cs = sub.add_parser("record", help="Verify an exported signed record")
    cs.add_argument("file")
    audit = sub.add_parser("audit", help="Check and export a local case audit chain")
    audit.add_argument("case")
    return result


def progress(stage, fraction, message):
    print(f"[{stage:8s}] {fraction:6.1%} {message}", file=sys.stderr, flush=True)


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        status = 0
        if args.command == "desktop":
            from .desktop import main as desktop
            return desktop()
        if args.command == "doctor":
            output = {"version": __version__, "platform": platform.platform(), "python": sys.version.split()[0],
                      "tools": {name: shutil.which(name) for name in ("lsblk", "mkfs.fat", "mcopy", "mdel", "fls", "icat", "photorec", "nvme", "hdparm")},
                      "physical_device_sanitization": "not implemented", "native_interface": "Qt / PySide6"}
        elif args.command == "devices":
            output = devices()
        elif args.command == "demo":
            output = demo.create(args.directory, args.deleted) if args.action == "create" else demo.delete(args.directory)
        elif args.command == "recover":
            output = recover(args.target, args.output, args.mode, args.sector_offset, progress)
        elif args.command == "verify":
            output = verify(args.target, references(args.references), progress)
            status = 0 if output["passed"] else 2
        elif args.command == "plan":
            output = plan(args.target, args.allow_device, args.confirm)
        elif args.command == "erase":
            output = erase(args.target, args.confirm, args.case, references(args.references), args.allow_device, progress)
            destination = Path(args.case)/f"{output['payload']['id']}.epcert.json"
            with destination.open("x") as file:
                json.dump(output, file, indent=2)
            output = {"certificate": str(destination), "record": output}
        elif args.command == "record":
            valid = verify_record(json.loads(Path(args.file).read_text()))
            output, status = {"signature_valid": valid, "identity": "embedded self-signed operator key"}, 0 if valid else 2
        elif args.command == "audit":
            store = EvidenceStore(args.case)
            output = {"intact": store.check(), "events": store.events()}
            status = 0 if output["intact"] else 2
        print(json.dumps(output, indent=2))
        return status
    except (EraseProofError, OSError, ValueError, KeyError) as error:
        print(f"EraseProof: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("EraseProof: interrupted; incomplete operations are not certified.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

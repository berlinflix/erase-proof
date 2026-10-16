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
from .evidence import EvidenceStore, verify_record, verify_receipt
from .models import EraseProofError
from .targets import describe, devices, descendants, find_device
from .files import plan_files, erase_files


def references(path):
    if not path:
        return None
    source = Path(path)
    if source.stat().st_size > 8*1024*1024:
        raise EraseProofError("Reference manifest exceeds 8 MiB.")
    value = json.loads(source.read_text())
    return value.get("references", value)


def recover(path, output, mode="both", sector_offset=0, progress=None, cancel=None, fragmented=False):
    target = describe(path)
    if sector_offset < 0:
        raise EraseProofError("Sector offset cannot be negative.")
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
    candidates, warnings, journal_summary = [], [], None
    if mode in ("deleted", "both"):
        try:
            found = tsk.deleted(path, sector_offset)
            for index, candidate in enumerate(found):
                carve.checkpoint(cancel)
                try:
                    extracted = tsk.recover(path, candidate, Path(output)/"filesystem", sector_offset)
                    candidates.append(extracted)
                    if extracted.length == 0:
                        warnings.append(f"{candidate.name}: metadata extraction produced zero bytes; no nonempty original content was recovered from this entry.")
                except (EraseProofError, OSError) as error:
                    warnings.append(f"{candidate.name}: metadata extraction failed: {error}")
                if progress:
                    progress("Recover", (index+1)/max(len(found), 1), f"Recovered deleted metadata entry: {candidate.name}")
        except (EraseProofError, FileNotFoundError) as error:
            if mode == "deleted":
                raise
            warnings.append(str(error))
        from . import journal
        if journal.applicable(path, sector_offset):
            try:
                found, journal_summary = journal.recover(path, Path(output)/"journal", progress, cancel)
                candidates.extend(found)
            except EraseProofError as error:
                warnings.append("Ext4 journal recovery: "+str(error))
    if mode in ("carve", "both"):
        for candidate in carve.scan(path, progress=progress, cancel=cancel, fragmented=fragmented, warnings=warnings):
            carve.checkpoint(cancel)
            candidates.append(carve.extract(path, candidate, Path(output)/"carved"))
    from .confidence import enrich_metadata
    for candidate in candidates:
        if not candidate.confidence_details:
            try:
                enrich_metadata(candidate, cancel)
            except (EraseProofError, OSError) as error:
                from .models import Cancelled
                if isinstance(error, Cancelled):
                    raise
                candidate.confidence = 0
                candidate.confidence_details = {'score': 0, 'validation': 'unavailable', 'detail': str(error)}
                warnings.append(candidate.name+': output confidence could not be measured: '+str(error))
    report = {"source": describe(path), "mode": mode, "sector_offset": sector_offset,
              "candidates": [asdict(c) for c in candidates], "warnings": warnings,
              "nonempty_outputs": sum(c.length > 0 for c in candidates),
              "empty_metadata_outputs": sum(c.length == 0 and c.method == "sleuthkit-metadata" for c in candidates),
              "journal_recovery": journal_summary,
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
    fp = sub.add_parser("fingerprint", help="Read an ordinary file and emit SHA-256/4 KiB/ssdeep references")
    fp.add_argument("target")
    ds = sub.add_parser("demo", help="Create or normally delete files in a real FAT32 demo image")
    ds.add_argument("action", choices=["create", "delete"])
    ds.add_argument("directory")
    ds.add_argument("--deleted", action="store_true", help="Delete demo files after creation")
    rs = sub.add_parser("recover", help="Recover deleted filesystem files and/or carve bytes")
    rs.add_argument("target")
    rs.add_argument("--output", required=True)
    rs.add_argument("--mode", choices=["deleted", "carve", "both"], default="both")
    rs.add_argument("--sector-offset", type=int, default=0)
    rs.add_argument("--fragments", "--fragmented-png", dest="fragments", action="store_true", help="Bounded PNG/ZIP/PDF/JPEG bifragment gap reconstruction; checksum-free reconstructions remain uncertain")
    trash_list = sub.add_parser('trash-list', help='List existing Ubuntu Trash items without changing them')
    trash_list.add_argument('--trash-root', help='A Freedesktop Trash store containing files/ and info/; defaults to the current user home Trash')
    trash_recover = sub.add_parser('trash-recover', help='Copy a Trash item to a new output folder; keeps the Trash original')
    trash_recover.add_argument('item', help='Exact item ID returned by trash-list')
    trash_recover.add_argument('--trash-root')
    trash_recover.add_argument('--output', required=True)
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
    cs.add_argument("--trusted-fingerprint", help="Expected full signer SHA-256 obtained through a trusted channel")
    pdf = sub.add_parser("pdf", help="Render a scoped PDF summary, offline QR reference and attached signed JSON")
    pdf.add_argument("record")
    pdf.add_argument("--output", required=True)
    pdf_record = sub.add_parser("pdf-record", help="Verify a PDF's attached signed JSON; the PDF wrapper itself is not authenticated")
    pdf_record.add_argument("file")
    pdf_record.add_argument("--trusted-fingerprint")
    audit = sub.add_parser("audit", help="Check and export a local case audit chain")
    audit.add_argument("case")
    audit.add_argument("--anchor", help="Previously exported signed anchor or audit export")
    audit.add_argument("--trusted-fingerprint")
    audit_export = sub.add_parser("audit-export", help="Export records, events and a signed checkpoint; preserve it independently")
    audit_export.add_argument("case")
    audit_export.add_argument("--output", required=True)
    fp = sub.add_parser("file-plan", help="Inspect a logical file/folder overwrite without changing it")
    fp.add_argument("target")
    fe = sub.add_parser("erase-files", help="Overwrite current file bytes and unlink; explicitly excludes filesystem history")
    fe.add_argument("target")
    fe.add_argument("--confirm", required=True)
    fe.add_argument("--case", required=True)
    fe.add_argument("--keep-zeroed", action="store_true")
    for filesystem in ("fat32", "ext4", "ntfs", "exfat"):
        listing = sub.add_parser(filesystem+"-list", help="List allocated paths in an offline "+filesystem+" volume image")
        listing.add_argument("image")
        ep = sub.add_parser(filesystem+"-plan", help="Inspect offline "+filesystem+" targeted erasure and global history cleanup")
        ep.add_argument("image")
        ep.add_argument("internal_path")
        ee = sub.add_parser(filesystem+"-erase", help="Erase a selected "+filesystem+" image path and clear deleted history on the volume")
        ee.add_argument("image")
        ee.add_argument("internal_path")
        ee.add_argument("--confirm", required=True)
        ee.add_argument("--case", required=True)
    worker = sub.add_parser("_validate", help=argparse.SUPPRESS)
    worker.add_argument("path")
    worker.add_argument("family")
    fragments = sub.add_parser('_fragments', help=argparse.SUPPRESS)
    fragments.add_argument('fd', type=int)
    fragments.add_argument('offset', type=int)
    fragments.add_argument('kind')
    fragments.add_argument('total', type=int)
    fragments.add_argument('attempts', type=int)
    fragments.add_argument('seconds', type=float)
    attack = sub.add_parser("attack", help="Run independent PhotoRec and Sleuth Kit checks, preserving errors and extracted evidence")
    attack.add_argument("target")
    attack.add_argument("--output", required=True)
    attack.add_argument("--sector-offset", type=int, default=0)
    partitions = sub.add_parser("partitions", help="Read-only primary MBR/GPT discovery; validate GPT checksums and bounds")
    partitions.add_argument("target")
    partitions.add_argument("--sector-size", type=int, choices=[512, 4096], default=512)
    media = sub.add_parser("media-probe", help="Inspect image encryption or native NVMe/ATA capabilities without writing")
    media.add_argument("target")
    media_plan = sub.add_parser("media-plan", help="Read-only media method matrix, hidden-capacity gates and executable support")
    media_plan.add_argument("target")
    for name in ("nvme-plan", "nvme-submit"):
        operation = sub.add_parser(name, help="Prepare or explicitly submit controller-wide NVMe sanitize; never issues an erasure certificate")
        operation.add_argument("controller")
        operation.add_argument("--method", choices=["block-erase", "crypto-erase"], required=True)
        operation.add_argument("--allow-controller", required=True)
        operation.add_argument("--confirm", required=True)
        if name == "nvme-submit":
            operation.add_argument("--case", required=True)
    status = sub.add_parser("nvme-status", help="Read controller sanitize status; firmware jobs continue independently of this process")
    status.add_argument("controller")
    for name in ("nvme-format-plan", "nvme-format-submit"):
        operation = sub.add_parser(name, help="Plan or execute Format NVM secure erase of every namespace, preserving sector formats")
        operation.add_argument("controller")
        operation.add_argument("--method", choices=["crypto", "user-data"], required=True)
        operation.add_argument("--allow-controller", required=True)
        operation.add_argument("--confirm", required=True)
        if name.endswith("submit"):
            operation.add_argument("--case", required=True)
    for name in ('nvme-workflow-plan', 'nvme-run'):
        operation = sub.add_parser(name, help='Plan or run a bounded controller-wide erase/attack/escalate/certify workflow')
        operation.add_argument('controller')
        operation.add_argument('--methods', nargs='+', choices=['crypto-erase', 'block-erase', 'format-crypto', 'format-user-data'], required=True)
        operation.add_argument('--allow-controller', required=True)
        operation.add_argument('--confirm', required=True)
        if name == 'nvme-run':
            operation.add_argument('--case', required=True)
            operation.add_argument('--references', required=True)
            operation.add_argument('--timeout', type=int, default=3600)
    for name in ("ata-plan", "ata-submit"):
        operation = sub.add_parser(name, help="Plan/execute allowlisted ATA sanitize, enhanced erase or explicit HPA/DCO opening")
        operation.add_argument("target")
        operation.add_argument("--method", choices=["sanitize-crypto", "sanitize-block", "enhanced-secure-erase", "open-hidden"], required=True)
        operation.add_argument("--allow-device", required=True)
        operation.add_argument("--confirm", required=True)
        operation.add_argument("--open-hidden", action="store_true")
        operation.add_argument("--capacity-sectors", type=int)
        if name.endswith("submit"):
            operation.add_argument("--case", required=True)
    ata_status = sub.add_parser("ata-status", help="Read ATA identity, hidden capacity and sanitize/security state")
    ata_status.add_argument("target")
    security_recover = sub.add_parser("ata-recover-security", help="Explicitly unlock/disable the saved temporary ATA password after an interrupted erase")
    security_recover.add_argument("target")
    security_recover.add_argument("--allow-device", required=True)
    security_recover.add_argument("--confirm", required=True)
    security_recover.add_argument("--recovery-key", required=True)
    security_recover.add_argument("--case", required=True)
    for name in ("device-plan", "device-erase", "device-discard"):
        operation = sub.add_parser(name, help="Explicit privileged whole host-visible disk operation; boot/mounted/holder gates apply")
        operation.add_argument("target")
        operation.add_argument("--allow-device", required=True)
        operation.add_argument("--confirm", required=True)
        if name != "device-plan":
            operation.add_argument("--case", required=True)
        if name == "device-erase":
            operation.add_argument("--references")
        if name == "device-discard":
            operation.add_argument("--secure", action="store_true")
    luks = sub.add_parser("luks-erase", help="Remove active software LUKS2 image keyslots; ciphertext/backups remain outside this operation")
    luks.add_argument("image")
    luks.add_argument("--confirm", required=True)
    luks.add_argument("--case", required=True)
    return result


def progress(stage, fraction, message):
    print(f"[{stage:8s}] {fraction:6.1%} {message}", file=sys.stderr, flush=True)


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        status = 0
        if args.command == '_fragments':
            from .fragments import worker
            worker(args.fd, args.offset, args.kind, args.total, args.attempts, args.seconds)
            return 0
        if args.command == "desktop":
            from .desktop import main as desktop
            return desktop()
        if args.command == "doctor":
            from .nativeio import library
            from .independent import bulk_tool
            from .fingerprints import library as fuzzy_library
            output = {"version": __version__, "platform": platform.platform(), "python": sys.version.split()[0],
                      "tools": {name: shutil.which(name) for name in ("lsblk", "losetup", "mkfs.fat", "mcopy", "mdel", "fls", "icat", "photorec", "nvme", "hdparm", "e2fsck", "ntfsfix", "ntfsresize", "ntfswipe", "fsck.exfat", "cryptsetup", "prlimit")},
                      "native_direct_io": library() is not None,
                      "offline_ext4_adapter": (Path(__file__).parent/"resources"/"native"/"eraseproof-ext4").is_file(),
                      "offline_ntfs_adapter": (Path(__file__).parent/"resources"/"native"/"eraseproof-ntfs").is_file(),
                      "offline_exfat_adapter": True,
                      "bulk_extractor": bulk_tool(),
                      'ssdeep_streaming': fuzzy_library() is not None,
                      'native_firmware_adapter': (Path(__file__).parent/'resources/native/liberaseproof_firmware.so').is_file(),
                      'strict_jpeg_fragment_validator': (Path(__file__).parent/'resources/native/liberaseproof_jpeg.so').is_file(),
                      "ext4_journal_reader": (Path(__file__).parent/"resources"/"native"/"eraseproof-ext4-journal").is_file(),
                      "physical_device_sanitization": "guarded NVMe/ATA/Format/HPA/DCO and host-range adapters; physical firmware behavior remains unverified", "native_interface": "Qt / PySide6"}
        elif args.command == "devices":
            output = devices()
        elif args.command in ("nvme-format-plan", "nvme-format-submit"):
            from . import nvmeformat, media
            output = (nvmeformat.submit(args.controller, args.method, args.allow_controller, args.confirm, args.case)
                      if args.command.endswith("submit") else nvmeformat.plan(media.nvme_probe(args.controller), args.method, args.allow_controller, args.confirm))
        elif args.command in ('nvme-workflow-plan', 'nvme-run'):
            from . import workflow, media
            output = (workflow.plan(media.nvme_probe(args.controller), args.methods, args.allow_controller, args.confirm)
                      if args.command.endswith('plan') else workflow.run(args.controller, args.methods, args.allow_controller,
                        args.confirm, args.case, references(args.references), timeout=args.timeout, progress=progress))
        elif args.command == "ata-status":
            from .ata import probe
            output = probe(args.target)
        elif args.command == "device-plan":
            output = plan(args.target, args.allow_device, args.confirm, host_device=True)
        elif args.command == "device-erase":
            output = erase(args.target, args.confirm, args.case, references(args.references), args.allow_device, progress, host_device=True)
        elif args.command == "device-discard":
            from .device import discard
            output = discard(args.target, args.allow_device, args.confirm, args.case, args.secure)
        elif args.command == "ata-recover-security":
            from .ata import recover_security
            output = recover_security(args.target, args.allow_device, args.confirm, args.recovery_key, args.case)
        elif args.command in ("ata-plan", "ata-submit"):
            from . import ata
            output = (ata.submit(args.target, args.method, args.allow_device, args.confirm, args.case, args.open_hidden, args.capacity_sectors)
                      if args.command.endswith("submit") else ata.plan(ata.probe(args.target), args.method, args.allow_device, args.confirm, args.open_hidden, args.capacity_sectors))
        elif args.command == "fingerprint":
            from .fingerprints import measure
            from .targets import open_target
            info = describe(args.target)
            if info["kind"] != "image":
                raise EraseProofError("Fingerprint a single ordinary file, not an entire device.")
            with open_target(args.target) as source:
                measured = measure(iter(lambda: source.read(carve.CHUNK), b""))
            output = {"file": info["path"], "fingerprint": measured,
                      "references": {"block_size": 4096, "block_hashes": measured["block_hashes_4096"],
                                     "file_hashes": [measured["sha256"]], "fuzzy_hashes": [measured["ssdeep"]],
                                     "fuzzy_threshold": 70}}
        elif args.command == "demo":
            output = demo.create(args.directory, args.deleted) if args.action == "create" else demo.delete(args.directory)
        elif args.command == "recover":
            output = recover(args.target, args.output, args.mode, args.sector_offset, progress, fragmented=args.fragments)
        elif args.command == 'trash-list':
            from .trash import listing
            output = listing(args.trash_root)
        elif args.command == 'trash-recover':
            from .trash import recover as recover_trash
            output = recover_trash(args.item, args.output, args.trash_root, progress)
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
        elif args.command in ("record", "pdf-record"):
            if args.command == "pdf-record":
                from .certificate import attached_record
                record = attached_record(args.file)
            else:
                record = json.loads(Path(args.file).read_text())
            validator = verify_receipt if record.get('payload', {}).get('schema') == 'eraseproof.firmware-receipt.v1' else verify_record
            valid = validator(record)
            trusted = validator(record, args.trusted_fingerprint) if args.trusted_fingerprint is not None else None
            output = {"signature_valid": valid, "trusted_signer": trusted, "signer_fingerprint": record.get("signer_fingerprint"),
                      "identity": "matched expected signer" if trusted else "operator identity not established", "pdf_wrapper_authenticated": False}
            status = 0 if valid and trusted is not False else 2
        elif args.command == "pdf":
            from .certificate import render
            output = render(json.loads(Path(args.record).read_text()), args.output)
        elif args.command == "audit":
            if not (Path(args.case)/"evidence.sqlite3").is_file():
                raise EraseProofError("This case has no evidence database.")
            store = EvidenceStore(args.case)
            intact = store.check()
            matches = None
            if args.anchor:
                anchor = json.loads(Path(args.anchor).read_text())
                matches = store.check_anchor(anchor.get("anchor", anchor), args.trusted_fingerprint)
            elif args.trusted_fingerprint:
                raise EraseProofError("A trusted fingerprint requires an --anchor to check.")
            output = {"intact": intact, "anchor_matches": matches, "unresolved_jobs": store.unresolved_jobs() if intact else None,
                      "events": store.events() if intact else [], "scope": "A local chain alone cannot detect tail deletion; compare with a separately protected checkpoint."}
            status = 0 if intact and matches is not False else 2
        elif args.command == "audit-export":
            if not (Path(args.case)/"evidence.sqlite3").is_file():
                raise EraseProofError("This case has no evidence database.")
            store = EvidenceStore(args.case)
            export = store.export()
            with Path(args.output).open("x") as file:
                json.dump(export, file, indent=2)
            output = {"path": str(Path(args.output).resolve()), "anchor": export["anchor"], "instruction": "Preserve the checkpoint outside this case; establish the signer fingerprint independently."}
        elif args.command == "file-plan":
            output = plan_files(args.target)
        elif args.command == "erase-files":
            output = erase_files(args.target, args.confirm, args.case, progress, unlink=not args.keep_zeroed)
        elif args.command == "_validate":
            from .validators import worker
            worker(args.path, args.family)
            return 0
        elif args.command == "attack":
            from .independent import attack
            output = attack(args.target, args.output, args.sector_offset, progress)
        elif args.command == "partitions":
            from .partitions import inspect
            output = inspect(args.target, args.sector_size)
        elif args.command == "media-probe":
            from .media import probe
            output = probe(args.target)
        elif args.command == "media-plan":
            from .media import decision, probe
            output = decision(probe(args.target))
        elif args.command in {fs+"-"+action for fs in ("fat32", "ext4", "ntfs", "exfat") for action in ("list", "plan", "erase")}:
            from .offline import backend
            filesystem, action = args.command.split("-", 1)
            adapter = backend(filesystem)
            if action == "list":
                output = adapter.list_paths(args.image)
            elif action == "plan":
                output = adapter.plan_path(args.image, args.internal_path)
            else:
                output = adapter.erase_path(args.image, args.internal_path, args.confirm, args.case, progress)
        elif args.command == "nvme-plan":
            from .media import nvme_probe, nvme_plan
            output = nvme_plan(nvme_probe(args.controller), args.method, args.allow_controller, args.confirm)
        elif args.command == "nvme-submit":
            from .media import submit_nvme
            output = submit_nvme(args.controller, args.method, args.allow_controller, args.confirm, args.case)
        elif args.command == "nvme-status":
            from .media import nvme_status
            output = nvme_status(args.controller)
        elif args.command == "luks-erase":
            from .media import erase_luks_image
            output = erase_luks_image(args.image, args.confirm, args.case)
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

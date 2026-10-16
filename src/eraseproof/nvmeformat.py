"""Controller-wide, format-preserving Format NVM secure erase workflow."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import stat
import uuid

from . import firmware, media
from .evidence import EvidenceStore, digest, now
from .models import EraseProofError
from .targets import open_target


def plan(probe, method, allow_controller, confirmation):
    media.nvme_gate(probe, allow_controller, confirmation)
    if method not in ("crypto", "user-data"):
        raise EraseProofError("Format NVM method must be crypto or user-data.")
    identify = probe["identify"]
    if not media.number(identify.get("oacs", 0)) & 2:
        raise EraseProofError("Format NVM support was not advertised.")
    fna = media.number(identify.get("fna", 0))
    if method == "crypto" and not fna & 4:
        raise EraseProofError("Cryptographic Format NVM support was not advertised.")
    status = media.number(probe.get("sanitize_log", {}).get("sstat", -1))
    if status == -1 and ('sanicap' not in identify or media.number(identify['sanicap']) & 7):
        raise EraseProofError('Sanitize status is unknown on a sanitize-capable or unidentified controller; Format NVM is blocked.')
    if status != -1 and status & 7 not in (0, 1, 4):
        raise EraseProofError("Sanitize is busy/failed; Format NVM is blocked.")
    layouts = []
    for identifier in probe["namespace_ids"]:
        info = probe.get("format_namespaces", {}).get(str(identifier), {})
        try:
            flbas, dps = media.number(info["flbas"]), media.number(info["dps"])
            if not 0 <= flbas <= 15 or dps != 0:
                raise ValueError
            lbaf = info["lbafs"][flbas]
            ds, ms = media.number(lbaf["ds"]), media.number(lbaf["ms"])
            if ms != 0 or not 9 <= ds <= 16 or media.number(info["nsze"]) <= 0:
                raise ValueError
        except (KeyError, IndexError, TypeError, ValueError):
            raise EraseProofError("Namespace layout is unknown, extended, or uses metadata/protection. This adapter refuses to change its format.") from None
        layouts.append({"nsid": identifier, "lbaf": flbas, "sector_bytes": 1 << ds,
                        "nsze": media.number(info["nsze"]), "metadata_bytes": 0, "protection": 0})
    common = len({(n["lbaf"], n["sector_bytes"]) for n in layouts}) == 1
    if fna & 3 and not common:
        raise EraseProofError("Format/secure erase affects every namespace but layouts differ; refusing an unintended format conversion.")
    ses = 2 if method == "crypto" else 1
    if common and not fna & 8:
        commands = [{"nsid": 0xffffffff, "lbaf": layouts[0]["lbaf"], "ses": ses}]
    elif fna & 3:
        commands = [{"nsid": layouts[0]["nsid"], "lbaf": layouts[0]["lbaf"], "ses": ses}]
    else:
        commands = [{"nsid": n["nsid"], "lbaf": n["lbaf"], "ses": ses} for n in layouts]
    return {"controller": probe["path"], "serial": probe["serial"], "model": probe["model"],
            "method": "nvme-format-"+method, "namespaces": layouts, "commands": commands,
            "scope": "Every allocated namespace on this single controller; existing sector format retained. Firmware success alone does not prove physical erasure.",
            "certificate_eligible": False, "read_only": True}


def pinned_controller(controller, stack, serial, model):
    fd = os.open(controller, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    stack.callback(os.close, fd)
    opened = os.fstat(fd)
    if not stat.S_ISCHR(opened.st_mode) or opened.st_rdev != os.stat(controller, follow_symlinks=False).st_rdev:
        raise EraseProofError("NVMe controller changed while opening.")
    import fcntl
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    raw = firmware.identify(fd)
    actual_serial = raw[4:24].decode("ascii", errors="strict").strip()
    actual_model = raw[24:64].decode("ascii", errors="strict").strip()
    if (actual_serial, actual_model) != (serial, model):
        raise EraseProofError("Pinned controller IDENTIFY identity differs from the confirmed plan.")
    return fd


def submit(controller, method, allow_controller, confirmation, evidence_dir, *, expected_namespaces=None):
    if os.geteuid() != 0:
        raise EraseProofError("Format NVM requires an explicit root CLI invocation.")
    initial = media.nvme_probe(controller)
    if expected_namespaces is not None and digest(initial['namespaces']) != digest(expected_namespaces):
        raise EraseProofError('Namespace inventory changed from the confirmed workflow; no format command sent.')
    prepared = plan(initial, method, allow_controller, confirmation)
    media.outside_devices(evidence_dir, [n["device"] for n in initial["namespaces"]])
    firmware.library()
    store = EvidenceStore(evidence_dir)
    if not store.check():
        raise EraseProofError("Audit history is damaged; no firmware command was sent.")
    store.key()
    job = "nvme-format-"+uuid.uuid4().hex
    completed = []
    with ExitStack() as stack:
        for namespace in initial["namespaces"]:
            source = stack.enter_context(open_target(namespace["device"]["name"], writable=True))
            if os.fstat(source.fileno()).st_rdev != os.stat(namespace["device"]["name"], follow_symlinks=False).st_rdev:
                raise EraseProofError("A namespace device changed while opening.")
        fresh = media.nvme_probe(controller)
        if digest(prepared) != digest(plan(fresh, method, allow_controller, confirmation)):
            raise EraseProofError("Controller identity, namespace capacity or layout changed; no command sent.")
        fd = pinned_controller(controller, stack, prepared["serial"], prepared["model"])
        for namespace in prepared["namespaces"]:
            raw = firmware.identify(fd, namespace["nsid"])
            if raw[26] != namespace["lbaf"] or raw[29] != 0 or int.from_bytes(raw[:8], "little") != namespace["nsze"]:
                raise EraseProofError("Pinned namespace format/capacity changed.")
        store.append("firmware.format-submitting", {"job": job, "plan": prepared})
        try:
            for operation in prepared["commands"]:
                response = firmware.format_nvm(fd, **operation)
                completed.append({**operation, "response": response})
                store.append("firmware.format-command-completed", {"job": job, **completed[-1]})
            after = media.nvme_probe(controller)
            if digest(prepared) != digest(plan(after, method, allow_controller, confirmation)):
                raise EraseProofError("Post-format identity/capacity/layout differs from the plan; inspect the controller.")
        except BaseException as error:
            store.append("firmware.format-incomplete", {"job": job, "completed": completed, "reason": str(error),
                         "instruction": "No automatic retry. Firmware may continue after process interruption."})
            raise
        receipt = {"schema": "eraseproof.firmware-receipt.v1", "job": job, "at": now(), "plan": prepared,
                   "completed_commands": completed, "state": "firmware-reports-completion", "certificate_issued": False,
                   "next": "Independently acquire and attack all namespaces against retained target fingerprints. This receipt does not establish physical erasure."}
        signed = store.sign(receipt)
        store.append("firmware.format-completed", {"job": job, "receipt_sha256": signed["payload_sha256"]})
    with (store.root/(job+".json")).open("x") as file:
        json.dump(signed, file, indent=2)
    return signed

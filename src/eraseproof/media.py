"""Media discovery and narrowly scoped firmware/keyslot operations.

Firmware acceptance is deliberately a job receipt, never an erasure certificate.
No shell commands, password arguments, HPA/DCO changes or force flags are used.
"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import uuid

from .evidence import EvidenceStore, digest, now
from .models import EraseProofError
from .runtime import system_environment
from .targets import describe, devices, descendants, find_device, open_target


def command(arguments, json_output=False, pass_fds=()):
    if not shutil.which(arguments[0]):
        raise EraseProofError(f"Install the Linux tool '{arguments[0]}' for this operation.")
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                timeout=30, pass_fds=pass_fds, env=system_environment())
    except subprocess.TimeoutExpired:
        raise EraseProofError(f"{arguments[0]} timed out. A submitted firmware operation may continue; inspect its status before retrying.") from None
    if result.returncode:
        raise EraseProofError(result.stderr.strip()[:2000] or f"{arguments[0]} failed ({result.returncode}).")
    return json.loads(result.stdout) if json_output else result.stdout


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def controller_namespaces(controller, inventory=None, sysfs=Path('/sys')):
    """Match sysfs ancestry, never the numeric spelling of an NVMe device.

    Namespace names use a subsystem instance number on some kernels. Native
    multipath heads cannot be safely claimed by this single-controller adapter.
    """
    parent = (sysfs/'class/nvme'/Path(controller).name).resolve(strict=True)
    result = []
    for root in devices() if inventory is None else inventory:
        node = sysfs/'class/block'/Path(root['name']).name
        if parent not in node.resolve().parents:
            continue
        nsid = node/'nsid'
        if not nsid.is_file():
            continue
        identifier = int(nsid.read_text())
        if identifier <= 0 or any(n['id'] == identifier for n in result):
            raise EraseProofError('Ambiguous NVMe namespace inventory; execution is blocked.')
        result.append({'id': identifier, 'device': root})
    return sorted(result, key=lambda n: n['id'])


def nvme_probe(controller):
    path = Path(controller)
    if not re.fullmatch(r"/dev/nvme\d+", str(path)) or path.is_symlink() or not stat.S_ISCHR(path.stat().st_mode):
        raise EraseProofError("Select a real NVMe controller character device, such as /dev/nvme0.")
    identify = command(["nvme", "id-ctrl", str(path), "-o", "json"], True)
    namespace_data = command(["nvme", "list-ns", str(path), "--all", "-o", "json"], True)
    namespace_ids = namespace_data.get("nsid_list")
    if not isinstance(namespace_ids, list) or any(not isinstance(n, int) or n <= 0 for n in namespace_ids):
        raise EraseProofError("Unsupported namespace inventory response; controller execution is blocked.")
    namespaces = controller_namespaces(path)
    return {"kind": "nvme-controller", "path": str(path), "serial": str(identify.get("sn") or "").strip(),
            "model": str(identify.get("mn") or "").strip(), "identify": identify, "namespace_ids": sorted(namespace_ids),
            "namespaces": namespaces, "sanitize_log": command(["nvme", "sanitize-log", str(path), "-o", "json"], True),
            "scope": "Controller-wide; affects every namespace. Firmware behavior has not been validated on physical hardware."}


def nvme_plan(probe, method, allow_controller, confirmation):
    if method not in ("block-erase", "crypto-erase"):
        raise EraseProofError("Supported NVMe sanitize methods: block-erase or crypto-erase.")
    if allow_controller != probe["path"] or not probe["serial"] or confirmation != probe["serial"]:
        raise EraseProofError("Controller allowlist and exact nonempty device serial are required.")
    identify = probe["identify"]
    # Multi-controller/subsystem and fabrics require a wider exclusivity model.
    if "cmic" not in identify or number(identify["cmic"]):
        raise EraseProofError("Multi-port/controller, SR-IOV and shared-subsystem configurations are refused.")
    bit, action = (1, 2) if method == "block-erase" else (0, 4)
    if not number(identify.get("sanicap", 0)) & (1 << bit):
        raise EraseProofError("The controller does not advertise the selected sanitize action.")
    allocated = probe["namespace_ids"]
    if not allocated or allocated != sorted(n["id"] for n in probe["namespaces"]):
        raise EraseProofError("Every allocated namespace must be attached and present in the Linux inventory.")
    for namespace in probe["namespaces"]:
        root = namespace["device"]
        if root.get("type") != "disk":
            raise EraseProofError("Namespace inventory is not a complete disk.")
        for item in descendants(root):
            if item.get("ro") or any(item.get("mountpoints") or []):
                raise EraseProofError("A namespace or child is mounted, swap, or read-only. Controller sanitization is blocked.")
            holders = Path("/sys/class/block")/Path(item["name"]).name/"holders"
            if holders.exists() and any(holders.iterdir()):
                raise EraseProofError("A namespace is held by another kernel block device.")
    status = number(probe["sanitize_log"].get("sstat", -1)) & 7
    if status not in (0, 1, 4):
        raise EraseProofError("Sanitize log is busy, failed or unrecognized; no new command will be submitted.")
    return {"controller": probe["path"], "serial": probe["serial"], "model": probe["model"],
            "namespaces": [n["device"]["name"] for n in probe["namespaces"]], "method": method,
            "command": ["nvme", "sanitize", probe["path"], f"--sanact={action}"],
            "scope": probe["scope"], "certificate_eligible": False,
            "warning": "Firmware commands cannot be cancelled by closing EraseProof. Acceptance alone proves no erasure."}


def outside_devices(directory, roots):
    ancestor = Path(directory).expanduser().resolve()
    while not ancestor.exists():
        ancestor = ancestor.parent
    if any(os.stat(item["name"]).st_rdev == ancestor.stat().st_dev for root in roots for item in descendants(root)):
        raise EraseProofError("Evidence destination is on a device affected by this operation.")


def submit_nvme(controller, method, allow_controller, confirmation, evidence_dir):
    if os.geteuid() != 0:
        raise EraseProofError("NVMe submission requires an explicit root CLI invocation.")
    initial = nvme_probe(controller)
    prepared = nvme_plan(initial, method, allow_controller, confirmation)
    outside_devices(evidence_dir, [n["device"] for n in initial["namespaces"]])
    store = EvidenceStore(evidence_dir)
    store.key()
    job = "nvme-"+uuid.uuid4().hex
    with ExitStack() as stack:
        # Hold all namespace devices exclusively for the command submission.
        for namespace in initial["namespaces"]:
            stack.enter_context(open_target(namespace["device"]["name"], writable=True))
        fresh = nvme_probe(controller)
        if digest(prepared) != digest(nvme_plan(fresh, method, allow_controller, confirmation)):
            raise EraseProofError("Controller identity or namespaces changed during preparation.")
        store.append("firmware.submitting", {"job": job, "plan": prepared, "before_log": initial["sanitize_log"]})
        try:
            response = command(prepared["command"])
        except BaseException as error:
            store.append("firmware.submission-uncertain", {"job": job, "error": str(error), "instruction": "Read controller sanitize-log; do not assume a timeout cancelled the command."})
            raise
        receipt = {"job": job, "at": now(), "plan": prepared, "command_response": response,
                   "state": "accepted-awaiting-verification", "certificate_issued": False,
                   "next": "Read nvme-status. Independently acquire/attack visible namespaces after firmware completion. Physical assurance requires hardware evaluation."}
        store.append("firmware.accepted", receipt)
    with (store.root/(job+".json")).open("x") as file:
        json.dump(receipt, file, indent=2)
    return receipt


def nvme_status(controller):
    probe = nvme_probe(controller)
    log = probe["sanitize_log"]
    state = number(log.get("sstat", -1)) & 7
    return {"controller": controller, "serial": probe["serial"], "log": log,
            "state": {0: "never-sanitized", 1: "firmware-reports-success", 2: "in-progress", 3: "failed", 4: "success-with-deallocation"}.get(state, "unknown"),
            "progress": min(1, max(0, number(log.get("sprog", 0))/65536)),
            "certificate_issued": False, "scope": "Observation of the controller log; not proof of physical erasure or correlation with a particular job."}


def probe(path):
    if re.fullmatch(r"/dev/nvme\d+", str(path)):
        return nvme_probe(str(path))
    info = describe(path)
    result = {"target": info, "recommendation": "logical-overwrite", "physical_assurance": "unverified", "checks": {}}
    if info["kind"] == "image":
        with open_target(path) as stream:
            header = stream.read(8)
        if header[:6] == b"LUKS\xba\xbe":
            result["encryption"] = "LUKS"+str(int.from_bytes(header[6:8], "big"))
            result["recommendation"] = "inspect-keyslots-before-logical-overwrite"
        return result
    _, device = find_device(path)
    result["transport"] = device.get("tran")
    result["rotational"] = device.get("rota")
    if device.get("tran") == "nvme":
        result["recommendation"] = "inspect-controller-sanitize-capabilities"
    elif device.get("tran") in ("sata", "ata"):
        for name, args in (("identify", ["-I"]), ("native_capacity", ["-N"]), ("dco", ["--dco-identify"])):
            try:
                result["checks"][name] = {"status": "read", "raw": command(["hdparm", *args, info["path"]])}
            except EraseProofError as error:
                result["checks"][name] = {"status": "unknown", "detail": str(error)}
        raw = result["checks"].get("native_capacity", {}).get("raw", "")
        match = re.search(r"max sectors\s*=\s*(\d+)/(\d+)", raw)
        result["hpa"] = {"visible_sectors": int(match[1]), "native_sectors": int(match[2]), "hidden": int(match[1]) < int(match[2])} if match else {"state": "unknown"}
        result["recommendation"] = "review-ATA-capabilities-and-hidden-areas"
        result["execution"] = "ATA firmware erasure and HPA/DCO changes are not enabled; unknown checks are not treated as absent."
    else:
        result["recommendation"] = "visible-range-overwrite-only; flash-hidden-pages-not-proven"
    return result


def decision(discovery):
    """A read-only method matrix with explicit scope and executable support.

    Capability preference is not a physical sanitization assurance rating.
    Scope is never broadened automatically when a recovery attack finds data.
    """
    methods, blockers = [], []
    def add(name, supported, reason, command=None, scope=''):
        methods.append({'method': name, 'available': bool(supported), 'reason': reason,
                        'command': command, 'scope': scope, 'physical_certificate': False})
    if discovery.get('kind') == 'nvme-controller':
        identify = discovery['identify']
        for method in ('crypto-erase', 'block-erase'):
            try:
                prepared = nvme_plan(discovery, method, discovery['path'], discovery['serial'])
                add('nvme-sanitize-'+method, True, 'Advertised and controller inventory gates passed.',
                    ['eraseproof', 'nvme-submit', discovery['path'], '--method', method,
                     '--allow-controller', discovery['path'], '--confirm', discovery['serial'], '--case', 'EVIDENCE_ON_ANOTHER_DEVICE'],
                    prepared['scope'])
            except (EraseProofError, ValueError) as error:
                add('nvme-sanitize-'+method, False, str(error))
        oacs, fna = number(identify.get('oacs', 0)), number(identify.get('fna', 0))
        add('nvme-format-crypto', False,
            'Advertised, but Format NVM execution is not enabled in this release.' if oacs & 2 and fna & 4 else 'Cryptographic Format NVM support was not established.')
        add('nvme-format-user-data', False,
            'Advertised, but Format NVM execution is not enabled in this release.' if oacs & 2 else 'Format NVM support was not established.')
        target = {'path': discovery['path'], 'serial': discovery['serial'], 'model': discovery['model']}
        hidden = {'state': 'controller-scoped', 'detail': 'All allocated namespaces must be visible. HPA/DCO are ATA mechanisms.'}
    else:
        target = discovery['target']
        hidden = {'state': 'not-applicable-to-image'} if target['kind'] == 'image' else {'state': 'unknown'}
        if target['kind'] == 'image':
            from .engine import plan
            try:
                plan(target['path'], confirmation=target['serial'])
                add('logical-overwrite', True, 'Complete current image overwrite and full readback are implemented.',
                    ['eraseproof', 'erase', target['path'], '--confirm', target['serial'], '--case', 'EVIDENCE_DIRECTORY'], target['scope'])
            except EraseProofError as error:
                add('logical-overwrite', False, str(error), scope=target['scope'])
            if discovery.get('encryption') == 'LUKS2':
                add('luks2-keyslot-removal', True, 'Removes active image keyslots; cached keys and header backups remain outside scope.',
                    ['eraseproof', 'luks-erase', target['path'], '--confirm', target['serial'], '--case', 'EVIDENCE_DIRECTORY'],
                    'Software keyslot-removal receipt; ciphertext is retained. Logical overwrite can follow as a separately confirmed operation.')
        else:
            from .targets import virtual_disk_policy
            try:
                virtual_disk_policy(target['path'], target['serial'], target['path'])
                add('logical-overwrite', True, 'Recognized unmounted secondary virtual disk; actual submission rechecks identity.',
                    ['eraseproof', 'erase', target['path'], '--allow-device', target['path'], '--confirm', target['serial'], '--case', 'EVIDENCE_ON_ANOTHER_DEVICE'], target['scope'])
            except EraseProofError as error:
                add('logical-overwrite', False, str(error), scope=target['scope'])
            if discovery.get('transport') in ('sata', 'ata'):
                hpa = discovery.get('hpa', {})
                native = hpa.get('native_sectors')
                dco_raw = discovery.get('checks', {}).get('dco', {}).get('raw', '')
                maximum = re.search(r'Real max sectors:\s*(\d+)', dco_raw)
                dco = int(maximum[1]) if maximum else None
                if hpa.get('hidden'):
                    hidden = {'state': 'hidden', 'hpa': hpa, 'dco_max_sectors': dco}
                elif native and dco and dco == native and hpa.get('visible_sectors') == native:
                    hidden = {'state': 'no-capacity-reduction-reported', 'hpa': hpa, 'dco_max_sectors': dco}
                elif native and dco and dco > native:
                    hidden = {'state': 'hidden', 'hpa': hpa, 'dco_max_sectors': dco}
                else:
                    hidden = {'state': 'unknown', 'hpa': hpa, 'dco_max_sectors': dco}
                for method in ('ata-sanitize-crypto', 'ata-sanitize-block', 'ata-enhanced-secure-erase'):
                    add(method, False, 'ATA destructive adapters require spare-hardware validation and are disabled. Raw IDENTIFY responses are retained in discovery.')
                if hidden['state'] in ('hidden', 'unknown'):
                    blockers.append('ATA hidden capacity is present or unknown. No whole-physical-media erasure claim is permitted; HPA/DCO changes are not automated.')
            if discovery.get('transport') == 'nvme':
                blockers.append('Inspect the real controller character device to plan controller-wide sanitization; namespace names do not establish controller ownership.')
            if not discovery.get('rotational'):
                blockers.append('Visible-sector overwrite cannot establish erasure of flash translation-layer pages, remapped blocks or overprovisioned space.')
    available = [m['method'] for m in methods if m['available']]
    return {'target': target, 'read_only': True, 'recommended': available[0] if available else None,
            'methods': methods, 'hidden_areas': hidden, 'blockers': blockers,
            'escalation': 'If attack finds residue, preserve the failed result. A stronger method or wider scope requires a new explicit plan and confirmation.',
            'assurance': 'Software capability/eligibility plan. No physical sanitization or NIST/IEEE compliance certification.',
            'discovery': discovery}


def luks_metadata(stream):
    stream.seek(0)
    if stream.read(8) != b"LUKS\xba\xbe\x00\x02":
        raise EraseProofError("This operation supports a self-contained software LUKS2 image only.")
    data = command(["cryptsetup", "luksDump", "--dump-json-metadata", f"/proc/self/fd/{stream.fileno()}"], True, (stream.fileno(),))
    if not data.get("segments") or any(segment.get("type") != "crypt" for segment in data["segments"].values()) or any(slot.get("type") != "luks2" for slot in data.get("keyslots", {}).values()):
        raise EraseProofError("Unsupported hardware encryption or LUKS2 segment/keyslot type.")
    return data


def erase_luks_image(path, confirmation, evidence_dir):
    info = describe(path)
    if info["kind"] != "image" or confirmation != info["serial"]:
        raise EraseProofError("Select a LUKS2 image and confirm its exact filename.")
    root = Path(evidence_dir).expanduser().resolve()
    if root == Path(info["path"]) or Path(info["path"]) in root.parents:
        raise EraseProofError("Evidence path conflicts with the source image.")
    associated = command(["losetup", "--associated", info["path"]])
    if associated.strip():
        raise EraseProofError("The image is attached to a loop device; detach it before keyslot removal.")
    store = EvidenceStore(root)
    store.key()
    # cryptsetup takes its own flock on the same inode. A parent flock would
    # deadlock the child despite the inherited descriptor. Keep the descriptor
    # pinned and let cryptsetup own the metadata transaction lock.
    with open_target(path, writable=True, lock=False) as stream:
        identity = os.stat(path)
        opened = os.fstat(stream.fileno())
        if (identity.st_dev, identity.st_ino, info["size"]) != (opened.st_dev, opened.st_ino, opened.st_size):
            raise EraseProofError("LUKS image identity changed.")
        before = luks_metadata(stream)
        if not before.get("keyslots"):
            raise EraseProofError("No active keyslots remain; nothing will be erased.")
        store.append("luks.keyslots-removing", {"target": info, "slot_ids": sorted(before["keyslots"])})
        try:
            command(["cryptsetup", "luksErase", "--batch-mode", f"/proc/self/fd/{stream.fileno()}"], pass_fds=(stream.fileno(),))
            os.fsync(stream.fileno())
            after = luks_metadata(stream)
            if after.get("keyslots"):
                raise EraseProofError("Active keyslots remain after cryptsetup returned.")
        except BaseException as error:
            store.append("luks.keyslots-incomplete", {"target": info, "reason": str(error)})
            raise
    result = {"target": info, "at": now(), "keyslots_before": len(before["keyslots"]), "keyslots_after": 0,
              "certificate_issued": False, "scope": "Active software LUKS2 keyslots removed from this image. Payload ciphertext, detached header backups, cached keys and external key copies are not erased. Run the full image overwrite for logical zero verification."}
    store.append("luks.keyslots-removed", result)
    return result

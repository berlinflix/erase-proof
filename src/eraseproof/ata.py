"""Allowlisted ATA sanitization and explicit hidden-capacity expansion.

The native SG_IO boundary uses the same exclusively opened device throughout.
Firmware receipts remain distinct from independent erasure verification.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import uuid

from . import firmware
from .evidence import EvidenceStore, digest, now
from .models import EraseProofError
from .targets import describe, descendants, find_device, open_target


def identify(data):
    if len(data) != 512:
        raise EraseProofError("Incomplete ATA IDENTIFY response.")
    words = struct.unpack("<256H", data)
    if words[0] & 0x8000 or words[83] & 0xc000 != 0x4000:
        raise EraseProofError("ATAPI/unknown ATA command-set data is refused.")
    if data[510] == 0xa5 and sum(data) % 256:
        raise EraseProofError("ATA IDENTIFY checksum mismatch.")
    def text(start, stop):
        raw = data[start:stop]
        value = bytes(byte for i in range(0, len(raw), 2) for byte in (raw[i+1], raw[i])).decode("ascii").strip()
        if not value or any(not 32 <= ord(c) <= 126 for c in value):
            raise EraseProofError("Missing or ambiguous ATA device identity.")
        return value
    lba48 = words[83] & 0xc400 == 0x4400 and bool(words[86] & 0x400)
    visible = int.from_bytes(data[200:208], "little") if lba48 else int.from_bytes(data[120:124], "little")
    sector = 512
    if words[106] & 0xc000 == 0x4000 and words[106] & 0x1000:
        sector = int.from_bytes(data[234:238], "little")*2
    if visible <= 0 or sector not in (512, 4096):
        raise EraseProofError("Unsupported ATA logical sector geometry.")
    return {"serial": text(20, 40), "model": text(54, 94), "visible_sectors": visible, "sector_bytes": sector,
            "lba48": lba48, "amax": bool(words[80] & 0x400 and words[119] & 0x100),
            "hpa_supported": bool(words[82] & 0x400), "dco_supported": bool(words[83] & 0x800),
            "sanitize_supported": bool(words[59] & 0x1000), "sanitize_block": bool(words[59] & 0x8000),
            "sanitize_crypto": bool(words[59] & 0x2000),
            "security": {"supported": bool(words[128] & 1), "enabled": bool(words[128] & 2),
                         "locked": bool(words[128] & 4), "frozen": bool(words[128] & 8),
                         "expired": bool(words[128] & 16), "enhanced": bool(words[128] & 32)},
            "enhanced_time_word": words[90], "identify_sha256": hashlib.sha256(data).hexdigest()}


def capacity(registers, extended=True):
    if len(registers) != 14 or registers[:2] != b"\x09\x0c":
        raise EraseProofError("Missing ATA return descriptor; native capacity is unknown.")
    indices = (7, 9, 11, 6, 8, 10) if extended else (7, 9, 11, 6)
    return sum(registers[index] << (8*n) for n, index in enumerate(indices))+1


def inspect_fd(fd):
    info = identify(firmware.ata(fd, 0)["data"])
    if info["hpa_supported"] or info["amax"]:
        native_op = 11 if info["amax"] else 1 if info["lba48"] else 13
        info["native_sectors"] = capacity(firmware.ata(fd, native_op)["registers"], info["lba48"] or info["amax"])
    else:
        info["native_sectors"] = info["visible_sectors"]
    if info["dco_supported"]:
        data = firmware.ata(fd, 2)["data"]
        checksum = sum(data[:308])+sum(data[416:418])+data[510]+data[511]
        if int.from_bytes(data[:2], "little") not in (1, 2) or checksum % 256:
            raise EraseProofError("DCO data revision or checksum is invalid; capacity remains unknown.")
        info["dco_sectors"] = int.from_bytes(data[6:12], "little")+1
        info["dco_sha256"] = hashlib.sha256(data).hexdigest()
    else:
        info["dco_sectors"] = info["native_sectors"]
    if not info["visible_sectors"] <= info["native_sectors"] <= info["dco_sectors"]:
        raise EraseProofError("ATA visible/native/DCO capacities contradict each other.")
    if info["sanitize_supported"]:
        registers = firmware.ata(fd, 3)["registers"]
        flags = registers[4]
        info["sanitize_status"] = {"flags": flags, "frozen": bool(flags & 32), "busy": bool(flags & 64),
                                   "last_success": bool(flags & 128), "progress_raw": registers[7] | registers[9] << 8}
    return info


def device_gate(path, allow_device=None, confirmation=None, *, writing=False):
    info = describe(path)
    root, device = find_device(path)
    if info["kind"] != "block-device" or device is not root or root.get("type") != "disk" or root.get("tran") not in ("sata", "ata"):
        raise EraseProofError("Select a complete, directly attached ATA/SATA disk. USB bridges, partitions and mapper devices are refused.")
    for child in descendants(root):
        if child.get("ro") or any(child.get("mountpoints") or []):
            raise EraseProofError("ATA disk/child is mounted, swap or read-only; boot/system disks are excluded.")
        holders = Path("/sys/class/block")/Path(child["name"]).name/"holders"
        if holders.exists() and any(holders.iterdir()):
            raise EraseProofError("ATA device has kernel holders; execution is blocked.")
    if writing and (allow_device != info["path"] or not info["serial"] or confirmation != info["serial"]):
        raise EraseProofError("An exact ATA device allowlist and nonempty serial confirmation are required.")
    return info, root


def probe(path):
    target, _ = device_gate(path)
    with open_target(path) as stream:
        info = inspect_fd(stream.fileno())
    if (target["serial"], target["model"], target["size"]) != (info["serial"], info["model"], info["visible_sectors"]*info["sector_bytes"]):
        raise EraseProofError("Linux inventory and ATA IDENTIFY identity/capacity disagree.")
    return {"target": target, "ata": info}


def plan(discovery, method, allow_device, confirmation, open_hidden=False, capacity_sectors=None):
    target, info = discovery["target"], discovery["ata"]
    if allow_device != target["path"] or confirmation != info["serial"] or not confirmation:
        raise EraseProofError("Exact device allowlist and ATA serial confirmation are required.")
    hidden = info["visible_sectors"] != info["dco_sectors"]
    if hidden and (not open_hidden or capacity_sectors != info["dco_sectors"]):
        raise EraseProofError("Hidden HPA/DCO capacity requires --open-hidden and --capacity-sectors matching the discovered factory range.")
    if info["security"]["locked"] or info["security"]["expired"]:
        raise EraseProofError("ATA security is locked or attempts expired; no new erase may start.")
    status = info.get('sanitize_status', {})
    if info['sanitize_supported'] and ('flags' not in status or status.get('busy')):
        raise EraseProofError('ATA sanitize state is unknown or busy; no erase or capacity change may start.')
    if method in ("sanitize-crypto", "sanitize-block"):
        action = "sanitize_crypto" if method == "sanitize-crypto" else "sanitize_block"
        if not info["sanitize_supported"] or not info[action]:
            raise EraseProofError("The requested ATA sanitize action is not advertised.")
        status = info.get("sanitize_status", {})
        if "flags" not in status or status["frozen"] or status["busy"]:
            raise EraseProofError("ATA sanitize state is unknown, frozen or busy.")
    elif method == "enhanced-secure-erase":
        security = info["security"]
        if not security["supported"] or not security["enhanced"] or security["enabled"] or security["frozen"]:
            raise EraseProofError("Enhanced erase needs advertised support, unfrozen security and no existing password.")
    elif method != "open-hidden":
        raise EraseProofError("Unknown ATA method.")
    if method == "open-hidden" and not hidden:
        raise EraseProofError("No hidden capacity is reported; no configuration change is needed.")
    if hidden and not info["lba48"]:
        raise EraseProofError("Hidden-capacity expansion requires a verified 48-bit ATA layout.")
    return {"target": target, "method": method, "serial": info["serial"], "factory_sectors": info["dco_sectors"],
            "open_hidden": hidden, "before": info, "certificate_eligible": False,
            "scope": "Complete ATA device including explicitly opened HPA/DCO. Firmware behavior and physical erasure require independent hardware evaluation.",
            "warning": "Firmware erasure cannot be cancelled by closing this application. DCO restore permanently resets device configuration."}


def open_capacity(fd, prepared):
    before = prepared["before"]
    def expand(info):
        if info["visible_sectors"] < info["native_sectors"]:
            # Legacy ATA requires READ NATIVE MAX immediately before SET MAX.
            firmware.ata(fd, 11 if info["amax"] else 1)
            firmware.ata(fd, 12 if info["amax"] else 6, info["native_sectors"])
    expand(before)
    current = inspect_fd(fd)
    if current["dco_sectors"] > current["native_sectors"]:
        firmware.ata(fd, 7)
        current = inspect_fd(fd)
        expand(current)
    after = inspect_fd(fd)
    if after["visible_sectors"] != prepared["factory_sectors"] or after["native_sectors"] != prepared["factory_sectors"] or after["dco_sectors"] != prepared["factory_sectors"]:
        raise EraseProofError("Hidden-capacity read-back failed. No erasure started; capacity may already have changed.")
    if (after["serial"], after["model"]) != (before["serial"], before["model"]):
        raise EraseProofError("ATA identity changed after capacity expansion.")
    return after


def credential(password, enhanced=False):
    buffer = bytearray(512)
    buffer[0] = 2 if enhanced else 0
    buffer[2:34] = password
    return buffer


def submit(path, method, allow_device, confirmation, evidence_dir, open_hidden=False, capacity_sectors=None, *, expected_identity=None):
    from .media import outside_devices
    if os.geteuid() != 0:
        raise EraseProofError("ATA execution requires an explicit root CLI invocation.")
    target, root = device_gate(path, allow_device, confirmation, writing=True)
    discovery = probe(path)
    observed = discovery['ata']
    if expected_identity is not None and (observed['serial'], observed['model'], observed['sector_bytes'], observed['dco_sectors']) != expected_identity:
        raise EraseProofError('ATA identity or factory capacity differs from the confirmed workflow; no command sent.')
    prepared = plan(discovery, method, allow_device, confirmation, open_hidden, capacity_sectors)
    outside_devices(evidence_dir, [root])
    store = EvidenceStore(evidence_dir)
    if not store.check():
        raise EraseProofError("Audit history is damaged; no ATA command sent.")
    store.key()
    job = "ata-"+uuid.uuid4().hex
    key_path = None
    with open_target(path, writable=True) as source:
        opened = os.fstat(source.fileno())
        if opened.st_rdev != os.stat(path, follow_symlinks=False).st_rdev:
            raise EraseProofError("ATA device changed while opening.")
        fresh, _ = device_gate(path, allow_device, confirmation, writing=True)
        info = inspect_fd(source.fileno())
        if fresh != target or digest(info) != digest(discovery["ata"]):
            raise EraseProofError("ATA device identity, capacity or state changed; no command sent.")
        store.append("firmware.ata-started", {"job": job, "plan": prepared})
        try:
            if prepared["open_hidden"]:
                info = open_capacity(source.fileno(), prepared)
                store.append("firmware.ata-capacity-opened", {"job": job, "after": info})
                if method != "open-hidden":
                    plan({"target": target, "ata": info}, method, allow_device, confirmation)
            if method == "enhanced-secure-erase":
                # Persist a private recovery credential before enabling security.
                # On interruption, never automatically clear a password or retry.
                password = bytearray(os.urandom(16).hex().encode("ascii"))
                key_path = store.root/(job+".recovery.key")
                key_fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(key_fd, "wb") as key:
                    key.write(password)
                    key.flush()
                    os.fsync(key.fileno())
                directory_fd = os.open(store.root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                store.append("firmware.ata-credential-saved", {"job": job, "recovery_key_path": str(key_path)})
                buffer = credential(password)
                password[:] = bytes(len(password))
                try:
                    firmware.ata(source.fileno(), 8, payload=buffer)
                    if not inspect_fd(source.fileno())["security"]["enabled"]:
                        raise EraseProofError("ATA password enable read-back failed.")
                    buffer[0] = 2
                    word = info["enhanced_time_word"]
                    units = word & (0x7fff if word & 0x8000 else 0xff)
                    timeout = min(4000000000, max(12*3600000, (units*2+90)*60000))
                    firmware.ata(source.fileno(), 9, payload=buffer, timeout=timeout)
                finally:
                    buffer[:] = bytes(len(buffer))
                after = inspect_fd(source.fileno())
                if after["security"]["enabled"] or after["security"]["locked"]:
                    raise EraseProofError("ATA security remains enabled/locked after erase; recovery credential retained.")
                key_path.unlink()
                state = "firmware-reports-completion"
            elif method.startswith("sanitize-"):
                firmware.ata(source.fileno(), 5 if method == "sanitize-crypto" else 4)
                after, state = inspect_fd(source.fileno()), "accepted-awaiting-verification"
            else:
                after, state = inspect_fd(source.fileno()), "capacity-opened-no-erasure"
            if (after["serial"], after["model"], after["visible_sectors"], after["native_sectors"], after["dco_sectors"]) != (info["serial"], info["model"], prepared["factory_sectors"], prepared["factory_sectors"], prepared["factory_sectors"]):
                raise EraseProofError("Post-command identity or hidden capacity check failed.")
        except BaseException as error:
            store.append("firmware.ata-incomplete", {"job": job, "reason": str(error),
                "recovery_key_path": str(key_path) if key_path and key_path.exists() else None,
                "instruction": "Inspect device status. A firmware command may continue; never assume interruption cancelled it."})
            raise
        receipt = store.sign({"schema": "eraseproof.firmware-receipt.v1", "job": job, "at": now(),
                              "plan": prepared, "after": after, "state": state, "certificate_issued": False})
        store.append("firmware.ata-receipt", {"job": job, "receipt_sha256": receipt["payload_sha256"]})
    with (store.root/(job+".json")).open("x") as file:
        json.dump(receipt, file, indent=2)
    return receipt


def recover_security(path, allow_device, confirmation, recovery_key, evidence_dir):
    """Explicit recovery from an interrupted password-based erase; no erasure."""
    from .media import outside_devices
    if os.geteuid() != 0:
        raise EraseProofError("ATA password recovery requires an explicit root CLI invocation.")
    target, root = device_gate(path, allow_device, confirmation, writing=True)
    outside_devices(evidence_dir, [root])
    store = EvidenceStore(evidence_dir)
    if not store.check():
        raise EraseProofError("Audit history is damaged.")
    store.key()
    key_fd = os.open(recovery_key, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(key_fd, "rb") as key:
        key_info = os.fstat(key.fileno())
        if not stat.S_ISREG(key_info.st_mode) or key_info.st_mode & 0o077 or key_info.st_size != 32 or key_info.st_uid != os.geteuid():
            raise EraseProofError("Use the private 32-byte recovery key owned by the invoking root operator (mode 600).")
        password = bytearray(key.read(32))
    buffer = credential(password)
    password[:] = bytes(len(password))
    job = "ata-security-recovery-"+uuid.uuid4().hex
    try:
        with open_target(path, writable=True) as source:
            device_gate(path, allow_device, confirmation, writing=True)
            current = identify(firmware.ata(source.fileno(), 0)["data"])
            if (current["serial"], current["model"]) != (target["serial"], target["model"]) or current["security"]["frozen"]:
                raise EraseProofError("ATA identity changed or security is frozen; recovery blocked.")
            if not current["security"]["enabled"]:
                raise EraseProofError("No ATA security password is enabled; nothing to recover.")
            store.append("firmware.ata-security-recovery-started", {"job": job, "target": target})
            try:
                if current["security"]["locked"]:
                    firmware.ata(source.fileno(), 15, payload=buffer)
                firmware.ata(source.fileno(), 10, payload=buffer)
                after = identify(firmware.ata(source.fileno(), 0)["data"])
                if after["security"]["enabled"] or after["security"]["locked"]:
                    raise EraseProofError("ATA password recovery read-back failed.")
            except BaseException as error:
                store.append("firmware.ata-security-recovery-incomplete", {"job": job, "reason": str(error)})
                raise
            receipt = store.sign({"schema": "eraseproof.firmware-receipt.v1", "job": job, "at": now(), "target": target,
                                  "state": "operator-recovered-security-access", "after": after,
                                  "certificate_issued": False, "scope": "Unlock/disable the saved temporary password only. No erasure or data recovery is established."})
            store.append("firmware.ata-security-recovered", {"job": job, "receipt_sha256": receipt["payload_sha256"]})
            with (store.root/(job+".json")).open("x") as file:
                json.dump(receipt, file, indent=2)
            return receipt
    finally:
        buffer[:] = bytes(len(buffer))

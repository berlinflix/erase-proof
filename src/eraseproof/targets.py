"""Target identity, bounded I/O and virtual-disk safety policy."""
import json
import os
from pathlib import Path
import platform
import stat
import struct
import subprocess

from .models import EraseProofError

VIRTUAL_MODELS = ("vbox", "virtual disk", "vmware", "qemu", "virtio")


def devices() -> list[dict]:
    if platform.system() != "Linux":
        raise EraseProofError("Device discovery requires Linux. Use WSL or your Ubuntu VM.")
    result = subprocess.run(
        ["lsblk", "--json", "--bytes", "--paths", "--output",
         "NAME,TYPE,SIZE,MODEL,SERIAL,ROTA,RO,MOUNTPOINTS,TRAN"],
        capture_output=True, text=True, check=False, timeout=15,
    )
    if result.returncode:
        raise EraseProofError(result.stderr.strip() or "lsblk failed")
    return json.loads(result.stdout).get("blockdevices", [])


def descendants(device):
    yield device
    for child in device.get("children", []):
        yield from descendants(child)


def find_device(path, inventory=None):
    resolved = str(Path(path).resolve())
    for root in devices() if inventory is None else inventory:
        for device in descendants(root):
            if device["name"] == resolved:
                return root, device
    raise EraseProofError("Device is absent from the current lsblk inventory.")


def virtual_disk_policy(path, confirmation, allow_device, inventory=None):
    resolved = str(Path(path).resolve())
    root, device = find_device(resolved, inventory)
    if device is not root or device.get("type") != "disk":
        raise EraseProofError("Select a complete secondary virtual disk, not a partition or mapper.")
    if not allow_device or str(Path(allow_device).resolve()) != resolved:
        raise EraseProofError("A block-device write needs an explicit matching --allow-device path.")
    model = (device.get("model") or "").strip()
    if not any(token in model.lower() for token in VIRTUAL_MODELS):
        raise EraseProofError("This release only enables block writes to recognized virtual disks. Physical-media sanitization is not implemented.")
    for child in descendants(root):
        if child.get("ro") or any(child.get("mountpoints") or []):
            raise EraseProofError("Target or a child is mounted, in use as swap, or read-only. System disks are excluded.")
    serial = (device.get("serial") or "").strip()
    if not serial:
        raise EraseProofError("No device serial was reported; destructive execution is blocked.")
    if confirmation != serial:
        raise EraseProofError("Confirmation must exactly match the device serial.")
    return {"kind": "virtual-block-device", "path": resolved, "size": int(device["size"]),
            "model": model, "serial": serial, "scope": "Guest-visible logical sectors only; no host/physical remanence claim."}


def describe(path):
    p = Path(path).expanduser()
    if p.is_symlink():
        raise EraseProofError("Symlink targets are refused. Select the real path.")
    info = p.stat()
    if stat.S_ISREG(info.st_mode):
        return {"kind": "image", "path": str(p.resolve()), "size": info.st_size,
                "model": "Raw image file", "serial": p.name,
                "scope": "Current image bytes only, excluding host snapshots and storage remnants."}
    if stat.S_ISBLK(info.st_mode):
        import fcntl
        with p.open("rb", buffering=0) as stream:
            length = struct.unpack("Q", fcntl.ioctl(stream, 0x80081272, bytes(8)))[0]
        _, device = find_device(p)
        return {"kind": "block-device", "path": str(p.resolve()), "size": length,
                "model": (device.get("model") or "").strip(),
                "serial": (device.get("serial") or "").strip(),
                "scope": "Host-visible logical sectors; no physical remanence claim."}
    raise EraseProofError("Only regular image files and Linux block devices are supported.")


def open_target(path, writable=False):
    flags = os.O_RDWR if writable else os.O_RDONLY
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    if writable and stat.S_ISBLK(os.lstat(path).st_mode):
        # Linux rejects an O_EXCL open of a block device already in use.
        flags |= os.O_EXCL
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISBLK(info.st_mode)):
            raise EraseProofError("The opened object is not an image or block device.")
        if writable:
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise EraseProofError("Hard-linked files are refused for destructive operations.")
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return os.fdopen(fd, "r+b" if writable else "rb", buffering=0)
    except BaseException:
        os.close(fd)
        raise

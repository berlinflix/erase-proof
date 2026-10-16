"""Native firmware boundary: fd-based, restricted commands, explicit failures."""
import ctypes
from functools import lru_cache
import os
from pathlib import Path

from .models import EraseProofError


@lru_cache(maxsize=1)
def library():
    path = Path(__file__).parent/"resources/native/liberaseproof_firmware.so"
    if not path.is_file():
        raise EraseProofError("Native firmware adapter missing; rebuild with scripts/build-native.sh.")
    lib = ctypes.CDLL(str(path), use_errno=True)
    status = ctypes.POINTER(ctypes.c_uint32)
    lib.ep_nvme_identify.argtypes = [ctypes.c_int, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, status]
    lib.ep_nvme_format.argtypes = [ctypes.c_int, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, status]
    lib.ep_nvme_format_fields.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, status]
    lib.ep_nvme_sanitize.argtypes = [ctypes.c_int, ctypes.c_uint32, status]
    lib.ep_tcg_discovery.argtypes = [ctypes.c_int, ctypes.c_void_p, status]
    lib.ep_tcg_discovery.restype = ctypes.c_int
    lib.ep_ata_fields.argtypes = [ctypes.c_uint32, ctypes.c_uint64, ctypes.c_void_p]
    lib.ep_ata.argtypes = [ctypes.c_int, ctypes.c_uint32, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
    lib.ep_ata.restype = lib.ep_ata_fields.restype = ctypes.c_int
    for name in ("ep_nvme_identify", "ep_nvme_format", "ep_nvme_format_fields", "ep_nvme_sanitize"):
        getattr(lib, name).restype = ctypes.c_int
    return lib


def call(name, *arguments):
    status = ctypes.c_uint32()
    error = getattr(library(), name)(*arguments, ctypes.byref(status))
    if error:
        suffix = 'A submitted command may continue; inspect the device before retrying.' if name in ('ep_nvme_format', 'ep_nvme_sanitize') else 'Read-only query failed.'
        raise EraseProofError(f"Native firmware ioctl failed: {os.strerror(error)}. {suffix}")
    if status.value:
        raise EraseProofError(f"NVMe controller rejected the command (status 0x{status.value:x}). No erasure certificate issued.")
    return {"transport": "NVME_IOCTL_ADMIN_CMD", "status": 0}


def identify(fd, nsid=0):
    buffer = ctypes.create_string_buffer(4096)
    call("ep_nvme_identify", fd, nsid, 0 if nsid else 1, buffer)
    return buffer.raw


def format_nvm(fd, nsid, lbaf, ses):
    return call("ep_nvme_format", fd, nsid, lbaf, ses)


def sanitize(fd, action):
    return call("ep_nvme_sanitize", fd, action)


def tcg_discovery(fd):
    buffer = ctypes.create_string_buffer(2048)
    call('ep_tcg_discovery', fd, buffer)
    return buffer.raw


def ata(fd, operation, value=0, payload=None, timeout=30000):
    registers = ctypes.create_string_buffer(14)
    buffer = ctypes.create_string_buffer(512) if operation in (0, 2) else None
    if operation in (8, 9, 10, 15):
        if not isinstance(payload, bytearray) or len(payload) != 512:
            raise EraseProofError("ATA security operation needs its private fixed-size credential buffer.")
        buffer = (ctypes.c_ubyte*512).from_buffer(payload)
    error = library().ep_ata(fd, operation, value, buffer, timeout, registers)
    if error:
        suffix = 'Read-only query failed.' if operation in (0, 1, 2, 3, 11, 13) else 'The operation may have started; inspect status before retrying.'
        raise EraseProofError(f"ATA SG_IO failed: {os.strerror(error)}. {suffix}")
    return {"data": buffer.raw if operation in (0, 2) else None, "registers": registers.raw}

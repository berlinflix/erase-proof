"""Optional Linux C I/O library, operating solely on policy-checked descriptors."""
import ctypes
import os
from pathlib import Path

from .models import EraseProofError

ALIGN = 4096


class Extent(ctypes.Structure):
    _fields_ = [("logical", ctypes.c_uint64), ("physical", ctypes.c_uint64),
                ("length", ctypes.c_uint64), ("reserved64", ctypes.c_uint64*2),
                ("flags", ctypes.c_uint32), ("reserved", ctypes.c_uint32*3)]


def library():
    path = Path(__file__).parent/"resources"/"native"/"liberaseproof_io.so"
    if not path.is_file():
        return None
    lib = ctypes.CDLL(str(path), use_errno=True)
    lib.ep_zero.argtypes = [ctypes.c_int, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int]
    lib.ep_zero.restype = ctypes.c_int
    lib.ep_fiemap.argtypes = [ctypes.c_int, ctypes.c_uint64, ctypes.c_uint32,
                             ctypes.POINTER(Extent), ctypes.POINTER(ctypes.c_uint32)]
    lib.ep_fiemap.restype = ctypes.c_int
    lib.ep_discard.argtypes = [ctypes.c_int, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int]
    lib.ep_discard.restype = ctypes.c_int
    return lib


def discard(fd, length, secure=False):
    lib = library()
    if lib is None:
        raise EraseProofError('Native discard adapter missing.')
    error = lib.ep_discard(fd, 0, length, int(secure))
    if error:
        raise EraseProofError('Discard failed: '+os.strerror(error))


def zero(fd, offset, length, *, direct=True):
    lib = library()
    if lib is None:
        raise EraseProofError("Native I/O library missing. Run bash scripts/build-native.sh.")
    if min(offset, length) < 0:
        raise EraseProofError("Negative native I/O range.")
    error = lib.ep_zero(fd, offset, length, int(direct))
    if error:
        raise EraseProofError(f"Native {'O_DIRECT' if direct else 'tail'} write failed: {os.strerror(error)}. The target may be partially overwritten.")


def extents(fd):
    lib = library()
    if lib is None:
        raise EraseProofError("Native I/O library missing. Run bash scripts/build-native.sh.")
    result, start = [], 0
    while True:
        values, count = (Extent*256)(), ctypes.c_uint32()
        error = lib.ep_fiemap(fd, start, 256, values, ctypes.byref(count))
        if error:
            raise EraseProofError("FIEMAP failed: "+os.strerror(error))
        if not count.value:
            return result
        for item in values[:count.value]:
            if not item.length or item.logical < start:
                raise EraseProofError("Invalid FIEMAP extent ordering.")
            result.append({"logical": item.logical, "physical": item.physical,
                           "length": item.length, "flags": item.flags})
            start = item.logical+item.length
        if values[count.value-1].flags & 1:
            return result
        if len(result) > 1_000_000:
            raise EraseProofError("FIEMAP inventory limit reached.")

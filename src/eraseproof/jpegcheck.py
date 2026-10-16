"""Strict no-warning JPEG validator; never claims pixel authenticity."""
import ctypes
from functools import lru_cache
from pathlib import Path

from .models import EraseProofError


@lru_cache(maxsize=1)
def library():
    path = Path(__file__).parent/'resources/native/liberaseproof_jpeg.so'
    if not path.is_file():
        raise EraseProofError('Strict JPEG fragment validator missing; rebuild native adapters.')
    lib = ctypes.CDLL(str(path))
    lib.ep_jpeg_valid.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    lib.ep_jpeg_valid.restype = ctypes.c_int
    lib.ep_jpeg_probe.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    lib.ep_jpeg_probe.restype = ctypes.c_int
    return lib


def valid(payload):
    return bool(library().ep_jpeg_valid(payload, len(payload)))


def probe(payload):
    position = ctypes.c_ulong()
    valid = library().ep_jpeg_probe(payload, len(payload), ctypes.byref(position))
    return bool(valid), position.value

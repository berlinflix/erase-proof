"""Streaming ssdeep and exact fingerprints; similarity is evidence, not identity."""
from collections import Counter
import ctypes
import ctypes.util
from functools import lru_cache
import hashlib
import math
from pathlib import Path
import re

from .models import EraseProofError

MAX_REFERENCES = 1024


def valid_signature(value):
    if not isinstance(value, str) or len(value) > 148:
        return False
    match = re.fullmatch(r"([0-9]{1,12}):([A-Za-z0-9+/]{0,64}):([A-Za-z0-9+/]{0,64})", value)
    if not match:
        return False
    block = int(match[1])
    return block >= 3 and block % 3 == 0 and not ((block//3) & (block//3-1))


@lru_cache(maxsize=1)
def library():
    bundled = Path(__file__).parent/"resources/native/libfuzzy.so.2"
    path = str(bundled) if bundled.is_file() else ctypes.util.find_library("fuzzy")
    if not path:
        raise EraseProofError("ssdeep library missing. Install libfuzzy2 or rebuild the Ubuntu bundle.")
    lib = ctypes.CDLL(path, use_errno=True)
    lib.fuzzy_new.argtypes, lib.fuzzy_new.restype = [], ctypes.c_void_p
    lib.fuzzy_update.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    lib.fuzzy_update.restype = ctypes.c_int
    lib.fuzzy_digest.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]
    lib.fuzzy_digest.restype = ctypes.c_int
    lib.fuzzy_free.argtypes, lib.fuzzy_free.restype = [ctypes.c_void_p], None
    lib.fuzzy_compare.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.fuzzy_compare.restype = ctypes.c_int
    return lib


class FuzzyHash:
    def __init__(self):
        self.lib = library()
        self.state = self.lib.fuzzy_new()
        if not self.state:
            raise EraseProofError("Cannot allocate ssdeep state.")

    def update(self, data):
        if not self.state or self.lib.fuzzy_update(self.state, data, len(data)):
            raise EraseProofError("ssdeep update failed.")

    def hexdigest(self):
        output = ctypes.create_string_buffer(148)
        if not self.state or self.lib.fuzzy_digest(self.state, output, 0):
            raise EraseProofError("ssdeep digest failed.")
        return output.value.decode("ascii")

    def close(self):
        if self.state:
            self.lib.fuzzy_free(self.state)
            self.state = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def compare(left, right):
    if not valid_signature(left) or not valid_signature(right):
        raise EraseProofError("Malformed ssdeep signature.")
    score = library().fuzzy_compare(left.encode("ascii"), right.encode("ascii"))
    if not 0 <= score <= 100:
        raise EraseProofError("ssdeep comparison failed.")
    return score


def matches(signature, references, threshold=70):
    return [{"reference_index": index, "score": score} for index, reference in enumerate(references)
            if (score := compare(signature, reference)) >= threshold]


def measure(chunks, cancel=None):
    from .carve import checkpoint
    sha, blocks, counts, pending, size = hashlib.sha256(), set(), Counter(), b"", 0
    with FuzzyHash() as fuzzy:
        for chunk in chunks:
            checkpoint(cancel)
            sha.update(chunk)
            fuzzy.update(chunk)
            counts.update(chunk)
            size += len(chunk)
            pending += chunk
            full = len(pending)//4096*4096
            for at in range(0, full, 4096):
                blocks.add(hashlib.sha256(pending[at:at+4096]).hexdigest())
            pending = pending[full:]
        if pending:
            blocks.add(hashlib.sha256(pending).hexdigest())
        entropy = -sum((n/size)*math.log2(n/size) for n in counts.values()) if size else 0.0
        return {"sha256": sha.hexdigest(), "size": size, "ssdeep": fuzzy.hexdigest(),
                "block_hashes_4096": sorted(blocks), "entropy_bits_per_byte": round(entropy, 6)}

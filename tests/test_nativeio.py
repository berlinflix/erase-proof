import os

import pytest

from eraseproof import nativeio
from eraseproof.models import EraseProofError


@pytest.mark.skipif(nativeio.library() is None, reason="Run scripts/build-native.sh for native I/O tests")
def test_c_direct_writes_tail_and_bounds(tmp_path):
    path = tmp_path/"range.img"
    path.write_bytes(b"x"*(16384+17))
    with path.open("r+b", buffering=0) as stream:
        original_flags = __import__("fcntl").fcntl(stream.fileno(), __import__("fcntl").F_GETFL)
        nativeio.zero(stream.fileno(), 4096, 8192)
        assert __import__("fcntl").fcntl(stream.fileno(), __import__("fcntl").F_GETFL) == original_flags
        nativeio.zero(stream.fileno(), 16384, 17, direct=False)
        with pytest.raises(EraseProofError):
            nativeio.zero(stream.fileno(), 0, 16384+4096)
        with pytest.raises(EraseProofError):
            nativeio.zero(stream.fileno(), 1, 4096)
        with pytest.raises(EraseProofError):
            nativeio.zero(stream.fileno(), -1, 4096)
    # A separate descriptor observes the exact selected ranges only.
    assert path.read_bytes() == b"x"*4096+bytes(8192)+b"x"*4096+bytes(17)


@pytest.mark.skipif(nativeio.library() is None, reason="Run scripts/build-native.sh for native I/O tests")
def test_fiemap_has_real_logical_extents(tmp_path):
    path = tmp_path/"mapped.bin"
    with path.open("w+b", buffering=0) as stream:
        stream.write(os.urandom(16384))
        os.fsync(stream.fileno())
        mapped = nativeio.extents(stream.fileno())
        assert mapped and mapped[0]["logical"] == 0
        assert sum(item["length"] for item in mapped) >= 16384
        assert mapped[-1]["flags"] & 1

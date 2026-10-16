import hashlib
import os
from pathlib import Path
import subprocess
import struct

import pytest

from eraseproof.evidence import EvidenceStore
from eraseproof.models import EraseProofError
from eraseproof.ntfs import erase_path, helper, plan_path


def tool(*args):
    result = subprocess.run(list(map(str, args)), capture_output=True)
    if result.returncode:
        raise RuntimeError((result.stdout+result.stderr).decode(errors="replace"))
    return result.stdout


def fixture(tmp_path):
    image = tmp_path/"volume.img"
    with image.open("xb") as stream:
        stream.truncate(64*1024*1024)
    tool("mkfs.ntfs", "-F", "-Q", image)
    tool(helper(), "mkdir", image, "/private-case")
    small, large, keep = tmp_path/"small", tmp_path/"large", tmp_path/"keep"
    small.write_bytes(b"NTFS-RESIDENT-SECRET-"+os.urandom(27))
    large.write_bytes(b"NTFS-LARGE-SECRET-CONTENT-"*1300)
    keep.write_bytes(os.urandom(40011))
    for source, internal in ((small, "/private-case/small.bin"), (large, "/private-case/large.bin"), (keep, "/keep.bin"), (large, "/old-copy.bin")):
        tool("ntfscp", image, source, internal)
    tool("ntfscp", "-N", "private-stream", image, small, "/private-case/large.bin")
    tool("ntfscp", "-N", "keep-stream", image, keep, "/keep.bin")
    tool(helper(), "remove", image, "/old-copy.bin")
    return image, small, large, keep


def test_ntfs_resident_streams_history_and_preservation(tmp_path):
    image, small, large, keep = fixture(tmp_path)
    before = image.read_bytes()
    assert small.read_bytes() in before and large.read_bytes() in before
    prepared = plan_path(image, "/private-case")
    assert len(prepared["selected"]) == 4
    record = erase_path(image, "/private-case", prepared["confirmation"], tmp_path/"case")
    result = record["payload"]["verification"]
    assert result["passed"] and result["rrs"] == 0
    assert result["preserved_files_hash_checked"] == 2
    after = image.read_bytes()
    assert small.read_bytes() not in after and large.read_bytes() not in after
    assert "small.bin".encode("utf-16-le") not in after
    assert "old-copy.bin".encode("utf-16-le") not in after
    # ntfscat reads the unrelated allocated stream directly from the volume.
    assert tool("ntfscat", image, "/keep.bin") == keep.read_bytes()
    assert tool("ntfscat", "-n", "keep-stream", image, "/keep.bin") == keep.read_bytes()
    tool("ntfsresize", "--info", "--no-action", "--no-progress-bar", image)


def test_ntfs_preconditions_preserve_image(tmp_path):
    image, _, _, _ = fixture(tmp_path)
    before = hashlib.sha256(image.read_bytes()).digest()
    with pytest.raises(EraseProofError):
        erase_path(image, "/private-case", "wrong", tmp_path/"case")
    for path in ("/", "/$MFT", "/private-case/../keep.bin", "/private-case/large.bin:private-stream"):
        with pytest.raises(EraseProofError):
            plan_path(image, path)
    assert hashlib.sha256(image.read_bytes()).digest() == before


def test_ntfs_live_copy_prevents_certificate(tmp_path):
    image, _, large, _ = fixture(tmp_path)
    tool("ntfscp", image, large, "/live-copy.bin")
    with pytest.raises(EraseProofError, match="residue remains"):
        erase_path(image, "/private-case", "volume.img:/private-case", tmp_path/"case")
    store = EvidenceStore(tmp_path/"case")
    assert store.records() == []
    assert store.events()[-1]["payload"]["detail"]["verification"]["rrs"] > 0


@pytest.mark.parametrize("known_content", [True, False])
def test_ntfs_reintroduced_free_copy_is_detected(tmp_path, monkeypatch, known_content):
    from eraseproof import ntfs
    image, small, _, _ = fixture(tmp_path)
    original = ntfs.scrub
    def inject(*args, **kwargs):
        result = original(*args, **kwargs)
        with image.open("r+b", buffering=0) as stream:
            stream.seek(image.stat().st_size-3*4096)
            stream.write(small.read_bytes() if known_content else os.urandom(113))
            os.fsync(stream.fileno())
        return result
    monkeypatch.setattr(ntfs, "scrub", inject)
    with pytest.raises(EraseProofError, match="residue remains"):
        erase_path(image, "/private-case", "volume.img:/private-case", tmp_path/"case")
    store = EvidenceStore(tmp_path/"case")
    assert store.records() == []
    verification = store.events()[-1]["payload"]["detail"]["verification"]
    assert verification["history_verification"]["nonzero_free_bytes"] > 0
    if not known_content:
        assert verification["rrs"] == 0


@pytest.mark.parametrize("resident", [False, True])
def test_ntfs_allocated_usn_payload_is_cleaned(tmp_path, resident):
    image, small, _, _ = fixture(tmp_path)
    maximum = tmp_path/"usn-max"
    maximum.write_bytes(struct.pack("<QQQQ", 1024*1024, 65536, 123456789, 0))
    payload = tmp_path/"usn-data"
    payload.write_bytes((small.read_bytes()+"small.bin".encode("utf-16-le"))*(1 if resident else 200))
    tool("ntfscp", "-N", "$Max", image, maximum, "/$Extend/$UsnJrnl")
    tool("ntfscp", "-N", "$J", image, payload, "/$Extend/$UsnJrnl")
    assert tool("ntfscat", "-n", "$J", image, "/$Extend/$UsnJrnl") == payload.read_bytes()
    record = erase_path(image, "/private-case", "volume.img:/private-case", tmp_path/"case")
    assert record["payload"]["verification"]["cleanup"]["usn_bytes_cleared"] == payload.stat().st_size
    history = record["payload"]["verification"]["history_verification"]
    assert history["usn_bytes_checked"] == payload.stat().st_size and history["nonzero_usn_bytes"] == 0
    assert tool("ntfscat", "-n", "$J", image, "/$Extend/$UsnJrnl") == bytes(payload.stat().st_size)

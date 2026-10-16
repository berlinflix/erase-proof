import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

import pytest

from eraseproof.evidence import EvidenceStore
from eraseproof.exfat import Volume, erase_path, list_paths, plan_path
from eraseproof.models import EraseProofError


def tool(*arguments):
    result = subprocess.run(list(map(str, arguments)), capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError((result.stdout+result.stderr).decode(errors="replace")[-4000:])
    return result.stdout.decode().strip()


def empty_image(tmp_path, filesystem="exfat"):
    image = tmp_path/"volume.img"
    with image.open("xb") as stream:
        stream.truncate(64*1024*1024)
    if filesystem == "fat32":
        tool("mkfs.fat", "-F", "32", image)
    else:
        tool("mkfs.exfat", image)
    return image


def fixture(tmp_path, filesystem="exfat", extra_name=None):
    if os.geteuid() != 0 or os.environ.get("ERASEPROOF_TEST_PRIVATE_MOUNTS") != "1":
        pytest.skip("Run exFAT driver tests as root under unshare --mount --propagation private with ERASEPROOF_TEST_PRIVATE_MOUNTS=1")
    image = empty_image(tmp_path, filesystem)
    mountpoint = tmp_path/"mnt"
    mountpoint.mkdir()
    loop, mounted = None, False
    secret = b"EXFAT-FRESH-SECRET-"+os.urandom(146)
    large, keep = os.urandom(19513), os.urandom(13017)
    try:
        loop = tool("losetup", "--find", "--show", image)
        association = json.loads(tool("losetup", "--list", "--json", "--output", "NAME,BACK-FILE", loop))["loopdevices"][0]
        if Path(association["back-file"]).resolve() != image.resolve():
            raise RuntimeError("Unexpected loop backing file; mount refused")
        if filesystem == "fat32":
            tool("mount", "-t", "vfat", "-o", "utf8=1", loop, mountpoint)
        else:
            tool("mount.exfat-fuse", loop, mountpoint)
        mounted = True
        private = mountpoint/"private-case"
        private.mkdir()
        (private/"small-secret.bin").write_bytes(secret)
        if extra_name:
            (private/extra_name).write_bytes(secret)
        (private/"large-secret.bin").write_bytes(large)
        (mountpoint/"keep-日本-Ω.txt").write_bytes(keep)
        history = mountpoint/"old-copy-私.bin"
        history.write_bytes(secret*73)
        # Interleaved growth forces a real noncontiguous FAT chain through the
        # filesystem driver; this does not construct entries with our parser.
        fragmented = private/"fragmented.bin"
        for index in range(12):
            with fragmented.open("ab") as stream:
                stream.write(secret+os.urandom(4096-len(secret)))
                stream.flush()
                os.fsync(stream.fileno())
            filler = mountpoint/("filler-"+str(index))
            with filler.open("wb") as stream:
                stream.write(os.urandom(8192))
                stream.flush()
                os.fsync(stream.fileno())
        tool("sync", "-f", mountpoint)
        history.unlink()
        for filler in mountpoint.glob("filler-*"):
            filler.unlink()
        tool("sync", "-f", mountpoint)
        tool("umount", mountpoint)
        mounted = False
        tool("losetup", "--detach", loop)
        loop = None
        # FUSE can briefly retain its descriptor after umount; Linux defers a
        # loop detach until that descriptor is released. Do not weaken the
        # product's unattached-image gate to accommodate this test race.
        deadline = time.monotonic()+5
        while tool("losetup", "--associated", image):
            if time.monotonic() >= deadline:
                raise RuntimeError("Fixture loop detach did not finish")
            time.sleep(.05)
    finally:
        if mounted:
            tool("umount", mountpoint)
        if loop:
            tool("losetup", "--detach", loop)
    return image, secret, large, keep


def test_exfat_boot_checksums_and_empty_inventory(tmp_path):
    image = empty_image(tmp_path)
    assert list_paths(image) == []
    with image.open("r+b") as stream:
        stream.seek(100)
        stream.write(b"BAD!")
    with pytest.raises(EraseProofError, match="checksum"):
        list_paths(image)


def test_exfat_driver_files_fragments_history_and_preservation(tmp_path):
    image, secret, large, keep = fixture(tmp_path)
    with image.open("rb") as stream:
        v = Volume(stream)
        chain = v.files["/private-case/fragmented.bin"]["chain"]
        assert any(b != a+1 for a, b in zip(chain, chain[1:]))
    assert secret in image.read_bytes() and large in image.read_bytes()
    prepared = plan_path(image, "/private-case")
    assert len(prepared["selected"]) == 4
    record = erase_path(image, "/private-case", prepared["confirmation"], tmp_path/"case")
    result = record["payload"]["verification"]
    assert result["passed"] and result["rrs"] == 0
    assert result["preserved_files_hash_checked"] == 1
    assert result["history_verification"]["free_clusters_checked"] > 0
    after = image.read_bytes()
    assert secret not in after and large not in after
    assert "old-copy-私.bin".encode("utf-16-le") not in after
    entry = list_paths(image)[0]
    from eraseproof.exfat import fingerprint
    with image.open("rb") as stream:
        assert fingerprint(stream, entry)[0]["sha256"] == hashlib.sha256(keep).hexdigest()
    # Independent Sleuth Kit extraction checks preserved bytes too.
    output = subprocess.run(["fls", "-u", "-r", "-p", str(image)], capture_output=True, check=True).stdout.decode()
    inode = next(line.split(":\t")[0].split()[-1] for line in output.splitlines() if "keep-日本-Ω.txt" in line)
    assert subprocess.run(["icat", str(image), inode], capture_output=True, check=True).stdout == keep
    tool("fsck.exfat", "-n", image)


def test_exfat_confirmation_and_path_gates_preserve_image(tmp_path):
    image, *_ = fixture(tmp_path)
    before = hashlib.sha256(image.read_bytes()).digest()
    with pytest.raises(EraseProofError):
        erase_path(image, "/private-case", "wrong", tmp_path/"case")
    for internal in ("/", "/private-case/../keep-日本-Ω.txt", "/missing"):
        with pytest.raises(EraseProofError):
            plan_path(image, internal)
    assert hashlib.sha256(image.read_bytes()).digest() == before


@pytest.mark.parametrize("location,known_content", [("free", True), ("free", False), ("directory", False), ("tail", False)])
def test_exfat_reintroduced_history_prevents_certificate(tmp_path, monkeypatch, location, known_content):
    from eraseproof import exfat
    image, secret, *_ = fixture(tmp_path)
    original = exfat.scrub
    def inject(*arguments, **kwargs):
        result = original(*arguments, **kwargs)
        with image.open("r+b", buffering=0) as stream:
            v = Volume(stream)
            if location == "free":
                cluster = next(c for c in range(2, v.count+2) if not v.allocated(c))
                offset = v.offset(cluster)
            elif location == "directory":
                offset = next(at for at, entry in v.directory(v.root_chain) if entry[0] == 1)+1
            else:
                entry = next(entry for entry in v.files.values() if entry["kind"] == "r")
                offset = v.offset(entry["chain"][-1])+entry["size"] % v.cluster_size
            v.write(offset, secret if known_content else os.urandom(17))
            os.fsync(stream.fileno())
        return result
    monkeypatch.setattr(exfat, "scrub", inject)
    with pytest.raises(EraseProofError, match="residue remains"):
        erase_path(image, "/private-case", "volume.img:/private-case", tmp_path/"case")
    store = EvidenceStore(tmp_path/"case")
    assert store.records() == []
    result = store.events()[-1]["payload"]["detail"]["verification"]
    counter = {"free": "nonzero_free_bytes", "directory": "nonzero_inactive_directory_bytes", "tail": "nonzero_stream_slack_bytes"}[location]
    assert result["history_verification"][counter] > 0
    assert result["rrs"] > 0 if known_content else result["rrs"] == 0

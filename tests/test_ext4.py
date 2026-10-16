import hashlib
import os
from pathlib import Path
import subprocess

import pytest

from eraseproof.ext4 import erase_path, helper, inventory, plan_path
from eraseproof.models import EraseProofError
from eraseproof.evidence import EvidenceStore


def tool(*args):
    result = subprocess.run(list(map(str, args)), capture_output=True, check=True)
    return result.stdout


def fixture(tmp_path, block_size=4096):
    image = tmp_path/"volume.img"
    with image.open("xb") as stream:
        stream.truncate(32*1024*1024)
    tool("mkfs.ext4", "-q", "-F", "-b", block_size, image)
    secret = tmp_path/"source.bin"
    secret.write_bytes(b"ERASEPROOF-PRIVATE-EXT4-CONTENT"*700)
    keep = tmp_path/"keep.bin"
    keep.write_bytes(os.urandom(40000))
    tool("debugfs", "-w", "-R", "mkdir /private-case", image)
    tool("debugfs", "-w", "-R", f"write {secret} /private-case/confidential.bin", image)
    tool("debugfs", "-w", "-R", f"write {keep} /keep.bin", image)
    # Normal deletion leaves another copy in unallocated blocks/inode records.
    tool("debugfs", "-w", "-R", f"write {secret} /old-secret.bin", image)
    tool("debugfs", "-w", "-R", "rm /old-secret.bin", image)
    return image, secret, keep


@pytest.mark.parametrize("block_size", [1024, 4096])
def test_ext4_cleanup_preserves_live_file_and_passes_fsck(tmp_path, block_size):
    image, secret, keep = fixture(tmp_path, block_size)
    assert secret.read_bytes() in image.read_bytes()
    prepared = plan_path(image, "/private-case")
    assert len(prepared["selected"]) == 2
    record = erase_path(image, "/private-case", prepared["confirmation"], tmp_path/"case")
    result = record["payload"]["verification"]
    assert result["passed"] and result["rrs"] == 0
    assert result["cleanup"]["free_blocks_cleared"] > 1000
    assert result["cleanup"]["journal_blocks_cleared"] > 100
    assert secret.read_bytes() not in image.read_bytes()
    assert b"confidential.bin" not in image.read_bytes()
    assert b"old-secret.bin" not in image.read_bytes()
    tool("e2fsck", "-f", "-n", image)
    dumped = tmp_path/"dumped.bin"
    tool("debugfs", "-R", f"dump /keep.bin {dumped}", image)
    assert hashlib.sha256(dumped.read_bytes()).digest() == hashlib.sha256(keep.read_bytes()).digest()


def test_ext4_preconditions_do_not_write(tmp_path):
    image, _, _ = fixture(tmp_path)
    before = hashlib.sha256(image.read_bytes()).digest()
    with pytest.raises(EraseProofError):
        erase_path(image, "/private-case", "wrong", tmp_path/"case")
    with pytest.raises(EraseProofError):
        plan_path(image, "/")
    with pytest.raises(EraseProofError):
        plan_path(image, "/private-case/../keep.bin")
    assert hashlib.sha256(image.read_bytes()).digest() == before


def test_ext4_rejects_remaining_allocated_copy_without_certificate(tmp_path):
    image, secret, _ = fixture(tmp_path)
    tool("debugfs", "-w", "-R", f"write {secret} /live-copy.bin", image)
    with pytest.raises(EraseProofError, match="residue remains"):
        erase_path(image, "/private-case", "volume.img:/private-case", tmp_path/"case")
    assert EvidenceStore(tmp_path/"case").records() == []
    verification = EvidenceStore(tmp_path/"case").events()[-1]["payload"]["detail"]["verification"]
    assert verification["rrs"] > 0


def test_ext4_indexed_directory_cleanup_preserves_index(tmp_path):
    image, _, _ = fixture(tmp_path)
    commands = tmp_path/"commands"
    source = tmp_path/"tiny"
    source.write_bytes(b"unrelated")
    commands.write_text("\n".join(f"write {source} /entry-{i:04d}" for i in range(180))+"\n")
    tool("debugfs", "-w", "-f", commands, image)
    # Ask e2fsprogs to construct actual directory indexes, then keep them intact.
    result = subprocess.run(["e2fsck", "-f", "-y", "-D", str(image)], capture_output=True)
    assert result.returncode in (0, 1)
    record = erase_path(image, "/private-case", "volume.img:/private-case", tmp_path/"case")
    assert record["payload"]["verification"]["preserved_files_hash_checked"] == 181
    tool("e2fsck", "-f", "-n", image)


@pytest.mark.parametrize("location", ["journal", "free-space"])
def test_ext4_verifier_detects_reintroduced_history(tmp_path, monkeypatch, location):
    from eraseproof import ext4
    image, secret, _ = fixture(tmp_path)
    blocks = [int(n) for n in tool("debugfs", "-R", "blocks <8>", image).split()]
    # Inactive journal payload is not part of the clean journal superblock.
    block_size = plan_path(image, "/private-case")["geometry"]["block_size"]
    offset = blocks[2]*block_size if location == "journal" else image.stat().st_size-4096
    original = ext4.run
    def inject(arguments, **kwargs):
        output = original(arguments, **kwargs)
        if len(arguments) > 1 and arguments[0] == helper() and arguments[1] == "scrub":
            with image.open("r+b", buffering=0) as stream:
                stream.seek(offset)
                stream.write(secret.read_bytes()[:512])
                os.fsync(stream.fileno())
        return output
    monkeypatch.setattr(ext4, "run", inject)
    with pytest.raises(EraseProofError, match="residue remains"):
        erase_path(image, "/private-case", "volume.img:/private-case", tmp_path/"case")
    assert EvidenceStore(tmp_path/"case").records() == []

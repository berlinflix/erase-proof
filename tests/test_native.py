import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
from types import SimpleNamespace

import pytest

from eraseproof import carve, demo, tsk
from eraseproof.cli import recover
from eraseproof.engine import erase, plan, verify
from eraseproof.evidence import EvidenceStore, verify_record
from eraseproof.models import Cancelled, EraseProofError
from eraseproof.targets import virtual_disk_policy


@pytest.fixture
def fat_case(tmp_path):
    return demo.create(tmp_path/"fat-case")


def test_attached_image_refused_before_any_overwrite(tmp_path, monkeypatch):
    import eraseproof.targets as targets
    image = tmp_path/'attached.img'
    original = os.urandom(8192)
    image.write_bytes(original)
    calls = []
    def attached(arguments, **kwargs):
        calls.append(arguments)
        return SimpleNamespace(returncode=0, stdout=b'/dev/loop-SYNTHETIC: attached', stderr=b'')
    monkeypatch.setattr(targets.subprocess, 'run', attached)
    with pytest.raises(EraseProofError, match='Detach'):
        erase(image, image.name, tmp_path/'case')
    assert calls[0] == ['losetup', '--associated', str(image)]
    assert image.read_bytes() == original and not (tmp_path/'case').exists()


def test_real_owned_loop_image_is_refused(tmp_path):
    if os.geteuid() != 0 or os.environ.get('ERASEPROOF_TEST_PRIVATE_MOUNTS') != '1':
        pytest.skip('Requires root in a private mount namespace; uses a newly generated loop image only')
    image = tmp_path/'own-loop.img'
    with image.open('xb') as stream:
        stream.truncate(8*1024*1024)
    before = hashlib.sha256(image.read_bytes()).hexdigest()
    loop = subprocess.run(['losetup', '--find', '--show', str(image)], check=True, capture_output=True, text=True).stdout.strip()
    association = json.loads(subprocess.run(['losetup', '--list', '--json', '--output', 'NAME,BACK-FILE', loop],
                                             check=True, capture_output=True, text=True).stdout)['loopdevices'][0]
    assert Path(association['back-file']).resolve() == image.resolve()
    try:
        with pytest.raises(EraseProofError, match='Detach'):
            erase(image, image.name, tmp_path/'case')
        assert hashlib.sha256(image.read_bytes()).hexdigest() == before
        assert not (tmp_path/'case').exists()
    finally:
        subprocess.run(['losetup', '--detach', loop], check=True)
    assert plan(image)['target']['size'] == image.stat().st_size


def test_real_fat32_deletion_and_independent_recovery(fat_case, tmp_path):
    image = Path(fat_case["image"])
    assert tsk.deleted(image) == []
    demo.delete(image.parent)
    found = tsk.deleted(image)
    assert len(found) == 4
    expected = {item["sha256"] for item in fat_case["files"]}
    hashes = {tsk.recover(image, item, tmp_path/"recovered").sha256 for item in found}
    assert hashes == expected
    assert verify(image, fat_case["references"])["rrs"] > 0


def test_carved_files_are_real_and_match_originals(fat_case, tmp_path):
    image = Path(fat_case["image"])
    demo.delete(image.parent)
    candidates = carve.scan(image)
    assert {candidate.file_type for candidate in candidates} == {"PNG", "PDF", "ZIP"}
    results = [carve.extract(image, item, tmp_path/"carved") for item in candidates]
    expected = {item["sha256"] for item in fat_case["files"]}
    assert all(candidate.sha256 in expected for candidate in results)
    assert next(c for c in results if c.file_type == "ZIP").confidence == 98


def test_real_overwrite_then_recovery_attack_and_ed25519_record(fat_case, tmp_path):
    image = Path(fat_case["image"])
    demo.delete(image.parent)
    record = erase(image, image.name, tmp_path/"evidence", fat_case["references"])
    assert record["payload"]["verification"]["passed"] is True
    assert record["payload"]["verification"]["rrs"] == 0
    assert record["payload"]["verification"]["bytes_checked"] == image.stat().st_size
    assert verify_record(record)
    assert carve.scan(image) == []
    assert image.read_bytes() == bytes(image.stat().st_size)
    store = EvidenceStore(tmp_path/"evidence")
    assert store.check() and len(store.records()) == 1
    assert [e["payload"]["event"] for e in store.events()] == ["erasure.started", "erasure.verified"]


def test_one_remaining_byte_blocks_verification(tmp_path):
    path = tmp_path/"one-byte.img"
    path.write_bytes(bytes(8191)+b"x")
    result = verify(path)
    assert result["nonzero_bytes"] == 1
    assert not result["passed"] and result["rrs"] is None


def test_invalid_reference_manifest_is_rejected_before_any_write(tmp_path):
    path = tmp_path/"keep.img"
    path.write_bytes(b"preserve original content")
    with pytest.raises(EraseProofError, match="block size"):
        erase(path, path.name, tmp_path/"case", {"block_size": 3})
    assert path.read_bytes() == b"preserve original content"


def test_single_byte_metadata_pattern_is_detected_across_multiple_chunks(tmp_path):
    path = tmp_path/"pattern.img"
    path.write_bytes(bytes(carve.CHUNK)+b"Z"+bytes(20))
    result = verify(path, {"metadata_patterns": ["5a"], "block_size": 512})
    assert result["metadata_residues"] == 1
    assert result["rrs"] == 1


def test_wrong_confirmation_symlinks_and_hardlinks_are_refused(tmp_path):
    path = tmp_path/"sample.img"
    path.write_bytes(b"retain this"*100)
    before = path.read_bytes()
    with pytest.raises(EraseProofError, match="exact"):
        erase(path, "wrong.img", tmp_path/"case")
    assert path.read_bytes() == before
    link = tmp_path/"symbolic.img"
    link.symlink_to(path)
    with pytest.raises(EraseProofError, match="Symlink"):
        plan(link)
    hard = tmp_path/"hard.img"
    hard.hardlink_to(path)
    with pytest.raises(EraseProofError, match="Hard-linked"):
        erase(path, path.name, tmp_path/"case")
    assert path.read_bytes() == before


def test_cancellation_leaves_no_certificate(tmp_path):
    path = tmp_path/"cancel.img"
    path.write_bytes(b"x"*(8*1024*1024))
    state = {"cancel": False}
    def progress(stage, fraction, message):
        if stage == "Erase":
            state["cancel"] = True
    with pytest.raises(Cancelled):
        erase(path, path.name, tmp_path/"case", progress=progress, cancel=lambda: state["cancel"])
    store = EvidenceStore(tmp_path/"case")
    assert not store.records()
    assert store.events()[-1]["payload"]["event"] == "erasure.incomplete"


def test_signed_record_and_audit_tampering_are_detected(tmp_path):
    image = tmp_path/"source.img"
    image.write_bytes(b"research"*100)
    store = EvidenceStore(tmp_path/"case")
    record = erase(image, image.name, tmp_path/"case")
    changed = copy.deepcopy(record)
    changed["payload"]["target"]["size"] += 1
    assert not verify_record(changed)
    with sqlite3.connect(store.db) as connection:
        connection.execute("UPDATE events SET hash=? WHERE sequence=1", ("a"*64,))
    assert not store.check()
    with pytest.raises(EraseProofError, match="damaged"):
        erase(image, image.name, tmp_path/"case")


def test_virtual_disk_guards_block_mounted_root_physical_disks_and_wrong_serial():
    disk = {"name": "/dev/sdb", "type": "disk", "size": 1024, "model": "VBOX HARDDISK", "serial": "DEMO-01", "ro": False, "mountpoints": [None]}
    assert virtual_disk_policy("/dev/sdb", "DEMO-01", "/dev/sdb", [disk])["kind"] == "virtual-block-device"
    with pytest.raises(EraseProofError, match="serial"):
        virtual_disk_policy("/dev/sdb", "WRONG", "/dev/sdb", [disk])
    mounted = {**disk, "children": [{"name": "/dev/sdb1", "type": "part", "mountpoints": ["/"]}]}
    with pytest.raises(EraseProofError, match="mounted"):
        virtual_disk_policy("/dev/sdb", "DEMO-01", "/dev/sdb", [mounted])
    physical = {**disk, "model": "Samsung SSD"}
    with pytest.raises(EraseProofError, match="Physical-media"):
        virtual_disk_policy("/dev/sdb", "DEMO-01", "/dev/sdb", [physical])


def test_signatures_cross_scan_chunk_boundaries_and_malformed_candidates(tmp_path):
    image = tmp_path/"boundary.img"
    payload = demo.png()
    image.write_bytes(bytes(carve.CHUNK-4)+payload+bytes(100))
    found = carve.scan(image)
    assert len(found) == 1 and found[0].offset == carve.CHUNK-4
    truncated = tmp_path/"truncated.img"
    truncated.write_bytes(payload[:-10])
    assert carve.scan(truncated) == []


def test_recovery_does_not_modify_source_or_overwrite_existing_outputs(fat_case, tmp_path):
    image = Path(fat_case["image"])
    demo.delete(image.parent)
    before = hashlib.sha256(image.read_bytes()).hexdigest()
    report = recover(image, tmp_path/"output")
    assert len(report["candidates"]) == 7
    assert hashlib.sha256(image.read_bytes()).hexdigest() == before
    with pytest.raises(FileExistsError):
        recover(image, tmp_path/"output")

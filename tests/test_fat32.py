import hashlib
import os
from pathlib import Path
import subprocess
import pytest
from eraseproof import demo, carve
from eraseproof.fat32 import Fat32, erase_path
from eraseproof.models import EraseProofError
from eraseproof.evidence import EvidenceStore, verify_record


def run(*args):
    result = subprocess.run(list(map(str, args)), capture_output=True, check=True)
    return result.stdout


def fixture(tmp_path):
    manifest = demo.create(tmp_path/"experiment")
    image = Path(manifest["image"])
    source = tmp_path/"private.bin"
    source.write_bytes(os.urandom(17537))
    run("mmd", "-i", image, "::/private-case")
    run("mcopy", "-i", image, source, "::/private-case/confidential.bin")
    return image, source, manifest


def test_targeted_file_erasure_preserves_filesystem_and_other_files(tmp_path):
    manifest = demo.create(tmp_path/"experiment")
    image = Path(manifest["image"])
    report = erase_path(image, "/REPORT.PDF", "experiment.img:/REPORT.PDF", tmp_path/"case")
    assert report["payload"]["verification"]["passed"]
    assert verify_record(report)
    assert run("fsck.fat", "-n", image)
    for name in ("CAPTURE.PNG", "ARCHIVE.ZIP", "NOTES.TXT"):
        output = tmp_path/name
        run("mcopy", "-i", image, "::/"+name, output)
        assert hashlib.sha256(output.read_bytes()).hexdigest() == next(f["sha256"] for f in manifest["files"] if f["name"] == name)
    assert "PDF" not in {c.file_type for c in carve.scan(image)}


def test_targeted_folder_long_names_and_known_unallocated_copy_sweep(tmp_path):
    manifest = demo.create(tmp_path/"experiment")
    image = Path(manifest["image"])
    run("mmd", "-i", image, "::/Private Folder")
    source = tmp_path/"private.bin"
    source.write_bytes(b"FRESH-PRIVATE-"+os.urandom(7777))
    run("mcopy", "-i", image, source, "::/Private Folder/Private report.bin")
    # Deleted older copy has identical content but no live allocation.
    run("mcopy", "-i", image, source, "::/OLD.BIN")
    run("mdel", "-i", image, "::/OLD.BIN")
    report = erase_path(image, "/Private Folder", "experiment.img:/Private Folder", tmp_path/"case")
    assert report["payload"]["verification"]["rrs"] == 0
    assert report["payload"]["verification"]["cleanup"]["free_clusters_cleared"] > 0
    assert report["payload"]["verification"]["history_verification"]["nonzero_free_bytes"] == 0
    assert source.read_bytes() not in image.read_bytes()
    run("mcopy", "-i", image, "::/REPORT.PDF", tmp_path/"preserved.pdf")
    assert (tmp_path/"preserved.pdf").read_bytes() == demo.pdf()
    run("fsck.fat", "-n", image)


def test_corrupt_fat_and_wrong_confirmation_are_not_written(tmp_path):
    manifest = demo.create(tmp_path/"experiment")
    image = Path(manifest["image"])
    before = hashlib.sha256(image.read_bytes()).hexdigest()
    with pytest.raises(EraseProofError, match="Confirmation"):
        erase_path(image, "/REPORT.PDF", "wrong", tmp_path/"case")
    assert hashlib.sha256(image.read_bytes()).hexdigest() == before
    with image.open("r+b") as stream:
        volume = Fat32(stream, image.stat().st_size)
        stream.seek((volume.reserved+volume.fat_sectors)*volume.bps+100)
        stream.write(b"bad!")
    corrupted = hashlib.sha256(image.read_bytes()).hexdigest()
    with pytest.raises(EraseProofError, match="FAT copies"):
        erase_path(image, "/REPORT.PDF", "experiment.img:/REPORT.PDF", tmp_path/"case")
    assert hashlib.sha256(image.read_bytes()).hexdigest() == corrupted


def test_retained_identical_live_copy_prevents_fat_certificate(tmp_path):
    manifest = demo.create(tmp_path/"experiment")
    image = Path(manifest["image"])
    run("mmd", "-i", image, "::/Private Folder")
    source = tmp_path/"private.pdf"
    source.write_bytes(demo.pdf())
    run("mcopy", "-i", image, source, "::/Private Folder/Private report.pdf")
    with pytest.raises(EraseProofError, match="residue remains"):
        erase_path(image, "/Private Folder", "experiment.img:/Private Folder", tmp_path/"case")
    store = EvidenceStore(tmp_path/"case")
    assert not store.records()
    assert store.events()[-1]["payload"]["detail"]["verification"]["matching_live_file_hashes"]
    run("mcopy", "-i", image, "::/REPORT.PDF", tmp_path/"preserved.pdf")
    assert (tmp_path/"preserved.pdf").read_bytes() == demo.pdf()


def test_fat_surrogate_pair_across_long_name_entries(tmp_path):
    from test_exfat import fixture as driver_fixture
    from eraseproof.fat import list_paths
    filename = "abcdefghijkl😀.bin"  # UTF-16 surrogate pair crosses slot boundary.
    image, *_ = driver_fixture(tmp_path, "fat32", filename)
    assert "/private-case/"+filename in {entry["path"] for entry in list_paths(image)}
    record = erase_path(image, "/private-case", "volume.img:/private-case", tmp_path/"case")
    assert record["payload"]["verification"]["passed"]
    assert record["payload"]["verification"]["cleanup"]["io"]["direct_bytes"] > 0
    run("fsck.fat", "-n", image)


@pytest.mark.parametrize("location", ["free", "directory", "tail"])
def test_unknown_fat_history_residue_prevents_certificate(tmp_path, monkeypatch, location):
    from eraseproof import fat
    manifest = demo.create(tmp_path/"experiment")
    image = Path(manifest["image"])
    original = fat.scrub
    def inject(*arguments, **kwargs):
        result = original(*arguments, **kwargs)
        with image.open("r+b", buffering=0) as stream:
            v = fat.volume(stream, fresh=True)
            if location == "free":
                cluster = next(c for c in range(2, v.clusters+2) if v.value(c) == 0)
                offset = v.offset(cluster)
            elif location == "directory":
                chain = v.chain(v.root)
                offsets = [v.offset(c)+at for c in chain for at in range(0, v.cluster_size, 32) if v.read_cluster(c)[at] == 0xe5]
                offset = offsets[0]+28
            else:
                entry = v.files["/NOTES.TXT"]
                offset = v.offset(v.chain(entry["cluster"])[-1])+entry["size"] % v.cluster_size
            fat.write(stream, offset, b"\x77")
            os.fsync(stream.fileno())
        return result
    monkeypatch.setattr(fat, "scrub", inject)
    with pytest.raises(EraseProofError, match="residue remains"):
        erase_path(image, "/REPORT.PDF", "experiment.img:/REPORT.PDF", tmp_path/"case")
    store = EvidenceStore(tmp_path/"case")
    assert not store.records()
    result = store.events()[-1]["payload"]["detail"]["verification"]
    counter = {"free": "nonzero_free_bytes", "directory": "nonzero_deleted_directory_bytes", "tail": "nonzero_file_slack_bytes"}[location]
    assert result["history_verification"][counter] > 0

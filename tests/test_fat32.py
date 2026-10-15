import hashlib
from pathlib import Path
import subprocess
import pytest
from eraseproof import demo, carve
from eraseproof.fat32 import Fat32, erase_path
from eraseproof.models import EraseProofError
from eraseproof.evidence import verify_record


def run(*args):
    result = subprocess.run(list(map(str, args)), capture_output=True, check=True)
    return result.stdout


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
    source = tmp_path/"private.pdf"
    source.write_bytes(demo.pdf())
    run("mcopy", "-i", image, source, "::/Private Folder/Private report.pdf")
    # Deleted older copy has identical content but no live allocation.
    run("mcopy", "-i", image, source, "::/OLD.PDF")
    run("mdel", "-i", image, "::/OLD.PDF")
    report = erase_path(image, "/Private Folder", "experiment.img:/Private Folder", tmp_path/"case")
    assert report["payload"]["verification"]["rrs"] == 0
    assert report["payload"]["plan"]["historical_sector_copies"] > 0
    # The unrelated live REPORT.PDF is intentionally preserved, even though it
    # shares bytes with the selected file. The sweep only edits free clusters.
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

from pathlib import Path
import pytest
from eraseproof.files import plan_files, erase_files
from eraseproof.evidence import EvidenceStore, verify_record
from eraseproof.models import EraseProofError, Cancelled


def test_real_file_tree_overwrite_and_unlink(tmp_path):
    selected = tmp_path/"selected"
    (selected/"nested").mkdir(parents=True)
    (selected/"one.txt").write_bytes(b"first"*1000)
    (selected/"nested"/"two.pdf").write_bytes(b"second"*1000)
    outside = tmp_path/"keep.txt"
    outside.write_text("preserve")
    record = erase_files(selected, "selected", tmp_path/"evidence")
    assert not selected.exists()
    assert outside.read_text() == "preserve"
    assert record["payload"]["verification"]["bytes_checked"] == 11000
    assert not record["payload"]["verification"]["all_filesystem_copies_verified"]
    assert verify_record(record)


def test_keep_zeroed_file_and_wrong_confirmation(tmp_path):
    path = tmp_path/"file.txt"
    path.write_bytes(b"sensitive")
    with pytest.raises(EraseProofError, match="Confirmation"):
        erase_files(path, "wrong", tmp_path/"case")
    assert path.read_bytes() == b"sensitive"
    erase_files(path, path.name, tmp_path/"case", unlink=False)
    assert path.read_bytes() == bytes(9)


def test_symlinks_hardlinks_and_evidence_inside_tree_block_before_writes(tmp_path):
    root = tmp_path/"selected"
    root.mkdir()
    path = root/"data.txt"
    path.write_text("keep")
    with pytest.raises(EraseProofError, match="outside"):
        erase_files(root, root.name, root/"evidence")
    link = root/"link"
    link.symlink_to(path)
    with pytest.raises(EraseProofError, match="symlink"):
        plan_files(root)
    link.unlink()
    link.hardlink_to(path)
    with pytest.raises(EraseProofError, match="Hard-linked"):
        plan_files(root)
    assert path.read_text() == "keep"


def test_cancellation_does_not_produce_completion_record(tmp_path):
    path = tmp_path/"cancel.txt"
    path.write_bytes(b"x"*(8*1024*1024))
    state = {"cancel": False}
    def progress(*args):
        state["cancel"] = True
    with pytest.raises(Cancelled):
        erase_files(path, path.name, tmp_path/"case", progress=progress, cancel=lambda: state["cancel"])
    assert EvidenceStore(tmp_path/"case").records() == []
    assert path.exists()

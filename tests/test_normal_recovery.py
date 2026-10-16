import hashlib
import io
import os
from pathlib import Path

from PIL import Image
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas

from eraseproof import carve
from eraseproof.cli import recover
from eraseproof.models import Candidate, EraseProofError


def test_fresh_pdf_preserves_eof_newline_and_incremental_update(tmp_path):
    original = tmp_path/"fresh.pdf"
    document = canvas.Canvas(str(original))
    document.drawString(60, 700, os.urandom(24).hex())
    document.save()
    writer = PdfWriter(original, incremental=True)
    writer.add_metadata({"/Title": "Fresh update "+os.urandom(12).hex()})
    revised = tmp_path/"revised.pdf"
    writer.write(revised)
    assert revised.read_bytes().count(b"%%EOF") == 2
    image = tmp_path/"unrelated.img"
    image.write_bytes(bytes(512)+original.read_bytes()+bytes(4096)+revised.read_bytes()+bytes(1024))
    report = recover(image, tmp_path/"out", "carve")
    hashes = {entry["sha256"] for entry in report["candidates"]}
    assert hashlib.sha256(original.read_bytes()).hexdigest() in hashes
    assert hashlib.sha256(revised.read_bytes()).hexdigest() in hashes


def test_one_failed_metadata_entry_does_not_stop_other_recovery(tmp_path, monkeypatch):
    from eraseproof import cli
    source = tmp_path/"disk.img"
    source.write_bytes(bytes(4096))
    first = Candidate(0, 0, "FILE", 0, [], name="unreadable.bin", inode="1")
    second = Candidate(0, 27, "FILE", 0, [], name="survivor.custom", inode="2")
    monkeypatch.setattr(cli.tsk, "deleted", lambda *args: [first, second])
    def extract(path, candidate, destination, offset):
        if candidate.inode == "1":
            raise EraseProofError("allocation metadata destroyed")
        candidate.method = "sleuthkit-metadata"
        return candidate
    monkeypatch.setattr(cli.tsk, "recover", extract)
    report = recover(source, tmp_path/"out", "deleted")
    assert report["nonempty_outputs"] == 1
    assert report["candidates"][0]["name"] == "survivor.custom"
    assert "allocation metadata destroyed" in report["warnings"][0]

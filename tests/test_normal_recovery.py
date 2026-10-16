import hashlib
import io
import os
import struct
import zipfile
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
        destination.mkdir(parents=True, exist_ok=True)
        output = destination/'survivor.custom'
        output.write_bytes(os.urandom(candidate.length))
        candidate.output = str(output)
        return candidate
    monkeypatch.setattr(cli.tsk, "recover", extract)
    report = recover(source, tmp_path/"out", "deleted")
    assert report["nonempty_outputs"] == 1
    assert report["candidates"][0]["name"] == "survivor.custom"
    assert "allocation metadata destroyed" in report["warnings"][0]
    assert report['candidates'][0]['confidence_details']['entropy_bits_per_byte'] > 0


def test_jpeg_thumbnail_footer_does_not_truncate_main_photo(tmp_path):
    main, thumb = io.BytesIO(), io.BytesIO()
    Image.frombytes("RGB", (71, 53), os.urandom(71*53*3)).save(main, "JPEG", progressive=True)
    Image.new("RGB", (8, 8), (31, 66, 90)).save(thumb, "JPEG")
    payload = b"Application thumbnail\x00"+thumb.getvalue()
    data = main.getvalue()[:2]+b"\xff\xe2"+struct.pack(">H", len(payload)+2)+payload+main.getvalue()[2:]
    image = tmp_path/"source.img"
    image.write_bytes(bytes(512)+data+bytes(2048))
    report = recover(image, tmp_path/"out", "carve")
    assert report["candidates"][0]["sha256"] == hashlib.sha256(data).hexdigest()
    assert report["candidates"][0]["length"] == len(data)


def test_zip_member_footer_literal_does_not_truncate_archive(tmp_path):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("user-data.bin", os.urandom(512)+b"PK\x05\x06"+bytes(18)+os.urandom(300))
        archive.comment = b"Actual user archive comment"
    data = out.getvalue()
    image = tmp_path/"source.img"
    image.write_bytes(bytes(512)+data+bytes(2048))
    report = recover(image, tmp_path/"out", "carve")
    assert report["candidates"][0]["sha256"] == hashlib.sha256(data).hexdigest()


def test_zip64_end_record_is_used_for_archive_boundary(tmp_path):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("fresh.bin", os.urandom(7123))
    original = out.getvalue()
    at = original.rfind(b"PK\x05\x06")
    _, _, _, _, count, size, start, _ = struct.unpack("<4s4H2IH", original[at:at+22])
    record = struct.pack("<4sQ2H2I4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, size, start)
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, at, 1)
    footer = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 65535, 65535, 0xffffffff, 0xffffffff, 0)
    data = original[:at]+record+locator+footer
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert archive.testzip() is None
    image = tmp_path/"source.img"
    image.write_bytes(bytes(512)+data+bytes(2048))
    report = recover(image, tmp_path/"out", "carve")
    assert report["candidates"][0]["sha256"] == hashlib.sha256(data).hexdigest()

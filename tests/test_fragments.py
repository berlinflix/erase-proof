import hashlib
import io
import os
import zipfile

from PIL import Image
import pytest

from eraseproof.fragments import Budget, reconstruct, zip_valid
from eraseproof.models import Cancelled, EraseProofError
from eraseproof import carve


@pytest.mark.parametrize("kind", ["PNG", "ZIP"])
@pytest.mark.parametrize("gap", [512, 1536])
def test_bifragment_inside_payload_recovers_fresh_original_exactly(kind, gap):
    buffer = io.BytesIO()
    if kind == "PNG":
        Image.frombytes("RGB", (117, 83), os.urandom(117*83*3)).save(buffer, "PNG")
    else:
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("fresh-"+os.urandom(8).hex()+".custom", os.urandom(23371))
            archive.writestr("second.txt", os.urandom(317))
    payload = buffer.getvalue()
    offset, split = 512, 2560
    data = bytes(offset)+payload[:split]+os.urandom(gap)+payload[split:]+bytes(512)
    source = io.BytesIO(data)
    result = reconstruct(source, offset, kind, len(data), Budget())
    assert result is not None and result.confidence == 98
    recovered = b"".join(data[at:at+length] for at, length in result.segments)
    assert hashlib.sha256(recovered).hexdigest() == hashlib.sha256(payload).hexdigest()


def test_fragment_search_cancellation_limits_and_zip_bomb_refusal():
    data = b"\x89PNG\r\n\x1a\n"+os.urandom(4096)
    with pytest.raises(EraseProofError, match="incomplete"):
        reconstruct(io.BytesIO(data), 0, "PNG", len(data), Budget(attempts=0))
    with pytest.raises(Cancelled):
        reconstruct(io.BytesIO(data), 0, "PNG", len(data), Budget(), cancel=lambda: True)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large", bytes(33*1024*1024))
    assert not zip_valid(buffer.getvalue())


def test_cli_carving_path_and_entropy_evidence(tmp_path):
    buffer = io.BytesIO()
    Image.frombytes("RGB", (113, 81), os.urandom(113*81*3)).save(buffer, "PNG")
    payload = buffer.getvalue()
    source = tmp_path/"fresh.img"
    source.write_bytes(bytes(512)+payload[:1536]+os.urandom(512)+payload[1536:]+bytes(512))
    found = carve.scan(source, fragmented=True)
    assert len(found) == 1 and found[0].method == "bifragment-gap-reconstruction"
    result = carve.extract(source, found[0], tmp_path/"out")
    assert result.sha256 == hashlib.sha256(payload).hexdigest()
    assert result.confidence_details["structural_completeness"]
    assert result.confidence_details["entropy_bits_per_byte"] > 7


def test_png_with_no_image_data_is_not_a_complete_carving():
    from eraseproof import demo
    payload = demo.png()
    invalid = payload[:33]+payload[-12:]
    assert carve.identify(io.BytesIO(invalid), 0, "PNG", len(invalid)) is None


@pytest.mark.parametrize("kind", ["JPEG", "PDF"])
def test_checksum_free_fragment_recovery_is_explicitly_uncertain(kind):
    buffer = io.BytesIO()
    if kind == "JPEG":
        Image.frombytes("RGB", (220, 170), os.urandom(220*170*3)).save(buffer, "JPEG", quality=94)
        split = 512  # Inside the Huffman table, not an authenticated pixel boundary.
    else:
        from reportlab.pdfgen.canvas import Canvas
        canvas = Canvas(buffer, pageCompression=0)
        for index in range(200):
            canvas.drawString(10, index % 700, os.urandom(40).hex())
        canvas.save()
        split = 1024
    payload = buffer.getvalue()
    data = bytes(512)+payload[:split]+os.urandom(512)+payload[split:]+bytes(512)
    result = reconstruct(io.BytesIO(data), 512, kind, len(data), Budget())
    assert result and result.confidence <= 60
    assert any("no checksum" in evidence for evidence in result.evidence)
    recovered = b"".join(data[at:at+length] for at, length in result.segments)
    assert recovered == payload

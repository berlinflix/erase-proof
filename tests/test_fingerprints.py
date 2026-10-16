import hashlib
import io
import os
import subprocess

import pytest
from PIL import Image

from eraseproof import attackgate, fingerprints
from eraseproof.engine import validate_references, verify
from eraseproof.models import EraseProofError
from eraseproof.offline import fingerprint_data


def test_streaming_ssdeep_agrees_with_independent_cli_and_finds_edited_version(tmp_path):
    original = os.urandom(128*1024+73)
    file = tmp_path/"fresh.unknown"
    file.write_bytes(original)
    measured = fingerprints.measure([original[:711], original[711:64000], original[64000:]])
    expected = subprocess.run(["ssdeep", "-b", str(file)], check=True, capture_output=True, text=True).stdout.splitlines()[1].split(",", 1)[0]
    assert measured["ssdeep"] == expected
    assert measured["sha256"] == hashlib.sha256(original).hexdigest()
    assert set(measured["block_hashes_4096"]) == {hashlib.sha256(original[i:i+4096]).hexdigest() for i in range(0, len(original), 4096)}
    edited = original[:60000]+os.urandom(1200)+original[61200:]
    assert fingerprints.compare(measured["ssdeep"], fingerprints.measure([edited])["ssdeep"]) >= 70
    assert fingerprints.compare(measured["ssdeep"], fingerprints.measure([os.urandom(len(original))])["ssdeep"]) == 0
    evidence = attackgate.scan_file(file, validate_references({"fuzzy_hashes": [fingerprints.measure([edited])["ssdeep"]]}))
    assert evidence["fuzzy_matches"] and not evidence["full_file_match"]


@pytest.mark.parametrize("signature", ["x", "3:a:b\x00", "4:AAAAAAA:BBBBBBB", "0::", "3:"+"A"*65+":", "3:a,b:c", "9::"])
def test_reject_malformed_untrusted_fuzzy_references(signature):
    with pytest.raises(EraseProofError, match="ssdeep"):
        validate_references({"fuzzy_hashes": [signature]})


def test_fuzzy_reference_limits_and_thresholds():
    for value in (True, 0, 101, "70"):
        with pytest.raises(EraseProofError, match="threshold"):
            validate_references({"fuzzy_threshold": value})
    with pytest.raises(EraseProofError, match="1024"):
        validate_references({"fuzzy_hashes": ["3::"]*1025})


def test_offline_fingerprints_include_exact_four_kibibyte_and_fuzzy_data():
    payload = os.urandom(8193)
    result, blocks, samples = fingerprint_data({"path": "/fresh.custom", "inode": "9"}, [payload[:100], payload[100:]])
    assert len(result["block_hashes_4096"]) == 3
    assert len(blocks) == 16 and len(samples) == 2
    assert fingerprints.valid_signature(result["ssdeep"])
    assert result["entropy_bits_per_byte"] > 7


def test_native_attack_uses_fuzzy_similarity_without_identical_file_hash(tmp_path):
    image = Image.frombytes("RGB", (200, 150), os.urandom(200*150*3))
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    data = buffer.getvalue()
    source = tmp_path/"case.img"
    source.write_bytes(bytes(512)+data+bytes(512))
    edited = data[:10000]+os.urandom(400)+data[10400:]
    refs = {"fuzzy_hashes": [fingerprints.measure([edited])["ssdeep"]]}
    result = verify(source, refs)
    assert result["rrs"] == 1 and result["fuzzy_findings"]
    assert not result["passed"]

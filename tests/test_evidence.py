import copy
import json
from pathlib import Path
import sqlite3

import pytest

from eraseproof.certificate import attached_record, qr_payload, render
from eraseproof.engine import erase
from eraseproof.evidence import EvidenceStore, verify_record
from eraseproof.models import EraseProofError


def record_case(tmp_path):
    image = tmp_path/"disposable.img"
    image.write_bytes(b"Data for a real verification record"*512)
    root = tmp_path/"evidence"
    record = erase(image, image.name, root)
    return EvidenceStore(root), record


def test_expected_signer_detects_valid_record_from_another_operator(tmp_path):
    store, record = record_case(tmp_path)
    from eraseproof import __version__
    assert record["payload"]["software"] == {"name": "EraseProof", "version": __version__}
    assert verify_record(record, record["signer_fingerprint"])
    substitute = EvidenceStore(tmp_path/"other-operator").sign(record["payload"])
    assert verify_record(substitute)
    assert not verify_record(substitute, record["signer_fingerprint"])
    assert not verify_record(record, "short-fingerprint")
    assert not verify_record({"payload": None})


def test_external_signed_checkpoint_detects_tail_deletion(tmp_path):
    store, record = record_case(tmp_path)
    store.append("evaluation.completed", {"result": "independent checkpoint"})
    anchor = store.checkpoint()
    assert store.check_anchor(anchor, record["signer_fingerprint"])
    snapshot = store.export()
    assert snapshot["anchor"]["payload"]["head_sha256"] == snapshot["events"][-1]["hash"]
    assert snapshot["records"] == [record]
    store.append("later.event", {})
    assert store.check_anchor(anchor, record["signer_fingerprint"])
    with store.connect() as connection:
        connection.execute("DELETE FROM events WHERE sequence>=3")
    assert store.check()  # A locally consistent prefix is not proof of completeness.
    assert not store.check_anchor(anchor, record["signer_fingerprint"])


def test_record_database_tampering_and_malformed_event_are_detected(tmp_path):
    store, record = record_case(tmp_path)
    with store.connect() as connection:
        connection.execute("UPDATE certificates SET record='{}'")
    assert not store.check()
    with store.connect() as connection:
        connection.execute("UPDATE events SET payload='not-json' WHERE sequence=1")
    assert not store.check()


def test_signing_failure_occurs_before_first_destructive_write(tmp_path):
    image = tmp_path/"unchanged.img"
    image.write_bytes(b"Do not change this data")
    store = EvidenceStore(tmp_path/"case")
    (store.root/"operator-ed25519.key").write_bytes(b"broken")
    (store.root/"operator-ed25519.key").chmod(0o600)
    with pytest.raises(EraseProofError, match="signing key"):
        erase(image, image.name, store.root)
    assert image.read_bytes() == b"Do not change this data"
    assert store.records() == []


def test_jobs_without_completion_are_visible_but_successful_jobs_close(tmp_path):
    store, record = record_case(tmp_path)
    assert store.unresolved_jobs() == []
    store.append("erasure.started", {"job": "interrupted-fixture"})
    assert store.unresolved_jobs()[0]["detail"]["job"] == "interrupted-fixture"
    assert store.records() == [record]


def test_pdf_preserves_exact_signed_json_and_offline_qr_reference(tmp_path):
    from pypdf import PdfReader
    store, record = record_case(tmp_path)
    path = tmp_path/"report.pdf"
    result = render(record, path)
    assert result["pages"] == 2
    assert attached_record(path) == record
    assert verify_record(attached_record(path), record["signer_fingerprint"])
    text = "\n".join(page.extract_text() for page in PdfReader(path).pages)
    assert record["payload"]["id"] in text
    assert "not digitally signed" in text
    assert "Unavailable" in text  # No manufactured RRS=0 without references.
    assert "No NIST/IEEE compliance claim" in text
    reference = json.loads(qr_payload(record))
    assert reference["payload_sha256"] == record["payload_sha256"]
    with pytest.raises(FileExistsError):
        render(record, path)
    changed = copy.deepcopy(record)
    changed["payload"]["target"]["path"] = "tampered"
    with pytest.raises(EraseProofError):
        render(changed, tmp_path/"invalid.pdf")

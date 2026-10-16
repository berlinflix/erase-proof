import pytest

from eraseproof.evidence import EvidenceStore
from eraseproof.models import EraseProofError


def test_successful_current_byte_work_is_a_receipt_not_erasure_certificate(tmp_path):
    store = EvidenceStore(tmp_path/"evidence")
    record = store.certify({"schema": "eraseproof.native-evidence.v1", "id": "receipt",
                            "verification": {"passed": True, "rrs": None}})
    assert record["payload"]["document_type"] == "operation-receipt"
    assert not record["payload"]["certificate_issued"]


def test_certificate_needs_zero_score_and_completed_independent_attack(tmp_path):
    store = EvidenceStore(tmp_path/"evidence")
    with pytest.raises(EraseProofError, match="nonzero"):
        store.certify({"schema": "eraseproof.native-evidence.v1", "id": "bad",
                       "verification": {"passed": True, "rrs": .01}})
    record = store.certify({"schema": "eraseproof.native-evidence.v1", "id": "certificate",
                           "verification": {"passed": True, "rrs": 0, "independent_attack": {"passed": True}}})
    assert record["payload"]["certificate_issued"]

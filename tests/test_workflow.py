import copy
import os

import pytest

from eraseproof import workflow, media, attackgate
from eraseproof.evidence import EvidenceStore
from eraseproof.models import EraseProofError


def fixture(monkeypatch):
    controller = {'path': '/dev/nvme99', 'serial': 'TEST-NOT-HARDWARE', 'model': 'Fixture',
                  'scope': 'All fixture namespaces', 'identify': {'cmic': 0, 'sanicap': 3}, 'namespace_ids': [1],
                  'namespaces': [{'id': 1, 'device': {'name': '/dev/nvme99n1', 'type': 'disk', 'size': 8192}}],
                  'sanitize_log': {'sstat': 0}}
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    monkeypatch.setattr(media, 'nvme_probe', lambda _: copy.deepcopy(controller))
    monkeypatch.setattr(media, 'outside_devices', lambda *a: None)
    monkeypatch.setattr(attackgate, 'require_tools', lambda: None)
    return controller


def run(data, destination):
    return workflow.run(data['path'], ['crypto-erase', 'block-erase'], data['path'], data['serial'], destination,
                        {'block_size': 4096, 'block_hashes': ['a'*64]}, timeout=1)


def test_closed_loop_advances_only_on_completed_residue_and_certifies_zero(tmp_path, monkeypatch):
    data = fixture(monkeypatch)
    calls = []
    monkeypatch.setattr(media, 'submit_nvme', lambda _, method, *a, **kw: calls.append(method) or {'method': method})
    monkeypatch.setattr(media, 'nvme_status', lambda _: {'serial': data['serial'], 'state': 'firmware-reports-success', 'progress': 1, 'log': {'scdw10': 4 if len(calls) == 1 else 2}})
    def attack(path, refs, folder, *a):
        passed = len(calls) == 2
        return {'target': {'path': path}, 'verification': {'passed': passed, 'rrs': 0 if passed else .5,
                'bytes_checked': 8192, 'attacks_completed': True, 'observed_residue': not passed}}
    monkeypatch.setattr(workflow, 'attack_namespace', attack)
    record = run(data, tmp_path/'evidence')
    assert calls == ['crypto-erase', 'block-erase']
    assert record['payload']['certificate_issued'] and record['payload']['verification']['rrs'] == 0
    assert len(record['payload']['verification']['rounds']) == 2
    assert EvidenceStore(tmp_path/'evidence').check()


@pytest.mark.parametrize('failure', ['unknown-firmware', 'incomplete-attack', 'no-observed-residue'])
def test_uncertain_state_never_triggers_second_command_or_certificate(tmp_path, monkeypatch, failure):
    data = fixture(monkeypatch)
    calls = []
    monkeypatch.setattr(media, 'submit_nvme', lambda _, method, *a, **kw: calls.append(method) or {})
    monkeypatch.setattr(media, 'nvme_status', lambda _: {'serial': data['serial'], 'state': 'unknown' if failure == 'unknown-firmware' else 'firmware-reports-success', 'progress': 1, 'log': {'scdw10': 4}})
    monkeypatch.setattr(workflow, 'attack_namespace', lambda *a: {'verification': {'passed': False, 'bytes_checked': 8192,
        'attacks_completed': failure != 'incomplete-attack', 'observed_residue': failure != 'no-observed-residue'}})
    with pytest.raises(EraseProofError):
        run(data, tmp_path/'evidence')
    assert calls == ['crypto-erase'] and not EvidenceStore(tmp_path/'evidence').records()
    assert EvidenceStore(tmp_path/'evidence').events()[-1]['payload']['event'] == 'workflow.incomplete'


def test_missing_baseline_refused_before_firmware_or_evidence(tmp_path, monkeypatch):
    data = fixture(monkeypatch)
    with pytest.raises(EraseProofError, match='baseline'):
        workflow.run(data['path'], ['block-erase'], data['path'], data['serial'], tmp_path/'evidence', {})
    assert not (tmp_path/'evidence').exists()


def test_changed_namespace_after_attack_never_receives_certificate(tmp_path, monkeypatch):
    data = fixture(monkeypatch)
    monkeypatch.setattr(media, 'submit_nvme', lambda *a, **kw: {})
    monkeypatch.setattr(media, 'nvme_status', lambda _: {'serial': data['serial'], 'state': 'firmware-reports-success', 'log': {'scdw10': 4}})
    def attack(*args):
        data['namespaces'][0]['device']['size'] += 512
        return {'verification': {'passed': True, 'bytes_checked': 8192}}
    monkeypatch.setattr(workflow, 'attack_namespace', attack)
    with pytest.raises(EraseProofError, match='changed during'):
        run(data, tmp_path/'case')
    assert not EvidenceStore(tmp_path/'case').records()


def test_attack_rejects_replaced_device_before_scanning(tmp_path, monkeypatch):
    import eraseproof.targets as targets
    path = tmp_path/'replacement.img'
    path.write_bytes(bytes(8192))
    expected = {'name': str(path), 'size': 8192, 'serial': 'ORIGINAL', 'model': 'ORIGINAL'}
    monkeypatch.setattr(targets, 'describe', lambda _: {'path': str(path), 'size': 8192, 'serial': 'REPLACEMENT', 'model': 'ORIGINAL'})
    with pytest.raises(EraseProofError, match='changed before'):
        workflow.attack_namespace(path, {}, tmp_path/'attack', expected_device=expected)
    assert not (tmp_path/'attack').exists()


def test_overwrite_rejects_target_replacement_before_creating_evidence(tmp_path):
    from eraseproof import engine
    path = tmp_path/'replacement.img'
    path.write_bytes(b'preserve original bytes')
    expected = {'path': str(path), 'size': path.stat().st_size, 'serial': 'ORIGINAL', 'model': 'Raw image file'}
    with pytest.raises(EraseProofError, match='differs from'):
        engine.erase(path, path.name, tmp_path/'case', expected_target=expected)
    assert path.read_bytes() == b'preserve original bytes' and not (tmp_path/'case').exists()

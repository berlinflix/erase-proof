import copy
import os

import pytest

from eraseproof import ata, ataworkflow, attackgate, media, workflow
from eraseproof.evidence import EvidenceStore
from eraseproof.models import EraseProofError
from test_ata import discovery


def fixture(monkeypatch):
    data = discovery()
    data['target']['size'] = data['ata']['visible_sectors']*512
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    monkeypatch.setattr(ata, 'probe', lambda _: copy.deepcopy(data))
    monkeypatch.setattr(ata, 'device_gate', lambda *a, **kw: (data['target'], {'name': data['target']['path']}))
    monkeypatch.setattr(media, 'outside_devices', lambda *a: None)
    monkeypatch.setattr(attackgate, 'require_tools', lambda: None)
    return data


def execute(data, destination, methods=None, **kwargs):
    return ataworkflow.run(data['target']['path'], methods or ['enhanced-secure-erase', 'logical-overwrite'],
        data['target']['path'], data['ata']['serial'], destination,
        {'block_size': 4096, 'block_hashes': ['a'*64]}, timeout=1, **kwargs)


def test_ata_closed_loop_requires_complete_attacks_and_rechecks_factory_range(tmp_path, monkeypatch):
    data = fixture(monkeypatch)
    calls = []
    monkeypatch.setattr(ata, 'submit', lambda _, method, *a, **kw: calls.append(method) or
                        {'payload': {'state': 'firmware-reports-completion'}})
    monkeypatch.setattr(ataworkflow.engine, 'erase', lambda *a, **kw: calls.append('logical-overwrite') or {'receipt': 'logical'})
    def attack(*args):
        clean = len(calls) == 2
        return {'target': data['target'], 'verification': {'passed': clean, 'rrs': 0 if clean else .5,
            'bytes_checked': data['target']['size'], 'attacks_completed': True, 'observed_residue': not clean}}
    monkeypatch.setattr(workflow, 'attack_namespace', attack)
    record = execute(data, tmp_path/'case')
    assert calls == ['enhanced-secure-erase', 'logical-overwrite']
    assert record['payload']['certificate_issued'] and record['payload']['verification']['hidden_capacity_rechecked']
    assert len(record['payload']['verification']['rounds']) == 2 and EvidenceStore(tmp_path/'case').check()


@pytest.mark.parametrize('failure', ['unknown-completion', 'incomplete-attack', 'inconclusive-attack', 'capacity-change'])
def test_ata_uncertainty_never_escalates_or_certifies(tmp_path, monkeypatch, failure):
    data = fixture(monkeypatch)
    calls = []
    def submit(_, method, *args, **kwargs):
        calls.append(method)
        if failure == 'capacity-change':
            data['ata']['native_sectors'] -= 1
        return {'payload': {'state': 'unknown' if failure == 'unknown-completion' else 'firmware-reports-completion'}}
    monkeypatch.setattr(ata, 'submit', submit)
    monkeypatch.setattr(workflow, 'attack_namespace', lambda *a: {'verification': {'passed': False,
        'attacks_completed': failure != 'incomplete-attack', 'observed_residue': failure != 'inconclusive-attack'}})
    with pytest.raises(EraseProofError):
        execute(data, tmp_path/'case')
    assert calls == ['enhanced-secure-erase'] and not EvidenceStore(tmp_path/'case').records()
    assert EvidenceStore(tmp_path/'case').events()[-1]['payload']['event'] == 'workflow.incomplete'


@pytest.mark.parametrize('transition', ['busy-success', 'stale-success', 'busy-failed', 'missing-status'])
def test_ata_sanitize_requires_observed_busy_transition(tmp_path, monkeypatch, transition):
    data = fixture(monkeypatch)
    prepared = ataworkflow.plan(data, ['sanitize-block'], data['target']['path'], data['ata']['serial'])
    before = {'flags': 64, 'busy': True} if transition.startswith('busy') else {'flags': 128, 'busy': False}
    after = {'flags': 128, 'busy': False, 'last_success': transition != 'busy-failed'}
    data['ata']['sanitize_status'] = {} if transition == 'missing-status' else after
    receipt = {'payload': {'after': {'sanitize_status': before}}}
    store = EvidenceStore(tmp_path/'case')
    if transition == 'busy-success':
        assert ataworkflow.wait(data['target']['path'], prepared, receipt, 1, store, 'fixture') == data
    else:
        with pytest.raises(EraseProofError):
            ataworkflow.wait(data['target']['path'], prepared, receipt, 1, store, 'fixture')


def test_hidden_range_and_method_order_require_explicit_authorization():
    data = discovery(True)
    args = (data['target']['path'], data['ata']['serial'])
    with pytest.raises(EraseProofError, match='Hidden'):
        ataworkflow.plan(data, ['logical-overwrite'], *args)
    result = ataworkflow.plan(data, ['logical-overwrite'], *args, True, 1200)
    assert result['open_hidden'] and result['factory_sectors'] == 1200
    with pytest.raises(EraseProofError, match='final'):
        ataworkflow.plan(data, ['logical-overwrite', 'sanitize-block'], *args, True, 1200)


def test_ata_workflow_without_baseline_never_reaches_device(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    monkeypatch.setattr(ata, 'probe', lambda *a: calls.append(a))
    with pytest.raises(EraseProofError, match='baseline'):
        ataworkflow.run('/dev/FIXTURE', ['logical-overwrite'], '/dev/FIXTURE', 'FIXTURE', tmp_path/'case', {})
    assert calls == [] and not (tmp_path/'case').exists()


def test_changed_identity_never_reaches_ata_submission(tmp_path, monkeypatch):
    data = fixture(monkeypatch)
    with pytest.raises(EraseProofError, match='differs from'):
        ata.submit(data['target']['path'], 'enhanced-secure-erase', data['target']['path'], data['ata']['serial'],
                   tmp_path/'case', expected_identity=('DIFFERENT', data['ata']['model'], 512, 1000))
    assert not (tmp_path/'case').exists()

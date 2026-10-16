import copy

import pytest

from eraseproof import targets
from eraseproof.models import EraseProofError


def setup_policy(monkeypatch):
    root = {'name': '/dev/TEST-NOT-REAL', 'type': 'disk', 'size': 8192, 'serial': 'TEST', 'model': 'Fixture', 'tran': 'usb'}
    monkeypatch.setattr(targets.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(targets, 'describe', lambda _: {'kind': 'block-device', 'path': root['name'], 'size': 8192, 'serial': 'TEST', 'model': 'Fixture'})
    monkeypatch.setattr(targets, 'find_device', lambda _: (root, root))
    return root


def test_host_device_policy_retains_flash_hidden_page_limitation(monkeypatch):
    root = setup_policy(monkeypatch)
    plan = targets.device_policy(root['name'], 'TEST', root['name'])
    assert plan['kind'] == 'host-block-device'
    assert plan['hidden_areas']['state'] == 'not-established'
    assert 'Flash translation' in plan['scope']


@pytest.mark.parametrize('mutation', ['mounted-child', 'swap', 'read-only', 'wrong-serial', 'no-allowlist', 'not-root'])
def test_host_disk_unsafe_state_refused(monkeypatch, mutation):
    root = setup_policy(monkeypatch)
    serial, allowlist = 'TEST', root['name']
    if mutation == 'mounted-child':
        root['children'] = [{'name': '/dev/TEST-NOT-REAL1', 'mountpoints': ['/']}]
    elif mutation == 'swap':
        root['mountpoints'] = ['[SWAP]']
    elif mutation == 'read-only':
        root['ro'] = True
    elif mutation == 'wrong-serial':
        serial = 'mistyped'
    elif mutation == 'no-allowlist':
        allowlist = None
    else:
        monkeypatch.setattr(targets.os, 'geteuid', lambda: 1000)
    with pytest.raises(EraseProofError):
        targets.device_policy(root['name'], serial, allowlist)


@pytest.mark.parametrize('mutation', ['security-enabled', 'security-locked', 'sanitize-busy', 'sanitize-unknown'])
def test_ata_disk_write_refused_during_security_or_sanitize_operation(monkeypatch, mutation):
    from eraseproof import ata
    from test_ata import discovery
    root = setup_policy(monkeypatch)
    root['tran'] = 'sata'
    data = discovery()
    if mutation.startswith('security-'):
        data['ata']['security'][mutation.removeprefix('security-')] = True
    elif mutation == 'sanitize-busy':
        data['ata']['sanitize_status']['busy'] = True
    else:
        data['ata']['sanitize_status'] = {}
    monkeypatch.setattr(ata, 'probe', lambda _: data)
    with pytest.raises(EraseProofError, match='not ready'):
        targets.device_policy(root['name'], 'TEST', root['name'])

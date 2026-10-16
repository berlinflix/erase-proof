import copy
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from eraseproof.evidence import EvidenceStore
from eraseproof.media import nvme_plan, erase_luks_image, probe, submit_nvme
from eraseproof.models import EraseProofError


@pytest.mark.parametrize('entries', [[{'nsid': 1}, {'nsid': 7}], [1, 7]])
def test_namespace_inventory_accepts_nvme_cli_entries(entries):
    from eraseproof.media import namespace_identifiers
    assert namespace_identifiers({'nsid_list': entries}) == [1, 7]


@pytest.mark.parametrize('response', [None, [], {}, {'nsid_list': '1'},
    {'nsid_list': [{'nsid': True}]}, {'nsid_list': [{'nsid': '1'}]},
    {'nsid_list': [{'nsid': 0}]}, {'nsid_list': [{'nsid': 0xffffffff}]},
    {'nsid_list': [{'nsid': 2}, {'nsid': 1}]}, {'nsid_list': [1, 1]},
    {'nsid_list': [{}]}, {'nsid_list': list(range(1, 1025))}])
def test_namespace_inventory_refuses_ambiguous_or_incomplete_scope(response):
    from eraseproof.media import namespace_identifiers
    with pytest.raises(EraseProofError):
        namespace_identifiers(response)


def controller():
    return {"path": "/dev/nvme99", "serial": "TEST-NOT-A-REAL-DEVICE", "model": "Fixture",
            "identify": {"sanicap": 3, "cmic": 0}, "namespace_ids": [1, 2],
            "namespaces": [{"id": n, "device": {"name": f"/dev/nvme99n{n}", "type": "disk", "mountpoints": [], "ro": False}} for n in (1, 2)],
            "sanitize_log": {"sstat": 0}, "scope": "Synthetic command-boundary test only"}


@pytest.mark.parametrize("mutation", ["mounted-second-namespace", "missing-namespace", "no-support", "shared-controller", "wrong-serial", "busy-log", "read-only", "missing-cmic"])
def test_nvme_rejects_incomplete_or_busy_controller(mutation):
    data = controller()
    confirm = data["serial"]
    if mutation == "mounted-second-namespace":
        data["namespaces"][1]["device"]["children"] = [{"name": "/dev/nvme99n2p1", "mountpoints": ["/"]}]
    elif mutation == "missing-namespace":
        data["namespaces"].pop()
    elif mutation == "no-support":
        data["identify"]["sanicap"] = 0
    elif mutation == "shared-controller":
        data["identify"]["cmic"] = 1
    elif mutation == "wrong-serial":
        confirm = "mistyped"
    elif mutation == "busy-log":
        data["sanitize_log"]["sstat"] = 2
    elif mutation == "read-only":
        data["namespaces"][0]["device"]["ro"] = True
    else:
        del data["identify"]["cmic"]
    with pytest.raises(EraseProofError):
        nvme_plan(data, "block-erase", data["path"], confirm)


def test_nvme_plans_distinguish_firmware_receipts_from_certificates():
    data = controller()
    for method, action in (("block-erase", 2), ("crypto-erase", 4)):
        prepared = nvme_plan(data, method, data["path"], data["serial"])
        assert prepared["command"] == ["nvme", "sanitize", data["path"], f"--sanact={action}"]
        assert prepared["namespaces"] == ["/dev/nvme99n1", "/dev/nvme99n2"]
        assert prepared["certificate_eligible"] is False


def test_mounted_controller_never_reaches_destructive_command(monkeypatch, tmp_path):
    import eraseproof.media as media
    data = controller()
    data["namespaces"][1]["device"]["mountpoints"] = ["/home"]
    monkeypatch.setattr(media.os, "geteuid", lambda: 0)
    monkeypatch.setattr(media, "nvme_probe", lambda path: data)
    calls = []
    monkeypatch.setattr(media, "command", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(EraseProofError, match="mounted"):
        submit_nvme(data["path"], "block-erase", data["path"], data["serial"], tmp_path/"case")
    assert calls == [] and not (tmp_path/"case").exists()


@pytest.mark.skipif(not shutil.which("cryptsetup"), reason="requires real cryptsetup for image keyslot test")
def test_real_luks2_keyslot_erasure_and_old_passphrase_refusal(tmp_path):
    image, key = tmp_path/"encrypted.img", tmp_path/"fixture.key"
    with image.open("wb") as stream:
        stream.truncate(32*1024*1024)
    key.write_bytes(b"Ephemeral test fixture passphrase")
    key.chmod(0o600)
    subprocess.run(["cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", "--pbkdf", "pbkdf2", "--iter-time", "10", "--key-file", str(key), str(image)], check=True)
    unlock = ["cryptsetup", "open", "--test-passphrase", "--key-file", str(key), str(image)]
    assert subprocess.run(unlock, capture_output=True).returncode == 0
    assert probe(image)["encryption"] == "LUKS2"
    # Evidence must describe precisely what the command verified.
    result = erase_luks_image(image, image.name, tmp_path/"case")
    assert result["keyslots_before"] == 1 and result["keyslots_after"] == 0
    assert result["certificate_issued"] is False
    assert subprocess.run(unlock, capture_output=True).returncode != 0
    assert EvidenceStore(tmp_path/"case").check()
    assert EvidenceStore(tmp_path/"case").records() == []
    assert key.read_bytes() not in json.dumps(result).encode()


def test_luks_wrong_confirmation_does_not_change_image(tmp_path):
    image = tmp_path/"ordinary.img"
    image.write_bytes(b"original bytes")
    with pytest.raises(EraseProofError):
        erase_luks_image(image, "wrong", tmp_path/"case")
    assert image.read_bytes() == b"original bytes"


def test_nvme_sysfs_ownership_does_not_follow_device_number(tmp_path):
    from eraseproof.media import controller_namespaces
    sysfs = tmp_path/'sys'
    actual = sysfs/'devices/pci/nvme/nvme7'
    actual.mkdir(parents=True)
    other = sysfs/'devices/pci/other/nvme/nvme99'
    other.mkdir(parents=True)
    (sysfs/'class/nvme').mkdir(parents=True)
    (sysfs/'class/block').mkdir(parents=True)
    (sysfs/'class/nvme/nvme7').symlink_to(actual, target_is_directory=True)
    inventory = []
    # Deliberately mismatched numbering: nvme2n1 belongs to controller nvme7.
    for name, parent, identifier in [('nvme2n1', actual, 1), ('nvme7n1', other, 2)]:
        node = parent/name
        node.mkdir()
        (node/'nsid').write_text(str(identifier))
        (sysfs/'class/block'/name).symlink_to(node, target_is_directory=True)
        inventory.append({'name': '/dev/'+name, 'type': 'disk'})
    assert controller_namespaces('/dev/nvme7', inventory, sysfs) == [{'id': 1, 'device': inventory[0]}]


def test_method_matrix_prefers_capable_sanitize_and_keeps_unsupported_explicit():
    from eraseproof.media import decision
    data = controller()
    data['kind'] = 'nvme-controller'
    result = decision(data)
    assert result['read_only'] and result['recommended'] == 'nvme-sanitize-crypto-erase'
    assert len([m for m in result['methods'] if m['available']]) == 2
    assert all(m['physical_certificate'] is False for m in result['methods'])
    data['sanitize_log']['sstat'] = 2
    assert decision(data)['recommended'] is None


@pytest.mark.parametrize('native,dco,state', [(1000, 1000, 'no-capacity-reduction-reported'),
                                             (1000, 1200, 'hidden'), (1000, None, 'unknown')])
def test_hidden_capacity_planner_never_treats_unknown_as_absent(monkeypatch, native, dco, state):
    from eraseproof.media import decision
    import eraseproof.targets as targets
    monkeypatch.setattr(targets, 'virtual_disk_policy', lambda *args: (_ for _ in ()).throw(EraseProofError('Physical disk writes disabled')))
    data = {'target': {'kind': 'block-device', 'path': '/dev/TEST-ONLY', 'serial': 'TEST', 'scope': 'visible only'},
            'transport': 'sata', 'rotational': False,
            'hpa': {'visible_sectors': 1000, 'native_sectors': native, 'hidden': False},
            'checks': {'dco': {'raw': '' if dco is None else f'Real max sectors: {dco}'}}}
    prepared = decision(data)
    assert prepared['hidden_areas']['state'] == state
    assert prepared['recommended'] is None
    assert all(not m['available'] for m in prepared['methods'])
    assert prepared['blockers']


def test_image_plan_contains_actual_cli_without_running_it(tmp_path):
    from eraseproof.media import decision
    path = tmp_path/'a normal image.img'
    path.write_bytes(b'unchanged')
    result = decision(probe(path))
    assert result['recommended'] == 'logical-overwrite'
    assert str(path) in result['methods'][0]['command']
    assert path.read_bytes() == b'unchanged'
    ordinary = tmp_path/'keep.txt'
    ordinary.write_bytes(b'preserve')
    assert decision(probe(ordinary))['recommended'] is None

import copy
import ctypes
import errno
import os
import struct

import pytest

from eraseproof import ata, firmware
from eraseproof.models import EraseProofError


def fixture_identify():
    words = [0]*256
    words[83], words[86] = 0x4c00, 0x400
    words[82], words[59], words[128], words[90] = 0x400, 0xb000, 0x21, 3
    data = bytearray(struct.pack("<256H", *words))
    data[200:208] = (1000).to_bytes(8, "little")
    for start, length, text in ((20, 20, "TEST-NOT-HARDWARE"), (54, 40, "ATA FIXTURE")):
        raw = text.encode().ljust(length)
        data[start:start+length] = bytes(byte for i in range(0, len(raw), 2) for byte in (raw[i+1], raw[i]))
    return bytes(data)


def discovery(hidden=False):
    info = ata.identify(fixture_identify())
    info.update(native_sectors=1100 if hidden else 1000, dco_sectors=1200 if hidden else 1000,
                sanitize_status={"flags": 0, "frozen": False, "busy": False})
    return {"target": {"path": "/dev/ATA-FIXTURE", "serial": info["serial"], "model": info["model"], "kind": "block-device"}, "ata": info}


def prepare(data, method="sanitize-crypto", **kwargs):
    return ata.plan(data, method, data["target"]["path"], data["ata"]["serial"], **kwargs)


def test_identify_parses_real_words_and_hidden_capacity_requires_explicit_scope():
    data = discovery(True)
    assert data["ata"]["serial"] == "TEST-NOT-HARDWARE"
    assert data["ata"]["sanitize_crypto"] and data["ata"]["sanitize_block"]
    with pytest.raises(EraseProofError, match="Hidden"):
        prepare(data)
    with pytest.raises(EraseProofError):
        prepare(data, open_hidden=True, capacity_sectors=1100)
    prepared = prepare(data, open_hidden=True, capacity_sectors=1200)
    assert prepared["open_hidden"] and prepared["factory_sectors"] == 1200
    assert not prepared["certificate_eligible"]


@pytest.mark.parametrize("mutation", ["frozen", "busy", "unsupported", "locked", "expired", "already-enabled", "enhanced-unavailable"])
def test_ata_unsafe_state_never_produces_erase_plan(mutation):
    data = discovery()
    method = "sanitize-crypto"
    if mutation in ("frozen", "busy"):
        data["ata"]["sanitize_status"][mutation] = True
    elif mutation == "unsupported":
        data["ata"]["sanitize_crypto"] = False
    elif mutation in ("locked", "expired"):
        data["ata"]["security"][mutation] = True
    else:
        method = "enhanced-secure-erase"
        data["ata"]["security"]["enabled" if mutation == "already-enabled" else "enhanced"] = mutation == "already-enabled"
    with pytest.raises(EraseProofError):
        prepare(data, method)


def test_enhanced_erase_cannot_start_while_sanitize_is_busy():
    data = discovery()
    data['ata']['sanitize_status']['busy'] = True
    with pytest.raises(EraseProofError, match='busy'):
        prepare(data, 'enhanced-secure-erase')


def test_native_ata_wire_commands_and_regular_file_refusal(tmp_path):
    lib = firmware.library()
    cdb = ctypes.create_string_buffer(16)
    assert lib.ep_ata_fields(4, 0, cdb) == 0
    assert cdb.raw[0] == 0x85 and cdb.raw[14] == 0xb4
    assert cdb.raw[4] == 0x12 and cdb.raw[1] & 1
    assert bytes(cdb.raw[i] for i in (8, 10, 12, 7)) == (0x426b4572).to_bytes(4, "little")
    assert lib.ep_ata_fields(6, 0, cdb) == errno.EINVAL
    assert lib.ep_ata_fields(6, 123456, cdb) == 0
    assert cdb.raw[6] == 0  # volatile HPA opening, never a permanent reduction
    assert lib.ep_ata_fields(16, 0, cdb) == errno.EINVAL
    path = tmp_path/"preserve.img"
    original = os.urandom(4096)
    path.write_bytes(original)
    with path.open("r+b") as file:
        for operation in (0, 4, 5, 7):
            with pytest.raises(EraseProofError):
                firmware.ata(file.fileno(), operation)
    assert path.read_bytes() == original


def test_hidden_expansion_command_sequence_and_full_readback(monkeypatch):
    prepared = prepare(discovery(True), open_hidden=True, capacity_sectors=1200)
    current = copy.deepcopy(prepared["before"])
    calls = []
    def execute(fd, operation, value=0):
        calls.append((operation, value))
        if operation in (6, 12):
            current["visible_sectors"] = value
        elif operation == 7:
            current["native_sectors"] = current["dco_sectors"]
    monkeypatch.setattr(firmware, "ata", execute)
    monkeypatch.setattr(ata, "inspect_fd", lambda _: copy.deepcopy(current))
    after = ata.open_capacity(42, prepared)
    assert calls == [(1, 0), (6, 1100), (7, 0), (1, 0), (6, 1200)]
    assert after["visible_sectors"] == after["native_sectors"] == after["dco_sectors"] == 1200
    monkeypatch.setattr(firmware, "ata", lambda *a, **kw: None)
    current["visible_sectors"] = 1000
    with pytest.raises(EraseProofError, match="read-back"):
        ata.open_capacity(42, prepared)


@pytest.mark.parametrize('interrupted', [False, True])
def test_secure_erase_credentials_private_persisted_before_command_and_retained_on_interrupt(tmp_path, monkeypatch, interrupted):
    from eraseproof import media
    from eraseproof.evidence import EvidenceStore
    import json
    data = discovery()
    source = tmp_path/'owned-generated.img'
    original = os.urandom(8192)
    source.write_bytes(original)
    target = {**data['target'], 'path': str(source)}
    data['target'] = target
    state = copy.deepcopy(data['ata'])
    monkeypatch.setattr(ata.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(ata, 'device_gate', lambda *a, **kw: (target, {}))
    monkeypatch.setattr(ata, 'probe', lambda _: data)
    monkeypatch.setattr(ata, 'inspect_fd', lambda _: copy.deepcopy(state))
    monkeypatch.setattr(media, 'outside_devices', lambda *a: None)
    commands = []
    case = tmp_path/'evidence'
    def execute(fd, operation, value=0, payload=None, timeout=30000):
        commands.append(operation)
        keys = list(case.glob('*.recovery.key'))
        assert len(keys) == 1 and keys[0].stat().st_mode & 0o077 == 0
        assert keys[0].read_bytes() == bytes(payload[2:34])
        if operation == 8:
            state['security']['enabled'] = True
        elif interrupted:
            raise EraseProofError('Injected interruption after password set')
        else:
            state['security']['enabled'] = False
    monkeypatch.setattr(firmware, 'ata', execute)
    arguments = (str(source), 'enhanced-secure-erase', str(source), target['serial'], case)
    if interrupted:
        with pytest.raises(EraseProofError, match='interruption'):
            ata.submit(*arguments)
        keys = list(case.glob('*.recovery.key'))
        assert len(keys) == 1 and len(keys[0].read_bytes()) == 32
        assert keys[0].read_bytes().decode() not in json.dumps(EvidenceStore(case).events())
    else:
        receipt = ata.submit(*arguments)
        assert receipt['payload']['state'] == 'firmware-reports-completion'
        assert not receipt['payload']['certificate_issued'] and not list(case.glob('*.recovery.key'))
    assert commands == [8, 9] and source.read_bytes() == original
    assert EvidenceStore(case).check()

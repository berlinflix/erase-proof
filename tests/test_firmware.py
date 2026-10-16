import copy
import ctypes
import errno
import os

import pytest

from eraseproof import firmware, nvmeformat
from eraseproof.models import EraseProofError


def controller():
    return {"path": "/dev/nvme99", "serial": "TEST-NOT-HARDWARE", "model": "Fixture",
            "identify": {"cmic": 0, "oacs": 2, "fna": 4}, "namespace_ids": [1, 2],
            "sanitize_log": {"sstat": 0},
            "namespaces": [{"id": n, "device": {"name": f"/dev/nvme99n{n}", "type": "disk", "size": 8192}} for n in (1, 2)],
            "format_namespaces": {str(n): {"nsze": 16, "flbas": 0, "dps": 0, "lbafs": [{"ms": 0, "ds": 9}]} for n in (1, 2)}}


def prepared(data, method="crypto"):
    return nvmeformat.plan(data, method, data["path"], data["serial"])


def test_format_all_namespaces_preserves_layout_and_crypto_bits():
    data = controller()
    result = prepared(data)
    assert result["commands"] == [{"nsid": 0xffffffff, "lbaf": 0, "ses": 2}]
    assert len(result["namespaces"]) == 2 and not result["certificate_eligible"]
    data["identify"]["fna"] |= 8
    assert prepared(data)["commands"] == [{"nsid": n, "lbaf": 0, "ses": 2} for n in (1, 2)]
    data["identify"]["fna"] |= 2
    assert prepared(data)["commands"] == [{"nsid": 1, "lbaf": 0, "ses": 2}]


@pytest.mark.parametrize('capability', [None, 0, 3])
def test_unknown_sanitize_status_only_allows_known_unsupported_controller(capability):
    data = controller()
    data['sanitize_log'] = {'sstat': -1}
    if capability is not None:
        data['identify']['sanicap'] = capability
    if capability == 0:
        assert prepared(data)['commands']
    else:
        with pytest.raises(EraseProofError, match='status is unknown'):
            prepared(data)


@pytest.mark.parametrize("mutation", ["mounted", "missing", "shared", "no-crypto", "no-format", "unknown-layout", "metadata", "protection", "busy", "all-layouts-differ"])
def test_format_refuses_unsafe_or_unknown_scope(mutation):
    data = controller()
    if mutation == "mounted":
        data["namespaces"][1]["device"]["mountpoints"] = ["/"]
    elif mutation == "missing":
        data["namespaces"].pop()
    elif mutation == "shared":
        data["identify"]["cmic"] = 1
    elif mutation == "no-crypto":
        data["identify"]["fna"] = 0
    elif mutation == "no-format":
        data["identify"]["oacs"] = 0
    elif mutation == "unknown-layout":
        data["format_namespaces"] = {}
    elif mutation == "metadata":
        data["format_namespaces"]["2"]["lbafs"][0]["ms"] = 8
    elif mutation == "protection":
        data["format_namespaces"]["2"]["dps"] = 1
    elif mutation == "busy":
        data["sanitize_log"]["sstat"] = 2
    else:
        data["identify"]["fna"] |= 2
        data["format_namespaces"]["2"]["lbafs"][0]["ds"] = 12
    with pytest.raises(EraseProofError):
        prepared(data)


def test_format_before_command_gate(monkeypatch, tmp_path):
    from eraseproof import media
    data = controller()
    data["namespaces"][0]["device"]["mountpoints"] = ["/"]
    monkeypatch.setattr(nvmeformat.os, "geteuid", lambda: 0)
    monkeypatch.setattr(media, "nvme_probe", lambda _: data)
    calls = []
    monkeypatch.setattr(firmware, "format_nvm", lambda *a, **kw: calls.append(a))
    with pytest.raises(EraseProofError, match="mounted"):
        nvmeformat.submit(data["path"], "crypto", data["path"], data["serial"], tmp_path/"case")
    assert not calls and not (tmp_path/"case").exists()


def test_native_format_wire_encoding_and_noncontroller_refusal(tmp_path):
    lib = firmware.library()
    value = ctypes.c_uint32()
    assert lib.ep_nvme_format_fields(0xffffffff, 7, 2, ctypes.byref(value)) == 0
    assert value.value == 7 | (2 << 9)
    for nsid, lbaf, ses in ((0, 0, 1), (1, 16, 1), (1, 0, 0), (1, 0, 7)):
        assert lib.ep_nvme_format_fields(nsid, lbaf, ses, ctypes.byref(value)) == errno.EINVAL
    ordinary = tmp_path/"preserve.img"
    ordinary.write_bytes(os.urandom(4096))
    original = ordinary.read_bytes()
    with ordinary.open("r+b") as file:
        with pytest.raises(EraseProofError, match="ioctl failed"):
            firmware.format_nvm(file.fileno(), 1, 0, 1)
        with pytest.raises(EraseProofError):
            firmware.sanitize(file.fileno(), 2)
    assert ordinary.read_bytes() == original

import copy
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from eraseproof.evidence import EvidenceStore
from eraseproof.media import nvme_plan, erase_luks_image, probe, submit_nvme
from eraseproof.models import EraseProofError


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

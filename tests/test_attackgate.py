import hashlib
import base64
import io
import os
import re
from pathlib import Path
import subprocess
import sys
import time

import pytest

from eraseproof import attackgate, carve, demo, external
from eraseproof.engine import erase
from eraseproof.evidence import EvidenceStore
from eraseproof.matching import Matcher
from eraseproof.models import Cancelled, EraseProofError


def test_actual_independent_recovery_finds_target_and_preserves_unrelated_findings(tmp_path):
    manifest = demo.create(tmp_path/"experiment", delete_files=True)
    image = Path(manifest["image"])
    target = next(file["sha256"] for file in manifest["files"] if file["name"] == "CAPTURE.PNG")
    original = hashlib.sha256(image.read_bytes()).hexdigest()
    with image.open("rb") as stream:
        result = attackgate.check(image, tmp_path/"attack", {"file_hashes": [target]}, stream=stream,
                                  length=image.stat().st_size, expected_sha256=original)
    assert not result["passed"]
    assert result["matching_file_hashes"] == [target]
    assert result["recovered_files"] > len(result["findings"])
    assert result["source_unchanged"]
    with image.open("rb") as stream:
        unrelated = attackgate.check(image, tmp_path/"unrelated", {"file_hashes": [hashlib.sha256(b"not on this volume").hexdigest()]},
                                     stream=stream, length=image.stat().st_size, expected_sha256=original)
    assert unrelated["passed"] and unrelated["recovered_files"] > 0


def test_bulk_extractor_recovers_encoded_jpeg_missed_by_raw_carving(tmp_path):
    from PIL import Image
    manifest = demo.create(tmp_path/"experiment")
    image = Path(manifest["image"])
    data = io.BytesIO()
    Image.frombytes("RGB", (137, 113), os.urandom(137*113*3)).save(data, "JPEG", quality=91)
    original = data.getvalue()
    encoded = tmp_path/"encoded.txt"
    encoded.write_bytes(b"Encoded backup:\n"+base64.encodebytes(original)+b"\n")
    subprocess.run(["mcopy", "-i", str(image), str(encoded), "::/ENCODED.TXT"], check=True, capture_output=True)
    assert "JPEG" not in {candidate.file_type for candidate in carve.scan(image)}
    target = hashlib.sha256(original).hexdigest()
    source_sha = hashlib.sha256(image.read_bytes()).hexdigest()
    with image.open("rb") as stream:
        result = attackgate.check(image, tmp_path/"encoded-attack", {"file_hashes": [target]}, stream=stream,
                                  length=image.stat().st_size, expected_sha256=source_sha)
    assert result["required_tools"]["bulk_extractor"] == "completed"
    assert not result["passed"] and result["matching_file_hashes"] == [target]
    assert any(finding["tool"] == "bulk_extractor" and finding["full_file_match"] for finding in result["findings"])


def test_missing_independent_tool_blocks_before_erase(tmp_path, monkeypatch):
    image = tmp_path/"preserve.img"
    image.write_bytes(os.urandom(8192))
    before = image.read_bytes()
    original = attackgate.shutil.which
    monkeypatch.setattr(attackgate.shutil, "which", lambda tool: None if tool == "photorec" else original(tool))
    with pytest.raises(EraseProofError, match="tools are missing"):
        erase(image, image.name, tmp_path/"case")
    assert image.read_bytes() == before


def test_independent_timeout_leaves_incomplete_evidence(tmp_path, monkeypatch):
    image = tmp_path/"volume.img"
    image.write_bytes(os.urandom(8192))
    monkeypatch.setattr(external, "run", lambda *args, **kwargs: {"status": "timeout", "returncode": -15})
    with pytest.raises(EraseProofError, match="Independent recovery check failed"):
        erase(image, image.name, tmp_path/"case")
    store = EvidenceStore(tmp_path/"case")
    assert not store.records()
    detail = store.events()[-1]["payload"]["detail"]
    assert not detail["verification"]["passed"]
    assert detail["verification"]["independent_attack"]["required_tools"]["PhotoRec"] == "timeout"


def test_success_exit_with_incomplete_scanner_report_blocks_certificate(tmp_path, monkeypatch):
    image = tmp_path/"volume.img"
    image.write_bytes(os.urandom(8192))
    original = external.run
    def weaken(*arguments, **kwargs):
        result = original(*arguments, **kwargs)
        if arguments[2] == "bulk-extractor":
            report = arguments[1]/"bulk-extractor"/"report.xml"
            data = report.read_bytes()
            changed, replacements = re.subn(rb"<total_bytes>\d+</total_bytes>", b"<total_bytes>0</total_bytes>", data)
            assert replacements == 1 and result["returncode"] == 0
            report.write_bytes(changed)
        return result
    monkeypatch.setattr(external, "run", weaken)
    with pytest.raises(EraseProofError, match="Independent recovery check failed"):
        erase(image, image.name, tmp_path/"case")
    store = EvidenceStore(tmp_path/"case")
    assert not store.records()
    detail = store.events()[-1]["payload"]["detail"]
    assert detail["verification"]["independent_attack"]["required_tools"]["bulk_extractor"] == "incomplete-report"


def test_identity_change_is_refused_before_external_attack(tmp_path):
    image = tmp_path/"source.img"
    image.write_bytes(os.urandom(8192))
    original = hashlib.sha256(image.read_bytes()).hexdigest()
    with image.open("rb") as stream:
        image.rename(tmp_path/"old.img")
        image.write_bytes(bytes(8192))
        with pytest.raises(EraseProofError, match="identity changed"):
            attackgate.check(image, tmp_path/"attack", None, stream=stream, length=8192, expected_sha256=original)
    assert not (tmp_path/"attack").exists()


def test_external_worker_timeout_and_output_budget(tmp_path):
    timed = tmp_path/"timed"
    timed.mkdir()
    result = external.run([sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)"], timed, "worker", timeout=1)
    assert result["status"] == "timeout" and result["duration_seconds"] < 5
    limited = tmp_path/"limited"
    limited.mkdir()
    result = external.run([sys.executable, "-c", "import sys,time; sys.stdout.buffer.write(b'x'*2097152); sys.stdout.flush(); time.sleep(30)"],
                          limited, "worker", timeout=10, output_limit=1024*1024)
    assert result["status"] == "output-limit" and result["duration_seconds"] < 5


def test_cancel_terminates_real_external_worker(tmp_path, monkeypatch):
    launched, original = [], subprocess.Popen
    def launch(*args, **kwargs):
        process = original(*args, **kwargs)
        launched.append(process)
        return process
    monkeypatch.setattr(external.subprocess, "Popen", launch)
    started = time.monotonic()
    with pytest.raises(Cancelled):
        external.run([sys.executable, "-c", "import time; time.sleep(30)"], tmp_path, "worker", 10,
                     cancel=lambda: time.monotonic()-started > .3)
    assert launched and launched[0].poll() is not None
    assert time.monotonic()-started < 5


def test_worker_cannot_leave_a_child_after_its_leader_exits(tmp_path):
    child = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"
    parent = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c',sys.argv[1]]); print(p.pid,flush=True); time.sleep(.2)"
    result = external.run([sys.executable, "-c", parent, child], tmp_path, "worker", 5)
    pid = int(Path(result["stdout_log"]).read_text())
    deadline = time.monotonic()+3
    while Path(f"/proc/{pid}/stat").exists():
        state = Path(f"/proc/{pid}/stat").read_text().split()[2]
        if state == "Z":  # Terminated; init will reap the orphan.
            break
        if time.monotonic() >= deadline:
            os.kill(pid, 9)
            pytest.fail("External worker left a running child")
        time.sleep(.01)


def test_binary_aho_corasick_matches_duplicates_and_overlaps():
    patterns = [b"\x80ABA", b"ABA", b"BA", b"ABA"]
    found = set(Matcher(patterns).iter(b"x\x80ABABA\xff"))
    assert (1, 0) in found and (2, 1) in found and (2, 3) in found
    assert (3, 2) in found and (4, 1) in found and (5, 2) in found


def test_excessive_signatures_are_an_incomplete_scan(tmp_path):
    image = tmp_path/"adversarial.img"
    image.write_bytes((b"\x1f\x8b\x08x")*100_001)
    with pytest.raises(EraseProofError, match="hit limit"):
        carve.scan(image)


def test_streamed_container_output_has_explicit_file_limit(tmp_path):
    writer = "import sys; open(sys.argv[1], 'wb').write(bytes(3*1024*1024))"
    too_small = tmp_path/'limited'
    too_small.mkdir()
    result = external.run([sys.executable, '-c', writer, too_small/'container.fat'], too_small, 'worker', 10,
                          output_limit=8*1024**2, per_file_limit=1024**2)
    assert result['status'] == 'failed'
    assert result['limits']['per_file_bytes'] == 1024**2
    enough = tmp_path/'complete'
    enough.mkdir()
    result = external.run([sys.executable, '-c', writer, enough/'container.fat'], enough, 'worker', 10,
                          output_limit=8*1024**2, per_file_limit=4*1024**2)
    assert result['status'] == 'completed'
    assert (enough/'container.fat').stat().st_size == 3*1024**2
    assert result['limits']['per_file_bytes'] == 4*1024**2

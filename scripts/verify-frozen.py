"""Exercise the shipped Linux binary, including recovery and destructive image I/O."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

binary = str(Path(sys.argv[1]).resolve())


def run(*args):
    result = subprocess.run([binary, "--cli", *map(str, args)], capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(result.stderr[-4000:])
    return json.loads(result.stdout)


with tempfile.TemporaryDirectory(prefix="eraseproof-release-") as temporary:
    root = Path(temporary)
    doctor = run("doctor")
    manifest = run("demo", "create", root/"experiment", "--deleted")
    recovery = run("recover", manifest["image"], "--output", root/"recovery")
    expected = {item["sha256"] for item in manifest["files"]}
    recovered = {item["sha256"] for item in recovery["candidates"] if item["method"] == "sleuthkit-metadata"}
    assert expected == recovered
    result = run("erase", manifest["image"], "--confirm", "experiment.img", "--references", root/"experiment"/"manifest.json", "--case", root/"evidence")
    assert result["record"]["payload"]["verification"]["rrs"] == 0
    assert run("record", result["certificate"])["signature_valid"]
    assert run("audit", root/"evidence")["intact"]
    after = run("recover", manifest["image"], "--mode", "carve", "--output", root/"after")
    assert after["candidates"] == []
    environment = {**os.environ, "QT_QPA_PLATFORM": "offscreen", "HOME": str(root/"home")}
    (root/"home").mkdir()
    gui = subprocess.Popen([binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    time.sleep(3)
    if gui.poll() is not None:
        raise RuntimeError("Frozen Qt launch failed: "+gui.stderr.read().decode(errors="replace"))
    gui.terminate()
    gui.wait(timeout=10)
    print(json.dumps({"binary": binary, "runtime": doctor["platform"], "deleted_files_recovered_and_hash_matched": len(recovered), "total_findings": len(recovery["candidates"]), "rrs_after_overwrite": 0, "after_carving_candidates": 0, "signed_record_valid": True, "audit_intact": True, "native_qt_process_startup": "passed"}, indent=2))

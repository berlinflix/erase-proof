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
    assert doctor["native_direct_io"] and doctor["offline_ext4_adapter"] and doctor["offline_ntfs_adapter"]
    manifest = run("demo", "create", root/"experiment", "--deleted")
    recovery = run("recover", manifest["image"], "--output", root/"recovery")
    expected = {item["sha256"] for item in manifest["files"]}
    recovered = {item["sha256"] for item in recovery["candidates"] if item["method"] == "sleuthkit-metadata"}
    assert expected == recovered
    result = run("erase", manifest["image"], "--confirm", "experiment.img", "--references", root/"experiment"/"manifest.json", "--case", root/"evidence")
    assert result["record"]["payload"]["verification"]["rrs"] == 0
    assert result["record"]["payload"]["verification"]["io"]["direct_bytes"] == 64*1024*1024
    assert run("record", result["certificate"])["signature_valid"]
    fingerprint = result["record"]["signer_fingerprint"]
    assert run("record", result["certificate"], "--trusted-fingerprint", fingerprint)["trusted_signer"]
    pdf = run("pdf", result["certificate"], "--output", root/"report.pdf")
    assert pdf["pages"] == 2
    assert run("pdf-record", root/"report.pdf", "--trusted-fingerprint", fingerprint)["trusted_signer"]
    run("audit-export", root/"evidence", "--output", root/"checkpoint.json")
    assert run("audit", root/"evidence", "--anchor", root/"checkpoint.json", "--trusted-fingerprint", fingerprint)["anchor_matches"]
    assert run("audit", root/"evidence")["intact"]
    after = run("recover", manifest["image"], "--mode", "carve", "--output", root/"after")
    assert after["candidates"] == []
    independent = run("attack", manifest["image"], "--output", root/"independent-after")
    assert independent["recovered_files"] == 0
    assert next(t for t in independent["tools"] if t["tool"] == "PhotoRec")["status"] == "completed"
    logical = root/"logical.txt"
    logical.write_text("Native executable targeted erasure fixture")
    assert run("erase-files", logical, "--confirm", logical.name, "--case", root/"evidence")["payload"]["verification"]["passed"]
    assert not logical.exists()
    fat_manifest = run("demo", "create", root/"fat-target")
    fat_image = Path(fat_manifest["image"])
    prepared = run("fat32-plan", fat_image, "/REPORT.PDF")
    fat = run("fat32-erase", fat_image, "/REPORT.PDF", "--confirm", prepared["confirmation"], "--case", root/"evidence")
    assert fat["payload"]["verification"]["rrs"] == 0
    assert fat["payload"]["verification"]["independent_attack"]["passed"]
    assert fat["payload"]["verification"]["preserved_files_hash_checked"] == 3
    assert fat["payload"]["verification"]["cleanup"]["io"]["direct_bytes"] > 0
    ext4_image = root/"ext4.img"
    with ext4_image.open("xb") as stream:
        stream.truncate(32*1024*1024)
    subprocess.run(["mkfs.ext4", "-q", "-F", str(ext4_image)], check=True)
    secret, keep = root/"secret.bin", root/"keep.bin"
    secret.write_bytes(b"FROZEN-EXT4-PRIVATE-SAMPLE"*1000)
    keep.write_bytes(os.urandom(17000))
    for source, internal in ((secret, "/private.bin"), (keep, "/keep.bin")):
        subprocess.run(["debugfs", "-w", "-R", f"write {source} {internal}", str(ext4_image)], check=True, capture_output=True)
    prepared = run("ext4-plan", ext4_image, "/private.bin")
    ext4 = run("ext4-erase", ext4_image, "/private.bin", "--confirm", prepared["confirmation"], "--case", root/"evidence")
    assert ext4["payload"]["verification"]["rrs"] == 0
    assert ext4["payload"]["verification"]["preserved_files_hash_checked"] == 1
    ntfs_image = root/"ntfs.img"
    with ntfs_image.open("xb") as stream:
        stream.truncate(64*1024*1024)
    subprocess.run(["mkfs.ntfs", "-F", "-Q", str(ntfs_image)], check=True, capture_output=True)
    for source, internal in ((secret, "/private.bin"), (keep, "/keep.bin")):
        subprocess.run(["ntfscp", str(ntfs_image), str(source), internal], check=True, capture_output=True)
    assert any(entry["path"] == "/private.bin" for entry in run("ntfs-list", ntfs_image))
    prepared = run("ntfs-plan", ntfs_image, "/private.bin")
    ntfs = run("ntfs-erase", ntfs_image, "/private.bin", "--confirm", prepared["confirmation"], "--case", root/"evidence")
    assert ntfs["payload"]["verification"]["history_verification"]["passed"]
    assert ntfs["payload"]["verification"]["preserved_files_hash_checked"] == 1
    environment = {**os.environ, "QT_QPA_PLATFORM": "offscreen", "HOME": str(root/"home")}
    (root/"home").mkdir()
    gui = subprocess.Popen([binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    time.sleep(3)
    if gui.poll() is not None:
        raise RuntimeError("Frozen Qt launch failed: "+gui.stderr.read().decode(errors="replace"))
    gui.terminate()
    gui.wait(timeout=10)
    assert all(c["confidence"] >= 98 for c in recovery["candidates"] if c["method"] != "sleuthkit-metadata")
    print(json.dumps({"binary": binary, "version": doctor["version"], "runtime": doctor["platform"], "deleted_files_recovered_and_hash_matched": len(recovered), "total_findings": len(recovery["candidates"]), "rrs_after_overwrite": 0, "after_carving_candidates": 0, "signed_record_and_expected_signer_valid": True, "pdf_attachment_valid": True, "anchored_audit_intact": True, "independent_photorec_after_files": 0, "targeted_file_erasure": "passed", "native_direct_io_bytes": 64*1024*1024, "offline_fat32_erasure_and_preservation": "passed", "offline_ext4_erasure_and_preservation": "passed", "offline_ntfs_erasure_and_preservation": "passed", "native_qt_process_startup": "passed"}, indent=2))

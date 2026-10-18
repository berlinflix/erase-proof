"""Check release checksums, source hygiene and extracted native startup."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import zipfile
import tarfile
import argparse

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root/"src"))
from eraseproof import __version__ as version
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--artifacts', type=Path, default=root/'artifacts')
parser.add_argument('--evidence-ui', action='store_true', help='Exercise selection, dialogs and exports inside the extracted frozen app')
args = parser.parse_args()
artifacts = args.artifacts.resolve()
interaction_check = None
for line in (artifacts/"SHA256SUMS").read_text().splitlines():
    expected, name = line.split("  ", 1)
    if Path(name).name != name:
        raise RuntimeError("Unsafe checksum manifest path")
    digest = hashlib.sha256()
    with (artifacts/name).open("rb") as source:
        for block in iter(lambda: source.read(4*1024*1024), b""):
            digest.update(block)
    assert digest.hexdigest() == expected, name
with zipfile.ZipFile(artifacts/f"EraseProof-source-{version}.zip") as source:
    assert source.testzip() is None
    names = source.namelist()
    assert all(not (info.external_attr >> 16) & 0o022 for info in source.infolist())
    assert any(n.endswith("src/eraseproof/desktop.py") for n in names)
    assert any(n.endswith("resources/fonts/LICENSE.txt") for n in names)
    assert any(n.endswith("native/io.c") for n in names)
    assert any(n.endswith("native/ext4.c") for n in names)
    assert not any(n.endswith(".so") or n.endswith("resources/native/eraseproof-ext4") for n in names)
    assert not any(".venv" in n or "operator-ed25519.key" in n or "prototype-web" in n or n.endswith(".sqlite3") for n in names)
with tarfile.open(artifacts/f"EraseProof-Ubuntu-x86_64-{version}.tar.gz") as archive:
    for item in archive:
        assert item.uid == 0 and item.gid == 0
        if item.isfile() or item.isdir():
            assert not item.mode & 0o022, item.name
with tempfile.TemporaryDirectory(prefix="eraseproof-extracted-") as temporary:
    subprocess.run(["tar", "-xzf", str(artifacts/f"EraseProof-Ubuntu-x86_64-{version}.tar.gz"), "-C", temporary], check=True)
    binary = Path(temporary)/"EraseProof"/"EraseProof"
    sys.path.insert(0, str(root/'scripts'))
    from bundle_manifest import verify as verify_bundle
    verify_bundle(binary.parent)
    doctor = json.loads(subprocess.run([str(binary), "--cli", "doctor"], capture_output=True, text=True, check=True).stdout)
    assert doctor["version"] == version
    provenance = json.loads((binary.parent/'BUILD-SOURCE.json').read_text())
    assert provenance['software_version'] == version
    assert provenance['tracked_worktree_modified'] is not True, 'Commit verified source/docs before the final release package.'
    assert doctor["native_direct_io"] and doctor["offline_ext4_adapter"]
    assert (binary.parent/"THIRD-PARTY-LICENSES"/"Qt-and-PySide"/"LGPL-3.0.txt").is_file()
    library_notices = binary.parent/'THIRD-PARTY-LICENSES/Ubuntu-libraries'
    for prefix in ('libext2fs', 'libntfs-3g', 'libre2'):
        assert any((folder/'copyright').is_file() for folder in library_notices.glob(prefix+'*')), prefix
    gui = subprocess.Popen([str(binary)], env={**os.environ, "QT_QPA_PLATFORM": "offscreen", "HOME": temporary}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(3)
    if gui.poll() is not None:
        raise RuntimeError(gui.stderr.read().decode(errors="replace"))
    gui.terminate()
    gui.wait(timeout=10)
    if args.evidence_ui:
        result = subprocess.run([str(binary), '--check-evidence-ui'],
            env={**os.environ, 'QT_QPA_PLATFORM': 'offscreen', 'XDG_CONFIG_HOME': temporary},
            capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise RuntimeError(result.stderr[-8000:])
        interaction_check = json.loads(result.stdout)
        assert interaction_check['passed'] and interaction_check['frozen']
print(json.dumps({"version": version, "checksums": "passed", "source_hygiene": "passed", "extracted_linux_cli": "passed", "extracted_qt_startup": "passed", "evidence_ui": interaction_check, "virtualbox_tested": False}, indent=2))

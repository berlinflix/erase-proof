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

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root/"src"))
from eraseproof import __version__ as version
artifacts = root/"artifacts"
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
    assert any(n.endswith("src/eraseproof/desktop.py") for n in names)
    assert any(n.endswith("resources/fonts/LICENSE.txt") for n in names)
    assert not any(".venv" in n or "operator-ed25519.key" in n or "prototype-web" in n or n.endswith(".sqlite3") for n in names)
with tempfile.TemporaryDirectory(prefix="eraseproof-extracted-") as temporary:
    subprocess.run(["tar", "-xzf", str(artifacts/f"EraseProof-Ubuntu-x86_64-{version}.tar.gz"), "-C", temporary], check=True)
    binary = Path(temporary)/"EraseProof"/"EraseProof"
    doctor = json.loads(subprocess.run([str(binary), "--cli", "doctor"], capture_output=True, text=True, check=True).stdout)
    assert doctor["version"] == version
    assert (binary.parent/"THIRD-PARTY-LICENSES"/"Qt-and-PySide"/"LGPL-3.0.txt").is_file()
    gui = subprocess.Popen([str(binary)], env={**os.environ, "QT_QPA_PLATFORM": "offscreen", "HOME": temporary}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(3)
    if gui.poll() is not None:
        raise RuntimeError(gui.stderr.read().decode(errors="replace"))
    gui.terminate()
    gui.wait(timeout=10)
print(json.dumps({"version": version, "checksums": "passed", "source_hygiene": "passed", "extracted_linux_cli": "passed", "extracted_qt_startup": "passed", "virtualbox_tested": False}, indent=2))

"""Package the native Linux distribution and clean source for an Ubuntu VM."""
import hashlib
from pathlib import Path
import tarfile
import zipfile
import importlib.metadata
import json
import shutil
import subprocess
from release_permissions import file_mode

root = Path(__file__).resolve().parent.parent
output = root/"artifacts"
output.mkdir(exist_ok=True)
import sys
sys.path.insert(0, str(root/"src"))
from eraseproof import __version__ as version
binary = root/"dist"/"EraseProof"
if not (binary/"EraseProof").exists():
    raise SystemExit("Build the Linux executable first.")
shipped_version = subprocess.run([str(binary/'EraseProof'), '--cli', '--version'], capture_output=True, text=True, check=True).stdout.strip()
if shipped_version != version:
    raise SystemExit('Executable/source version mismatch. Rebuild before packaging.')
revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=root, capture_output=True, text=True)
tracked = subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--'], cwd=root, capture_output=True)
(binary/'BUILD-SOURCE.json').write_text(json.dumps({'software_version': version,
    'git_commit': revision.stdout.strip() if revision.returncode == 0 else None,
    'tracked_worktree_modified': tracked.returncode != 0,
    'provenance': 'Packaging metadata; not an independent reproducible-build attestation.'}, indent=2)+'\n')

for name in ("cryptography", "Pillow", "pypdf", "reportlab", "qrcode", "pyahocorasick", "PySide6-Essentials", "shiboken6", "cffi", "pyinstaller", "typing_extensions", "charset-normalizer", "pycparser"):
    distribution = importlib.metadata.distribution(name)
    for entry in distribution.files or []:
        if any(token in str(entry).lower() for token in ("license", "copying", "notice")):
            original = Path(distribution.locate_file(entry))
            if original.is_file():
                destination = binary/"THIRD-PARTY-LICENSES"/name/Path(entry).name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, destination)
python_license = Path("/usr/share/doc/python3.10/copyright")
if python_license.is_file():
    destination = binary/"THIRD-PARTY-LICENSES"/"Python"
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(python_license, destination/"copyright")
shutil.copytree(root/"docs"/"licenses", binary/"THIRD-PARTY-LICENSES"/"Qt-and-PySide", dirs_exist_ok=True)
# PyInstaller discovers system ELF dependencies as well as wheel libraries.
# Preserve Ubuntu copyright files and the full common license texts for them.
system_packages = set()
for bundled in (binary/"_internal").iterdir():
    if not bundled.is_file() or ".so" not in bundled.name:
        continue
    for directory in (Path("/lib/x86_64-linux-gnu"), Path("/usr/lib/x86_64-linux-gnu"), Path("/lib64")):
        original = directory/bundled.name
        if not original.is_file():
            continue
        for candidate in {str(original), str(original.resolve())}:
            found = subprocess.run(["dpkg-query", "-S", candidate], capture_output=True, text=True)
            if found.returncode == 0:
                for line in found.stdout.splitlines():
                    system_packages.add(line.split(": ", 1)[0].split(":", 1)[0])
for package in sorted(system_packages):
    copyright_file = Path("/usr/share/doc")/package/"copyright"
    if copyright_file.is_file():
        destination = binary/"THIRD-PARTY-LICENSES"/"Ubuntu-libraries"/package
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(copyright_file, destination/"copyright")
shutil.copytree("/usr/share/common-licenses", binary/"THIRD-PARTY-LICENSES"/"Common-license-texts", dirs_exist_ok=True)
versions = [f"{distribution.metadata['Name']}=={distribution.version}" for distribution in importlib.metadata.distributions()
            if distribution.metadata.get("Name") != "eraseproof"]
(binary/"BUILD-PACKAGES.txt").write_text("\n".join(sorted(set(versions)))+"\n")

(binary/"install-runtime.sh").write_bytes((root/"scripts"/"install-binary-runtime.sh").read_bytes())
(binary/"install-runtime.sh").chmod(0o755)
(binary/"README-FIRST.txt").write_text("""EraseProof — NATIVE UBUNTU APPLICATION

This is a Linux x86-64 program, built on Ubuntu 22.04 under WSL.
It has a native Qt desktop interface and needs no browser or web server.

IN YOUR UBUNTU VIRTUALBOX VM:
1. Extract this archive into your Ubuntu home directory.
2. In a terminal inside the extracted EraseProof folder, run:
     bash install-runtime.sh
   This installs real forensic/demo tools, capability tools and Qt runtime libraries.
   The bundled program includes Python and Qt; no pip setup is required.
3. Run:
     ./EraseProof
   Or use the EraseProof entry installed in Ubuntu's application menu.

DEMO:
Experiment -> Create FAT32 experiment -> Delete files normally.
Recover files -> Scan & recover -> Open recovered PDF/PNG.
Erase & verify -> Prepare overwrite -> Type experiment.img to confirm.
Evidence -> Inspect/export the signed local record.

CLI:
  ./EraseProof --cli doctor
  ./EraseProof --cli --help

Scope: actual image writes and guest-visible logical overwrite only.
The default demo needs no root and never targets the system disk.
Includes native C direct I/O, targeted logical file/folder erasure, offline
FAT32 path cleanup, C/libext2fs ext4 allocation/inode/slack/journal cleanup,
NTFS stream/MFT/log/USN cleanup, exFAT allocation/history cleanup, selectable
offline paths, arbitrary-format Ubuntu Trash copies, expanded validated carving,
required PhotoRec/TSK/bulk_extractor verification, partition discovery,
signed JSON/PDF/QR reports, trusted signer checks and audit checkpoints.
NVMe command submission is a separate guarded privileged CLI adapter, with
audited receipts rather than physical-erasure certificates. LUKS2 image
keyslot removal is supported. See source docs/MEDIA.md and docs/EVIDENCE.md.
The media planner reports actual executable support and unknown hidden capacity.
ATA destructive commands, Format NVM, HPA/DCO changes, snapshots and physical
flash-remanence assurance are outside this release's verified scope.
Secondary virtual-disk writes are gated by a path/serial policy and require
separate VirtualBox acceptance testing. Begin with the image experiment.

WSL validation: automated engine and native Qt tests, real FAT32 recovery,
hash comparisons, overwrite/read-back, and executable-level workflow tests.
VirtualBox has not been operated by the developer in this session.

Keep the whole EraseProof folder together; the _internal directory is needed.
""")
shutil.copytree(root/"docs", binary/"docs", dirs_exist_ok=True)

archive = output/f"EraseProof-Ubuntu-x86_64-{version}.tar.gz"
def archive_mode(info):
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    if info.isdir():
        info.mode = 0o755
    elif info.isfile():
        info.mode = file_mode(binary.parent/info.name)
    return info
with tarfile.open(archive, "w:gz") as file:
    file.add(binary, arcname="EraseProof", filter=archive_mode)

source = output/f"EraseProof-source-{version}.zip"
paths = [root/name for name in ("README.md", "pyproject.toml", ".gitattributes", ".gitignore")]
for directory in ("src", "tests", "scripts", "docs", "native"):
    paths.extend(p for p in (root/directory).rglob("*") if p.is_file() and "__pycache__" not in p.parts
                 and p.suffix not in (".pyc", ".so") and "resources/native" not in p.as_posix())
with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as file:
    for path in sorted(paths):
        info = zipfile.ZipInfo.from_file(path, arcname=str(Path(f"EraseProof-source-{version}")/path.relative_to(root)))
        info.external_attr = (0o100000 | file_mode(path)) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        file.writestr(info, path.read_bytes())

checksums = []
release_files = [archive, source]
for path in sorted(output.glob(f"EraseProof-Live-*-{version}.iso")):
    release_files.append(path)
for path in release_files:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(4*1024*1024), b""):
            digest.update(block)
    checksums.append(f"{digest.hexdigest()}  {path.name}")
    print(f"{path.name}: {path.stat().st_size:,} bytes")
(output/"SHA256SUMS").write_text("\n".join(checksums)+"\n")

"""Package the native Linux distribution and clean source for an Ubuntu VM."""
import hashlib
from pathlib import Path
import tarfile
import zipfile

root = Path(__file__).resolve().parent.parent
output = root/"artifacts"
output.mkdir(exist_ok=True)
version = "0.2.0"
binary = root/"dist"/"EraseProof"
if not (binary/"EraseProof").exists():
    raise SystemExit("Build the Linux executable first.")

(binary/"install-runtime.sh").write_bytes((root/"scripts"/"install-binary-runtime.sh").read_bytes())
(binary/"install-runtime.sh").chmod(0o755)
(binary/"README-FIRST.txt").write_text("""EraseProof 0.2.0 — NATIVE UBUNTU APPLICATION

This is a Linux x86-64 program, built on Ubuntu 22.04 under WSL.
It has a native Qt desktop interface and needs no browser or web server.

IN YOUR UBUNTU VIRTUALBOX VM:
1. Extract this archive into your Ubuntu home directory.
2. In a terminal inside the extracted EraseProof folder, run:
     bash install-runtime.sh
   This installs dosfstools, mtools, Sleuth Kit and Linux Qt runtime libraries.
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
Physical SSD/ATA/NVMe sanitization, filesystem-aware targeted file/folder
scrubbing, snapshots and hidden media areas are NOT implemented.
Secondary virtual-disk writes are gated by a path/serial policy and require
separate VirtualBox acceptance testing. Begin with the image experiment.

WSL validation: automated engine and native Qt tests, real FAT32 recovery,
hash comparisons, overwrite/read-back, and executable-level workflow tests.
VirtualBox has not been operated by the developer in this session.

Keep the whole EraseProof folder together; the _internal directory is needed.
""")

archive = output/f"EraseProof-Ubuntu-x86_64-{version}.tar.gz"
with tarfile.open(archive, "w:gz") as file:
    file.add(binary, arcname="EraseProof")

source = output/f"EraseProof-source-{version}.zip"
paths = [root/name for name in ("README.md", "pyproject.toml", ".gitattributes", ".gitignore")]
for directory in ("src", "tests", "scripts", "docs"):
    paths.extend(p for p in (root/directory).rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc")
with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as file:
    for path in sorted(paths):
        file.write(path, arcname=str(Path(f"EraseProof-source-{version}")/path.relative_to(root)))

checksums = []
for path in (archive, source):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(4*1024*1024), b""):
            digest.update(block)
    checksums.append(f"{digest.hexdigest()}  {path.name}")
    print(f"{path.name}: {path.stat().st_size:,} bytes")
(output/"SHA256SUMS").write_text("\n".join(checksums)+"\n")

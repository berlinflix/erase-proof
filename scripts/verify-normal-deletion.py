"""Real VFS deletion on disposable loop images, independent of the demo/eraser.

Root is needed only to mount our own newly created images. No existing disks
are selected. Ground-truth originals are never passed into the recovery call.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument("--filesystems", nargs="+", choices=["fat32", "ext4", "ntfs", "exfat"], default=["fat32", "ext4", "ntfs", "exfat"])
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
if os.geteuid() != 0:
    parser.error("Use sudo for isolated loop-image mounts. No physical disks are used.")
if os.environ.get("ERASEPROOF_NORMAL_DELETE_NAMESPACE") != "1":
    os.execvpe("unshare", ["unshare", "--mount", "--propagation", "private", sys.executable,
                           str(Path(__file__).resolve()), *sys.argv[1:]],
              {**os.environ, "ERASEPROOF_NORMAL_DELETE_NAMESPACE": "1"})
sys.path.insert(0, str(Path(__file__).resolve().parent.parent/"src"))
from eraseproof.cli import recover
from PIL import Image
from reportlab.pdfgen import canvas

args.output.mkdir(parents=True, exist_ok=False)
output = args.output.resolve()


def run(*arguments):
    result = subprocess.run(list(map(str, arguments)), capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError((result.stdout+result.stderr).decode(errors="replace")[-4000:])
    return result.stdout.decode().strip()


def hash_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(4*1024*1024), b""):
            digest.update(block)
    return digest.hexdigest()


def create_originals(root):
    root.mkdir()
    token = uuid.uuid4().hex
    image = Image.frombytes("RGB", (137, 113), os.urandom(137*113*3))
    image.save(root/f"photo {token[:8]}.png")
    image.save(root/f"camera-{token[8:16]}.jpg", quality=91)
    pdf = canvas.Canvas(str(root/f"notes-{token[16:24]}.pdf"))
    pdf.drawString(52, 750, "Independent normal deletion: "+token)
    pdf.drawString(52, 720, "Created outside EraseProof's demonstration.")
    pdf.save()
    with zipfile.ZipFile(root/f"bundle-{token[24:]}.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("fresh-data.bin", os.urandom(29023))
        archive.writestr("message.txt", token*900)
    (root/f"ordinary-{token[:6]}.txt").write_text((token+" user-created text\n")*153)
    # An unknown extension and no recognizable header exercises metadata recovery.
    (root/f"random-{token[-6:]}.custom").write_bytes(os.urandom(17317))
    return [{"name": p.name, "bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in sorted(root.iterdir())]


reports = []
for filesystem in args.filesystems:
    case = output/filesystem
    case.mkdir()
    originals = case/"originals"
    truth = create_originals(originals)
    with tempfile.TemporaryDirectory(prefix="eraseproof-vfs-", dir="/var/tmp") as temporary:
        managed = Path(temporary).resolve()
        image, mountpoint = managed/"volume.img", managed/"mnt"
        mountpoint.mkdir()
        with image.open("xb") as stream:
            stream.truncate(128*1024*1024)
        if filesystem == "fat32":
            run("mkfs.fat", "-F", "32", image)
        elif filesystem == "ext4":
            run("mkfs.ext4", "-q", "-F", image)
        elif filesystem == "ntfs":
            run("mkfs.ntfs", "-F", "-Q", image)
        else:
            run("mkfs.exfat", image)
        loop, mounted = None, False
        try:
            loop = run("losetup", "--find", "--show", image)
            association = json.loads(run("losetup", "--list", "--json", "--output", "NAME,BACK-FILE", loop))["loopdevices"][0]
            if Path(association["back-file"]).resolve() != image:
                raise RuntimeError("Loop backing identity mismatch; mount refused.")
            if filesystem == "ntfs":
                run("ntfs-3g", loop, mountpoint)
            elif filesystem == "exfat":
                run("mount.exfat-fuse", loop, mountpoint)
            else:
                run("mount", "-t", "vfat" if filesystem == "fat32" else "ext4", loop, mountpoint)
            mounted = True
            folder = mountpoint/("normal-user-folder-"+uuid.uuid4().hex[:6])
            folder.mkdir()
            for original in originals.iterdir():
                with original.open("rb") as source, (folder/original.name).open("xb") as destination:
                    shutil.copyfileobj(source, destination)
                    destination.flush()
                    os.fsync(destination.fileno())
            # Keep a separate live file to make this an actual populated volume.
            (mountpoint/"still-live.txt").write_text("This file remains allocated.")
            run("sync", "-f", mountpoint)
            for original in originals.iterdir():
                os.unlink(folder/original.name)  # Ordinary Linux VFS deletion.
            os.rmdir(folder)
            run("sync", "-f", mountpoint)
            run("umount", mountpoint)
            mounted = False
            run("losetup", "--detach", loop)
            loop = None
            before = hash_file(image)
            recovered = recover(image, case/"recovered")
            after = hash_file(image)
            if before != after:
                raise RuntimeError("Recovery modified the source image.")
            actual = {item["sha256"] for item in recovered["candidates"] if item["length"] > 0}
            matches = [{**entry, "recovered_exactly": entry["sha256"] in actual} for entry in truth]
            expected_formats = {".png", ".jpg", ".pdf", ".zip"}
            supported = [entry for entry in matches if Path(entry["name"]).suffix in expected_formats]
            if not all(entry["recovered_exactly"] for entry in supported):
                raise RuntimeError(filesystem+": an independently generated intact supported format was not recovered exactly.")
            if not all(entry["recovered_exactly"] for entry in matches):
                raise RuntimeError(filesystem+": generic metadata recovery failed for a fresh unknown-extension/text file.")
            report = {"filesystem": filesystem, "deletion": "os.unlink/os.rmdir through mounted Linux filesystem driver",
                      "predefined_demo_used": False, "references_given_to_recovery": False,
                      "exact_matches": sum(entry["recovered_exactly"] for entry in matches),
                      "original_count": len(truth), "files": matches, "warnings": recovered["warnings"],
                      "source_unchanged": before == after,
                      "physical_disks_used": 0}
            (case/"comparison.json").write_text(json.dumps(report, indent=2)+"\n")
            reports.append(report)
            print(json.dumps(report, indent=2), flush=True)
        finally:
            if mounted:
                run("umount", mountpoint)
            if loop:
                run("losetup", "--detach", loop)
(output/"normal-deletion-results.json").write_text(json.dumps(reports, indent=2)+"\n")

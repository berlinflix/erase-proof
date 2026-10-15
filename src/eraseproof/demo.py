"""Reproducible FAT32 experiment using genuine Linux filesystem tools."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import zipfile
import zlib

from .models import EraseProofError
from .runtime import system_environment


def png():
    def chunk(name, body):
        return struct.pack(">I", len(body)) + name + body + struct.pack(">I", zlib.crc32(name+body) & 0xffffffff)
    # A small, visible green checkerboard, valid and viewable after recovery.
    pixels = b"".join(b"\x00" + b"".join(bytes((52, 112, 81) if (x//8+y//8)%2 else (207, 225, 185)) for x in range(64)) for y in range(64))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 64, 64, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b"")


def pdf():
    stream = b"BT /F1 22 Tf 45 130 Td (EraseProof recovery experiment) Tj 0 -35 Td /F1 12 Tf (Recovered bytes should match the original SHA-256.) Tj ET"
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 500 210] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
               b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"]
    data, offsets = b"%PDF-1.4\n", []
    for i, obj in enumerate(objects, 1):
        offsets.append(len(data))
        data += f"{i} 0 obj\n".encode()+obj+b"\nendobj\n"
    xref = len(data)
    data += b"xref\n0 6\n0000000000 65535 f \n" + b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    return data + b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n"+str(xref).encode()+b"\n%%EOF"


def samples():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as file:
        file.writestr("experiment.txt", "EraseProof: recover these exact bytes after ordinary FAT32 deletion.\n")
    return {"REPORT.PDF": pdf(), "CAPTURE.PNG": png(), "ARCHIVE.ZIP": archive.getvalue(),
            "NOTES.TXT": b"Ordinary deletion removes directory references. File data may remain in unallocated clusters.\n"}


def run_tool(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=60, env=system_environment())
    if result.returncode:
        raise EraseProofError(result.stderr.strip() or result.stdout.strip() or f"{args[0]} failed")
    return result


def create(directory, delete_files=False):
    for tool in ("mkfs.fat", "mcopy", "mdel"):
        if not shutil.which(tool):
            raise EraseProofError(f"Missing {tool}. Install Ubuntu packages dosfstools and mtools.")
    root = Path(directory).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=False)
    originals = root / "originals"
    originals.mkdir()
    image = root / "experiment.img"
    with image.open("xb") as file:
        file.truncate(64 * 1024 * 1024)
    run_tool(["mkfs.fat", "-F", "32", "-n", "ERASEPROOF", str(image)])
    files = samples()
    for name, data in files.items():
        source = originals / name
        source.write_bytes(data)
        run_tool(["mcopy", "-i", str(image), str(source), f"::/{name}"])
    # Fingerprint the sectors that contain known file data, before deletion.
    image_data = image.read_bytes()
    hashes, locations = set(), {}
    for name, data in files.items():
        start = image_data.find(data)
        if start < 0:
            raise EraseProofError(f"Demo data was not written contiguously: {name}")
        locations[name] = start
        for at in range(start//512*512, start+len(data), 512):
            hashes.add(hashlib.sha256(image_data[at:at+512]).hexdigest())
    patterns = []
    for name in files:
        stem, ext = name.split(".")
        # FAT deletion replaces the first filename byte with E5; the residue remains.
        patterns.append((stem.ljust(8)+ext.ljust(3))[1:].encode().hex())
    manifest = {"schema": "eraseproof.demo.v1", "image": str(image), "size": image.stat().st_size,
                "files": [{"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "offset": locations[name]} for name, data in files.items()],
                "references": {"block_size": 512, "block_hashes": sorted(hashes), "metadata_patterns": patterns},
                "deleted": False}
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2)+"\n")
    if delete_files:
        return delete(root)
    return manifest


def delete(directory):
    root = Path(directory).expanduser().resolve()
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    image = root / "experiment.img"
    if manifest.get("schema") != "eraseproof.demo.v1" or str(image) != manifest.get("image"):
        raise EraseProofError("This is not an EraseProof demo directory.")
    if manifest["deleted"]:
        raise EraseProofError("Demo files are already deleted. Create a new experiment to reset.")
    for item in manifest["files"]:
        run_tool(["mdel", "-i", str(image), f"::/{item['name']}"])
    manifest["deleted"] = True
    manifest_path.write_text(json.dumps(manifest, indent=2)+"\n")
    return manifest

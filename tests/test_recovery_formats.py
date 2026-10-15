import gzip
import hashlib
import io
from pathlib import Path
import sqlite3
import struct
import subprocess
import tarfile
import wave
import zlib
import shutil
from PIL import Image
import pytest
from eraseproof import carve, demo
from eraseproof.independent import attack
from eraseproof.cli import recover
from eraseproof.partitions import inspect
from eraseproof.models import EraseProofError


def test_additional_containers_are_extracted_with_exact_bytes(tmp_path):
    files = {}
    for kind in ("GIF", "BMP", "JPEG"):
        buf = io.BytesIO()
        Image.new("RGB", (16, 16), (31, 121, 63)).save(buf, kind)
        files[kind] = buf.getvalue()
    audio = io.BytesIO()
    with wave.open(audio, "wb") as stream:
        stream.setnchannels(1)
        stream.setsampwidth(2)
        stream.setframerate(8000)
        stream.writeframes(bytes(160))
    files["WAV"] = audio.getvalue()
    files["GZIP"] = gzip.compress(b"recovery evidence"*100, mtime=0)
    files["RTF"] = b"{\\rtf1\\ansi Recovered {nested} text.}"
    sqlite = tmp_path/"original.sqlite"
    with sqlite3.connect(sqlite) as db:
        db.execute("CREATE TABLE evidence(value TEXT)")
        db.execute("INSERT INTO evidence VALUES ('recover me')")
    files["SQLITE"] = sqlite.read_bytes()
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as file:
        info = tarfile.TarInfo("evidence.txt")
        info.size = 8
        file.addfile(info, io.BytesIO(b"evidence"))
    # Tar logical boundary is two zero blocks; tar's 10 KiB transport padding
    # isn't part of that logical extent.
    files["TAR"] = archive.getvalue()[:2048]
    cfile = tmp_path/"main.c"
    cfile.write_text("int main(void){return 0;}")
    subprocess.run(["gcc", str(cfile), "-o", str(tmp_path/"original.elf")], check=True)
    files["ELF"] = (tmp_path/"original.elf").read_bytes()
    image = tmp_path/"formats.img"
    data = bytearray(1024)
    for payload in files.values():
        data.extend(payload)
        data.extend(bytes(1024))
    image.write_bytes(data)
    found = carve.scan(image)
    assert set(files) <= {c.file_type for c in found}
    for candidate in found:
        recovered = carve.extract(image, candidate, tmp_path/"out")
        if candidate.file_type in files:
            assert Path(recovered.output).read_bytes() == files[candidate.file_type]


def test_png_chunk_gap_reconstruction_recovers_original_hash(tmp_path):
    payload = demo.png()
    # First IHDR ends at byte 33; insert an unrelated gap before IDAT.
    image = tmp_path/"fragmented.img"
    image.write_bytes(bytes(512)+payload[:33]+b"GAP!"*128+payload[33:]+bytes(512))
    assert not carve.scan(image)
    found = carve.scan(image, fragmented=True)
    assert len(found) == 1 and len(found[0].segments) == 2
    recovered = carve.extract(image, found[0], tmp_path/"recovered")
    assert recovered.sha256 == hashlib.sha256(payload).hexdigest()
    assert recovered.method == "png-gap-reconstruction"


def test_native_and_independent_attack_results_before_and_after_wipe(tmp_path):
    manifest = demo.create(tmp_path/"experiment", delete_files=True)
    before = attack(manifest["image"], tmp_path/"before", timeout=60)
    assert before["complete"]
    assert next(t for t in before["tools"] if t["tool"] == "Sleuth Kit")["recovered_files"] == 4
    assert next(t for t in before["tools"] if t["tool"] == "PhotoRec")["recovered_files"] >= 1
    path = Path(manifest["image"])
    with path.open("r+b") as stream:
        stream.write(bytes(path.stat().st_size))
    after = attack(path, tmp_path/"after", timeout=60)
    assert not after["complete"]  # No filesystem parser success is fabricated after the filesystem is wiped.
    assert after["recovered_files"] == 0
    assert next(t for t in after["tools"] if t["tool"] == "Sleuth Kit")["status"] == "filesystem-unrecognized-or-error"


@pytest.mark.skipif(not shutil.which("ffmpeg") or not shutil.which("7z"), reason="ffmpeg and 7z generate real media fixtures")
def test_real_audio_video_and_7z_recovery(tmp_path):
    payloads = {}
    for family, suffix, arguments in (
        ("OGG", "ogg", ["-f", "lavfi", "-i", "sine=frequency=440:duration=0.08", "-c:a", "libvorbis"]),
        ("MP4", "mp4", ["-f", "lavfi", "-i", "color=c=green:s=32x32:d=0.08", "-c:v", "mpeg4"]),
        ("AVI", "avi", ["-f", "lavfi", "-i", "color=c=green:s=32x32:d=0.08", "-c:v", "mpeg4"]),
    ):
        path = tmp_path/("original."+suffix)
        subprocess.run(["ffmpeg", "-v", "error", *arguments, str(path)], check=True)
        payloads[family] = path.read_bytes()
    note = tmp_path/"note.txt"
    note.write_text("Independent archive fixture")
    archive = tmp_path/"original.7z"
    subprocess.run(["7z", "a", str(archive), str(note)], check=True, stdout=subprocess.DEVNULL)
    payloads["7Z"] = archive.read_bytes()
    image = tmp_path/"multimedia.img"
    image.write_bytes(bytes(512)+b"".join(value+bytes(1024) for value in payloads.values()))
    found = carve.scan(image)
    assert {c.file_type for c in found} == set(payloads)
    for candidate in found:
        extracted = carve.extract(image, candidate, tmp_path/"recovered")
        assert Path(extracted.output).read_bytes() == payloads[candidate.file_type]
    corrupt = bytearray(payloads["OGG"])
    corrupt[30] ^= 1
    image.write_bytes(corrupt)
    assert not carve.scan(image)


def test_mbr_offset_recovers_real_deleted_files(tmp_path):
    manifest = demo.create(tmp_path/"fixture", delete_files=True)
    disk = tmp_path/"partitioned.img"
    mbr = bytearray(2048*512)
    mbr[450] = 0x0c
    struct.pack_into("<II", mbr, 454, 2048, Path(manifest["image"]).stat().st_size//512)
    mbr[510:512] = b"\x55\xaa"
    with disk.open("wb") as output, open(manifest["image"], "rb") as volume:
        output.write(mbr)
        shutil.copyfileobj(volume, output)
    report = inspect(disk)
    assert report["table"] == "MBR" and report["partitions"][0]["tsk_offset"] == 2048
    recovered = recover(disk, tmp_path/"out", "deleted", report["partitions"][0]["tsk_offset"])
    assert {c["sha256"] for c in recovered["candidates"]} == {f["sha256"] for f in manifest["files"]}
    with disk.open("r+b") as stream:
        stream.seek(454)
        stream.write(struct.pack("<I", 0xfffffff0))
    with pytest.raises(EraseProofError, match="bounds"):
        inspect(disk)


def test_gpt_checksums_reject_corrupt_partition_tables(tmp_path):
    image = tmp_path/"gpt.img"
    data = bytearray(512*128)
    data[450] = 0xee
    struct.pack_into("<II", data, 454, 1, 127)
    data[510:512] = b"\x55\xaa"
    array = bytearray(128*4)
    array[:16] = bytes(range(1, 17))
    struct.pack_into("<QQ", array, 32, 40, 80)
    array[56:64] = "Data".encode("utf-16-le")
    data[1024:1024+len(array)] = array
    header = bytearray(92)
    header[:8] = b"EFI PART"
    struct.pack_into("<III", header, 8, 0x10000, 92, 0)
    struct.pack_into("<QQQQ", header, 24, 1, 127, 34, 100)
    struct.pack_into("<QIII", header, 72, 2, 4, 128, zlib.crc32(array))
    struct.pack_into("<I", header, 16, zlib.crc32(header))
    data[512:604] = header
    image.write_bytes(data)
    assert inspect(image)["partitions"][0]["name"] == "Data"
    data[1024+70] ^= 1
    image.write_bytes(data)
    with pytest.raises(EraseProofError, match="entry-array checksum"):
        inspect(image)

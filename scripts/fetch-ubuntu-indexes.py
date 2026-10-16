"""Fetch live-build package indexes in verified byte ranges from Ubuntu.

Each InRelease signature is checked against Ubuntu's archive keyring. Both
compressed and decompressed hashes must match its SHA-256 entries. This only
populates a managed build's apt cache, never the installed host package lists.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.request


root = Path(sys.argv[1]).resolve()
if root.name != "rootfs" or not (root.parent/"ERASEPROOF_BUILD_ROOT").is_file() or (root.parent/"ERASEPROOF_BUILD_ROOT").read_text().strip() != str(root.parent):
    raise SystemExit("Requires a managed EraseProof live build root")
lists = root/"var/lib/apt/lists"
jobs, indexes = [], []
for host, suite in (("archive.ubuntu.com", "noble"), ("archive.ubuntu.com", "noble-updates"), ("security.ubuntu.com", "noble-security")):
    prefix = f"{host}_ubuntu_dists_{suite}_"
    destination = lists/(prefix+"InRelease")
    source = destination if destination.exists() else lists/"partial"/destination.name
    if not source.exists():
        source.write_bytes(urllib.request.urlopen(f"https://{host}/ubuntu/dists/{suite}/InRelease", timeout=90).read())
    subprocess.run(["gpgv", "--keyring", "/usr/share/keyrings/ubuntu-archive-keyring.gpg", str(source)], capture_output=True, check=True)
    entries, in_sha = {}, False
    for line in source.read_text().splitlines():
        if not line.startswith(" "):
            in_sha = line == "SHA256:"
        elif in_sha:
            sha, size, name = line.split()
            entries[name] = (sha, int(size))
    if source != destination:
        shutil.copyfile(source, destination)
    for component in ("main", "universe"):
        name = f"{component}/binary-amd64/Packages"
        compressed_sha, compressed_size = entries[name+".xz"]
        raw_sha, raw_size = entries[name]
        path = lists/(prefix+component+"_binary-amd64_Packages")
        if path.exists() and path.stat().st_size == raw_size and hashlib.sha256(path.read_bytes()).hexdigest() == raw_sha:
            continue
        if compressed_size > 128*1024*1024 or raw_size > 1024**3:
            raise RuntimeError("Package index exceeds build limits")
        data = bytearray(compressed_size)
        item = {"path": path, "data": data, "sha": compressed_sha, "raw_sha": raw_sha, "raw_size": raw_size}
        indexes.append(item)
        url = f"https://{host}/ubuntu/dists/{suite}/{component}/binary-amd64/by-hash/SHA256/{compressed_sha}"
        for start in range(0, compressed_size, 1024*1024):
            end = min(compressed_size, start+1024*1024)-1
            jobs.append((item, url, start, end))


def fetch(job):
    item, url, start, end = job
    request = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
    with urllib.request.urlopen(request, timeout=120) as response:
        if response.status != 206 or not response.headers.get("Content-Range", "").startswith(f"bytes {start}-{end}/"):
            raise RuntimeError("Ubuntu mirror did not honor the requested byte range")
        data = response.read(end-start+2)
    if len(data) != end-start+1:
        raise RuntimeError("Short or oversized package index range")
    return item, start, data


print(f"Fetching {len(indexes)} signed package indexes in {len(jobs)} bounded ranges", flush=True)
with ThreadPoolExecutor(max_workers=12) as pool:
    for future in as_completed([pool.submit(fetch, job) for job in jobs]):
        item, start, data = future.result()
        item["data"][start:start+len(data)] = data
for item in indexes:
    if hashlib.sha256(item["data"]).hexdigest() != item["sha"]:
        raise RuntimeError("Compressed package index SHA-256 mismatch")
    fd, temporary = tempfile.mkstemp(prefix=".eraseproof-index-", dir=lists)
    try:
        digest, size = hashlib.sha256(), 0
        import io
        with os.fdopen(fd, "wb") as output, lzma.LZMAFile(io.BytesIO(item["data"])) as source:
            while data := source.read(1024*1024):
                output.write(data)
                digest.update(data)
                size += len(data)
                if size > item["raw_size"]:
                    raise RuntimeError("Expanded package index exceeds signed size")
        if size != item["raw_size"] or digest.hexdigest() != item["raw_sha"]:
            raise RuntimeError("Expanded package index checksum/size mismatch")
        os.chmod(temporary, 0o644)
        os.replace(temporary, item["path"])
        print("Verified "+item["path"].name, flush=True)
    finally:
        Path(temporary).unlink(missing_ok=True)
(root/"etc/apt/apt.conf.d/99eraseproof-build").write_text('Acquire::Languages "none";\n')
(root/"etc/apt/sources.list").write_text('deb https://archive.ubuntu.com/ubuntu noble main universe\ndeb https://archive.ubuntu.com/ubuntu noble-updates main universe\ndeb https://security.ubuntu.com/ubuntu noble-security main universe\n')

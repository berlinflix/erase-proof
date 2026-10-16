"""Prefetch signed-index Ubuntu bootstrap packages into a managed live build.

This is optional network acceleration; debootstrap/apt still verify and install
the packages. No installed host package or physical device is modified.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.request
import shlex
import urllib.parse
import time


def bootstrap(root):
    lists = root/"var/lib/apt/lists"
    prefix = "archive.ubuntu.com_ubuntu_dists_noble_"
    release = lists/(prefix+"Release")
    packages = lists/(prefix+"main_binary-amd64_Packages")
    subprocess.run(["gpgv", "--keyring", "/usr/share/keyrings/ubuntu-archive-keyring.gpg", str(release)+".gpg", str(release)], check=True, capture_output=True)
    sha = None
    in_sha256 = False
    for line in release.read_text().splitlines():
        if not line.startswith(" "):
            in_sha256 = line == "SHA256:"
        elif in_sha256:
            fields = line.split()
            if len(fields) == 3 and fields[2] == "main/binary-amd64/Packages":
                sha = fields[0]
    if not sha or hashlib.sha256(packages.read_bytes()).hexdigest() != sha:
        raise RuntimeError("Signed Ubuntu package index checksum failed or download is incomplete.")
    index = {}
    for stanza in packages.read_text().split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            if line and not line.startswith(" ") and ": " in line:
                key, value = line.split(": ", 1)
                fields[key] = value
        if "Package" in fields:
            index[fields["Package"]] = fields
    pending = [name for name, fields in index.items() if fields.get("Priority") == "required"]+["apt", "ca-certificates"]
    wanted = set()
    while pending:
        name = pending.pop()
        if name in wanted or name not in index:
            continue
        wanted.add(name)
        fields = index[name]
        for dependency in (fields.get("Depends", "")+","+fields.get("Pre-Depends", "")).split(","):
            for alternative in dependency.split("|"):
                match = re.match(r"\s*([a-z0-9+.-]+)", alternative)
                if match and match[1] in index:
                    pending.append(match[1])
                    break
    cache = root/"var/cache/apt/archives"
    cache.mkdir(parents=True, exist_ok=True)
    def download(name):
        fields = index[name]
        filename = fields["Filename"]
        if not filename.startswith("pool/") or ".." in Path(filename).parts:
            raise RuntimeError("Unsafe package index path")
        destination = cache/Path(filename).name
        expected = fields["SHA256"]
        if destination.exists() and hashlib.sha256(destination.read_bytes()).hexdigest() == expected:
            return False
        fd, temporary = tempfile.mkstemp(prefix=".eraseproof-fetch-", dir=cache)
        try:
            digest = hashlib.sha256()
            length = 0
            with os.fdopen(fd, "wb") as output, urllib.request.urlopen("https://archive.ubuntu.com/ubuntu/"+filename, timeout=90) as response:
                while data := response.read(256*1024):
                    output.write(data)
                    length += len(data)
                    digest.update(data)
            if length != int(fields["Size"]) or digest.hexdigest() != expected:
                raise RuntimeError("Package hash/size mismatch: "+name)
            os.replace(temporary, destination)
            return True
        finally:
            Path(temporary).unlink(missing_ok=True)
    total = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        for future in as_completed([pool.submit(download, name) for name in sorted(wanted)]):
            total += bool(future.result())
    print(f"Verified bootstrap prefetch: {total} new packages; {len(wanted)} indexed dependencies.", flush=True)


def apt(root):
    names = Path(__file__).with_name("live-packages.txt").read_text().split()
    result = subprocess.run(["chroot", str(root), "apt-get", "--print-uris", "--download-only", "--yes", "--no-install-recommends", "install", *names], capture_output=True, text=True, check=True)
    cache = root/"var/cache/apt/archives"
    packages = []
    for line in result.stdout.splitlines():
        if not line.startswith("'"):
            continue
        url, name, size, checksum = shlex.split(line)
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in ("archive.ubuntu.com", "security.ubuntu.com") or Path(name).name != name or not name.endswith(".deb"):
            raise RuntimeError("Refused unexpected package URL or cache path")
        algorithm, expected = checksum.split(":", 1)
        algorithm = {"MD5Sum": "md5", "SHA256": "sha256", "SHA512": "sha512"}[algorithm]
        packages.append((url, name, int(size), algorithm, expected))
    print(f"Prefetching {len(packages)} APT packages ({sum(p[2] for p in packages)/1024**2:.1f} MiB); APT independently revalidates them.", flush=True)
    jobs = []
    for url, name, size, algorithm, expected in packages:
        if size > 256*1024*1024:
            raise RuntimeError("A package exceeds the per-package build download limit")
        pieces = [(start, min(start+1024*1024, size)-1) for start in range(0, size, 1024*1024)]
        item = {"name": name, "data": bytearray(size), "remaining": len(pieces), "algorithm": algorithm, "hash": expected}
        jobs.extend((item, url, start, end, size) for start, end in pieces)
    def download(job):
        item, url, start, end, size = job
        error = None
        for attempt in range(3):
            try:
                request = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
                with urllib.request.urlopen(request, timeout=60) as response:
                    if not (response.status == 206 and response.headers.get("Content-Range", "").startswith(f"bytes {start}-{end}/") or response.status == 200 and start == 0 and end == size-1):
                        raise RuntimeError("Mirror did not honor package byte range")
                    data = response.read(end-start+2)
                if len(data) != end-start+1:
                    raise RuntimeError("Short/oversized package byte range")
                return item, start, data
            except Exception as exception:
                error = exception
                time.sleep(.25*(attempt+1))
        raise RuntimeError(f"Download failed after retries: {item['name']}: {error}")
    completed, received, last_report, failures = 0, 0, 0, []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for future in as_completed([pool.submit(download, job) for job in jobs]):
            try:
                item, start, data = future.result()
                received += len(data)
                if received-last_report >= 16*1024*1024:
                    print(f"Downloaded {received/1024**2:.1f} MiB in bounded ranges; {completed} complete package hashes verified", flush=True)
                    last_report = received
                item["data"][start:start+len(data)] = data
                item["remaining"] -= 1
                if item["remaining"]:
                    continue
                if hashlib.new(item["algorithm"], item["data"]).hexdigest() != item["hash"]:
                    raise RuntimeError("Package hash mismatch: "+item["name"])
                fd, temporary = tempfile.mkstemp(prefix=".eraseproof-fetch-", dir=cache)
                try:
                    with os.fdopen(fd, "wb") as output:
                        output.write(item["data"])
                    os.replace(temporary, cache/item["name"])
                finally:
                    Path(temporary).unlink(missing_ok=True)
                item["data"] = None
                completed += 1
                if completed % 10 == 0 or completed == len(packages):
                    print(f"Verified {completed}/{len(packages)} packages", flush=True)
            except Exception as error:
                failures.append(str(error))
                print(str(error), file=sys.stderr, flush=True)
    if failures:
        raise RuntimeError("Build package prefetch incomplete; verified cache is preserved for --resume. "+failures[0])


if __name__ == "__main__":
    root = Path(sys.argv[1]).resolve()
    marker = root.parent/"ERASEPROOF_BUILD_ROOT"
    if root.name != "rootfs" or not marker.is_file() or marker.read_text().strip() != str(root.parent):
        raise SystemExit("Requires an existing managed EraseProof live build root.")
    if "--apt" in sys.argv[2:]:
        apt(root)
    else:
        bootstrap(root)

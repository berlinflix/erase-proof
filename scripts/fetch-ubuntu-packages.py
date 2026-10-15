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
    print(f"Prefetching {len(packages)} APT packages ({sum(p[2] for p in packages)/1024**2:.1f} MiB), eight connections; APT will independently revalidate them.", flush=True)
    def download(package):
        url, name, size, algorithm, expected = package
        destination = cache/name
        if destination.is_file() and destination.stat().st_size == size and hashlib.new(algorithm, destination.read_bytes()).hexdigest() == expected:
            return
        fd, temporary = tempfile.mkstemp(prefix=".eraseproof-fetch-", dir=cache)
        try:
            digest, length = hashlib.new(algorithm), 0
            with os.fdopen(fd, "wb") as output, urllib.request.urlopen(url, timeout=120) as response:
                while data := response.read(256*1024):
                    output.write(data)
                    length += len(data)
                    digest.update(data)
            if length != size or digest.hexdigest() != expected:
                raise RuntimeError("APT package checksum/size mismatch: "+name)
            os.replace(temporary, destination)
        finally:
            Path(temporary).unlink(missing_ok=True)
    with ThreadPoolExecutor(max_workers=8) as pool:
        for index, future in enumerate(as_completed([pool.submit(download, package) for package in packages]), 1):
            future.result()
            if index % 25 == 0 or index == len(packages):
                print(f"Verified {index}/{len(packages)} APT downloads", flush=True)


if __name__ == "__main__":
    root = Path(sys.argv[1]).resolve()
    marker = root.parent/"ERASEPROOF_BUILD_ROOT"
    if root.name != "rootfs" or not marker.is_file() or marker.read_text().strip() != str(root.parent):
        raise SystemExit("Requires an existing managed EraseProof live build root.")
    if "--apt" in sys.argv[2:]:
        apt(root)
    else:
        bootstrap(root)

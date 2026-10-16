"""Read-only, bounded journal-version recovery for regular ext4 volume images."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

from .carve import checkpoint
from .models import Candidate, EraseProofError
from .runtime import system_environment
from .targets import describe, open_target


def applicable(path, sector_offset=0):
    if sector_offset:
        return False
    with open_target(path) as stream:
        stream.seek(1080)
        return stream.read(2) == b"\x53\xef"


def recover(path, output_dir, progress=None, cancel=None):
    info = describe(path)
    if info["kind"] != "image":
        raise EraseProofError("Journal recovery requires an offline regular volume image.")
    helper = Path(__file__).parent/"resources"/"native"/"eraseproof-ext4-journal"
    if not helper.is_file():
        raise EraseProofError("Build the C journal reader with scripts/build-native.sh.")
    associated = subprocess.run(["losetup", "--associated", info["path"]], capture_output=True,
                                text=True, timeout=15, env=system_environment())
    if associated.returncode or associated.stdout.strip():
        raise EraseProofError("Journal recovery requires an unattached offline image; detach its loop devices first.")
    root = Path(output_dir).resolve()
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    checkpoint(cancel)
    # prlimit avoids a preexec_fn in a threaded Qt process. The native helper
    # accepts only a read-only regular-image descriptor and numeric output names.
    with open_target(path) as source:
        command = ["prlimit", "--as=1073741824", "--cpu=120", "--core=0", "--",
                   str(helper), f"/proc/self/fd/{source.fileno()}", str(root)]
        try:
            result = subprocess.run(command, pass_fds=(source.fileno(),), capture_output=True,
                                    timeout=150, env=system_environment())
        except subprocess.TimeoutExpired:
            raise EraseProofError("Journal reader timed out; unreported partial outputs are not counted as recovered files.") from None
    (root/"reader.stdout.log").write_bytes(result.stdout)
    (root/"reader.stderr.log").write_bytes(result.stderr)
    if result.returncode:
        raise EraseProofError("Journal reader failed: "+result.stderr.decode(errors="replace")[-2000:])
    candidates, summary = [], None
    for line in result.stdout.splitlines():
        checkpoint(cancel)
        entry = json.loads(line)
        if entry.get("summary"):
            summary = entry
            continue
        name = entry["output"]
        if Path(name).name != name or not name.startswith("journal-inode-"):
            raise EraseProofError("Unexpected journal output name.")
        output = root/name
        digest = hashlib.sha256()
        with output.open("rb") as stream:
            for block in iter(lambda: stream.read(4*1024*1024), b""):
                digest.update(block)
        if output.stat().st_size != entry["bytes"]:
            raise EraseProofError("Journal output size changed.")
        candidate = Candidate(0, entry["bytes"], "FILE", 60,
                              ["Recovered from a historical inode stored in a committed journal transaction",
                               "Inode checksum verified" if entry["inode_checksum_checked"] else "Filesystem has no inode checksums",
                               "Historical data blocks may have been reused; compare original hashes when available. Original name is unavailable."],
                              name=name, method="ext4-journal-inode", inode=str(entry["inode"]),
                              output=str(output), sha256=digest.hexdigest())
        candidates.append(candidate)
    if summary is None:
        raise EraseProofError("Journal reader returned no completion summary.")
    (root/"journal.json").write_text(json.dumps(summary, indent=2)+"\n")
    if progress:
        progress("Journal recovery", 1, f"Recovered {len(candidates)} historical inode candidates")
    return candidates, summary

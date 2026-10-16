"""Normalize distribution modes when source files live on Windows/DrvFS."""
import os
from pathlib import Path
import sys


def file_mode(path):
    path = Path(path)
    with path.open("rb") as source:
        executable = source.read(4) == b"\x7fELF"
    return 0o755 if executable or path.suffix == ".sh" else 0o644


if __name__ == "__main__":
    root = Path(sys.argv[1]).resolve()
    if not (root/"EraseProof").is_file() or not (root/"_internal").is_dir():
        raise SystemExit("Requires a built EraseProof application directory")
    for path in [root, *root.rglob("*")]:
        if path.is_symlink():
            if "--root-owner" in sys.argv[2:]:
                os.chown(path, 0, 0, follow_symlinks=False)
            continue
        if path.is_dir():
            path.chmod(0o755)
        elif path.is_file():
            path.chmod(file_mode(path))
        if "--root-owner" in sys.argv[2:]:
            os.chown(path, 0, 0, follow_symlinks=False)
    print("Normalized native bundle permissions: "+str(root))

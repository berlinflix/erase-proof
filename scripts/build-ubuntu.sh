#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
python="${ERASEPROOF_BUILD_PYTHON:-$root/.venv/bin/python}"
"$python" -m pip install pyinstaller
"$python" -m PyInstaller --noconfirm --clean --name EraseProof --windowed \
  --add-data "$root/src/eraseproof/resources:eraseproof/resources" \
  --paths "$root/src" --distpath "$root/dist" --workpath "${TMPDIR:-/tmp}/eraseproof-pyinstaller" \
  --specpath "${TMPDIR:-/tmp}" "$root/scripts/desktop-entry.py"
printf '%s\n' "Built native Linux application: $root/dist/EraseProof/EraseProof"

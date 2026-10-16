#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
python="${ERASEPROOF_BUILD_PYTHON:-$root/.venv/bin/python}"
cd "$root"
bash "$root/scripts/build-native.sh"
PYTHONPATH=src QT_QPA_PLATFORM=offscreen "$python" -m pytest -q
ERASEPROOF_BUILD_PYTHON="$python" bash "$root/scripts/build-ubuntu.sh"
python3 "$root/scripts/verify-frozen.py" "$root/dist/EraseProof/EraseProof"
"$python" "$root/scripts/package-release.py"
"$python" "$root/scripts/verify-package.py"

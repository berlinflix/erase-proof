#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ! -x "$root/.venv/bin/eraseproof-desktop" ]]; then
  echo "First run: bash scripts/setup-ubuntu.sh" >&2
  exit 1
fi
exec "$root/.venv/bin/eraseproof-desktop"

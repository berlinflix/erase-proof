#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)" != Linux ]]; then
  echo "Run this inside Ubuntu (VirtualBox or WSL)." >&2
  exit 1
fi
echo "Installing the Ubuntu runtime and real forensic/demo tools."
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip xdg-utils dosfstools mtools sleuthkit testdisk nvme-cli hdparm cryptsetup-bin \
  libegl1 libopengl0 libxcb-cursor0 libxkbcommon-x11-0 libxcb-xinerama0 \
  libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0 libdbus-1-3 fonts-dejavu-core
python3 -m venv "$root/.venv"
"$root/.venv/bin/python" -m pip install --upgrade pip
"$root/.venv/bin/python" -m pip install "$root[desktop,test]"
mkdir -p "$HOME/.local/share/applications"
python3 - "$root" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
entry = Path.home()/'.local/share/applications/eraseproof.desktop'
entry.write_text('[Desktop Entry]\nType=Application\nName=EraseProof\nComment=Native recovery and verified erasure workbench\nExec="'+str(root/'.venv/bin/eraseproof-desktop')+'"\nTerminal=false\nCategories=System;Utility;\n')
PY
echo "Ready. Launch EraseProof from Ubuntu's app menu, or run:"
printf '%s\n' "  $root/.venv/bin/eraseproof-desktop"

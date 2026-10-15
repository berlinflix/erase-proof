#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
sudo apt-get update
sudo apt-get install -y dosfstools mtools sleuthkit testdisk nvme-cli hdparm cryptsetup-bin libegl1 libopengl0 libxcb-cursor0 \
  libxkbcommon-x11-0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0 \
  libxcb-xinerama0 libdbus-1-3 fonts-dejavu-core
mkdir -p "$HOME/.local/share/applications"
python3 - "$root" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1]).resolve()
(Path.home()/'.local/share/applications/eraseproof.desktop').write_text(
    '[Desktop Entry]\nType=Application\nName=EraseProof\nComment=Native Linux recovery and verified erasure\nExec="'+str(root/'EraseProof')+'"\nTerminal=false\nCategories=System;Utility;\n')
PY
chmod +x "$root/EraseProof"
printf '%s\n' "Ready. Launch EraseProof from Ubuntu's applications menu or: $root/EraseProof"

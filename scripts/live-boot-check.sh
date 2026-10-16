#!/bin/sh
# Runs only when eraseproof.selftest=1 is explicitly supplied at boot.
# Every write is to new temporary image/evidence files. No device path is used.
set -eu
app=/opt/eraseproof/EraseProof
work="$(mktemp -d /tmp/eraseproof-live-check.XXXXXXXX)"
echo "ERASEPROOF_BOOT_CHECK_START $work"
"$app" --cli doctor > "$work/doctor.json"
"$app" --cli demo create "$work/demo" --deleted > "$work/demo.json"
"$app" --cli recover "$work/demo/experiment.img" --output "$work/recovered" > "$work/recovery.json"
python3 - "$work" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
originals = {f['sha256'] for f in json.loads((root/'demo/manifest.json').read_text())['files']}
recovered = {f['sha256'] for f in json.loads((root/'recovery.json').read_text())['candidates'] if f['method'] == 'sleuthkit-metadata'}
assert originals == recovered and len(originals) == 4
PY
"$app" --cli erase "$work/demo/experiment.img" --confirm experiment.img --references "$work/demo/manifest.json" --case "$work/evidence" > "$work/erasure.json"
for record in "$work/evidence/"*.epcert.json; do
  "$app" --cli record "$record" > "$work/signature.json"
  "$app" --cli pdf "$record" --output "$work/report.pdf" > "$work/pdf.json"
done
"$app" --cli pdf-record "$work/report.pdf" > "$work/pdf-record.json"
"$app" --cli audit "$work/evidence" > "$work/audit.json"
# Exercise the shipped binary against Noble's actual filesystem tools as well
# as the basic whole-image demonstration. This creates temporary images only.
python3 /usr/local/lib/eraseproof-verify-frozen.py "$app" > "$work/frozen-workflow.json"
echo ERASEPROOF_BOOT_CHECK_PASS

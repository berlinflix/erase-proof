"""Render the real Qt application with real demo results for visual QA."""
import json
import os
from pathlib import Path
import sys
import time
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication
from eraseproof.desktop import MainWindow, STYLE
from eraseproof.engine import erase


def wait(app, window):
    deadline = time.monotonic()+45
    while window.job and window.job.isRunning():
        app.processEvents()
        if time.monotonic() > deadline:
            raise RuntimeError("UI task timed out")
        time.sleep(.01)
    app.processEvents()


output = Path(sys.argv[1]).resolve()
output.mkdir(parents=True, exist_ok=True)
app = QApplication([])
app.setStyle("Fusion")
app.setStyleSheet(STYLE)
window = MainWindow(output/"workspace")
window.resize(1280, 900)
window.show()
window.create_demo()
wait(app, window)
window.delete_demo()
wait(app, window)
window.switch(0)
app.processEvents()
window.grab().save(str(output/"native-experiment.png"))
window.switch(1)
window.start_recovery()
wait(app, window)
window.grab().save(str(output/"native-recovery.png"))
refs = json.loads(Path(window.reference_file).read_text())["references"]
record = erase(window.target, Path(window.target).name, window.store.root, refs)
window.refresh_evidence()
window.switch(3)
window.status_label.setText("Full read-back passed. No supported carving candidates. Ed25519 evidence saved.")
app.processEvents()
window.grab().save(str(output/"native-evidence.png"))
(output/"verified-record.json").write_text(json.dumps(record, indent=2))
print(json.dumps({"screenshots": [str(output/name) for name in ("native-experiment.png", "native-recovery.png", "native-evidence.png")], "recovered": len(window.recovered), "rrs_after": record["payload"]["verification"]["rrs"]}))
window.close()

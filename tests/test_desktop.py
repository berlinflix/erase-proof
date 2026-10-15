import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import time
from pathlib import Path
import pytest

pytest.importorskip("PySide6")
from PySide6.QtWidgets import QApplication
from eraseproof.desktop import MainWindow, STYLE


def wait_for_job(app, window):
    deadline = time.monotonic()+30
    while window.job and window.job.isRunning():
        app.processEvents()
        if time.monotonic() > deadline:
            window.job.requestInterruption()
            window.job.wait(10000)
            pytest.fail("Native desktop job timed out")
        time.sleep(.01)
    app.processEvents()


def test_native_window_pages_and_background_recovery(tmp_path):
    application = QApplication.instance() or QApplication([])
    application.setStyle("Fusion")
    application.setStyleSheet(STYLE)
    window = MainWindow(tmp_path/"native-workspace")
    window.show()
    application.processEvents()
    assert window.stack.count() == 5
    for index in range(5):
        window.switch(index)
        assert window.stack.currentIndex() == index
        assert window.nav[index].isChecked()
    window.switch(0)
    window.create_demo()
    wait_for_job(application, window)
    assert window.originals.rowCount() == 4
    window.delete_demo()
    wait_for_job(application, window)
    assert "Ordinary deletion completed" in window.demo_status.text()
    window.switch(1)
    window.recovery_destination.setText(str(tmp_path/"chosen-output"))
    window.start_recovery()
    wait_for_job(application, window)
    assert window.results.rowCount() == 7
    assert all(Path(candidate["output"]).exists() for candidate in window.recovered)
    assert all(str(tmp_path/"chosen-output") in candidate["output"] for candidate in window.recovered)
    assert window.cancel_button.isEnabled() is False
    window.close()

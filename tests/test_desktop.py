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
    assert window.stack.count() == 7
    for index in range(7):
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


def test_native_window_supports_a_small_vm_display(tmp_path):
    application = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path/"small-workspace")
    window.resize(1000, 720)
    window.show()
    application.processEvents()
    assert window.width() <= 1000 and window.height() <= 720
    window.switch(1)
    application.processEvents()
    assert window.page_scroll.verticalScrollBar().maximum() > 0
    window.page_scroll.verticalScrollBar().setValue(window.page_scroll.verticalScrollBar().maximum())
    application.processEvents()
    assert window.page_scroll.verticalScrollBar().value() > 0
    window.close()


@pytest.mark.parametrize("filesystem", ["FAT32", "ext4", "NTFS", "exFAT"])
def test_native_offline_targeted_workflow(tmp_path, monkeypatch, filesystem):
    if filesystem == "ext4":
        from test_ext4 import fixture
    elif filesystem == "NTFS":
        from test_ntfs import fixture
    elif filesystem == "exFAT":
        from test_exfat import fixture
    else:
        from test_fat32 import fixture
    from PySide6.QtWidgets import QInputDialog
    image, *_ = fixture(tmp_path)
    application = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path/(filesystem+"-workspace"))
    window.switch(5)
    window.offline_filesystem.setCurrentText(filesystem)
    window.fat_image.setText(str(image))
    window.fat_internal.setText("/private-case")
    window.list_fat()
    wait_for_job(application, window)
    assert "/private-case/" in window.targeted_details.toPlainText()
    monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: (image.name+":/private-case", True))
    window.erase_fat_target()
    wait_for_job(application, window)
    assert window.store.records()[0]["payload"]["verification"]["rrs"] == 0
    assert "Unrelated allocated files preserved" in window.status_label.text()
    window.close()

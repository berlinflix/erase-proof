import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import time
from pathlib import Path
import pytest

pytest.importorskip("PySide6")
from PySide6.QtWidgets import QApplication
from eraseproof.desktop import MainWindow, STYLE


@pytest.fixture(autouse=True)
def reject_unexpected_operation_dialogs(monkeypatch):
    # A failed background operation opens a modal warning. In unattended CI,
    # that dialog can otherwise wait forever inside processEvents(). Retain
    # the real failure text and fail the test after the job has stopped.
    from PySide6.QtWidgets import QMessageBox
    warnings = []
    monkeypatch.setattr(QMessageBox, 'warning', lambda parent, title, message: warnings.append(message))
    yield
    assert not warnings, '\n'.join(warnings)


def wait_for_job(app, window):
    # Verification includes independently bounded scanners and fragment search.
    # A 30-second UI test deadline can cancel healthy work on a busy build host.
    deadline = time.monotonic()+180
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
    assert window.stack.currentIndex() == 1
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
    window.targeted_modes.setCurrentIndex(1)
    window.offline_filesystem.setCurrentText(filesystem)
    window.fat_image.setText(str(image))
    window.fat_internal.setText("/private-case")
    window.list_fat()
    wait_for_job(application, window)
    assert "/private-case/" in window.targeted_details.toPlainText()
    assert window.offline_entries.rowCount() > 0
    for row in range(window.offline_entries.rowCount()):
        if window.offline_entries.item(row, 0).text() == '/private-case':
            window.offline_entries.selectRow(row)
            break
    application.processEvents()
    assert window.fat_internal.text() == '/private-case'
    window.inspect_offline_plan()
    wait_for_job(application, window)
    assert 'confirmation' in window.targeted_details.toPlainText()
    monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: (image.name+":/private-case", True))
    window.erase_fat_target()
    wait_for_job(application, window)
    assert window.store.records()[0]["payload"]["verification"]["rrs"] == 0
    assert "Unrelated allocated files preserved" in window.status_label.text()
    window.close()


def test_device_selection_defaults_to_read_only_recovery(tmp_path):
    application = QApplication.instance() or QApplication([])
    from eraseproof.desktop import fill_table
    window = MainWindow(tmp_path/'workspace')
    window.device_rows = [{'name': '/dev/SYNTHETIC-PARTITION'}]
    fill_table(window.devices_table, [['/dev/SYNTHETIC-PARTITION', 'Fixture', '1 GiB', '', 'Unmounted']])
    window.devices_table.selectRow(0)
    window.select_device()
    assert window.stack.currentIndex() == 1
    assert window.recovery_source.text() == '/dev/SYNTHETIC-PARTITION'
    assert window.job is None
    window.select_device(erasure=True)
    assert window.stack.currentIndex() == 2
    assert window.job is None
    window.close()


def test_native_trash_selection_copies_real_unknown_file(tmp_path, monkeypatch):
    from PySide6.QtWidgets import QDialog, QTableWidget
    data_home = tmp_path/'data'
    root = data_home/'Trash'
    (root/'files').mkdir(parents=True)
    (root/'info').mkdir()
    data = os.urandom(12037)
    (root/'files/unknown.custom').write_bytes(data)
    (root/'info/unknown.custom.trashinfo').write_text('[Trash Info]\nPath=/original/unknown.custom\n')
    monkeypatch.setenv('XDG_DATA_HOME', str(data_home))
    def select(dialog):
        dialog.findChild(QTableWidget).selectRow(0)
        return QDialog.DialogCode.Accepted
    monkeypatch.setattr(QDialog, 'exec', select)
    application = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path/'workspace')
    window.browse_trash()
    deadline = time.monotonic()+20
    while not window.recovered and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(.01)
    wait_for_job(application, window)
    assert len(window.recovered) == 1
    assert Path(window.recovered[0]['output']).read_bytes() == data
    assert (root/'files/unknown.custom').read_bytes() == data
    assert 'Trash originals are unchanged' in window.status_label.text()
    window.close()

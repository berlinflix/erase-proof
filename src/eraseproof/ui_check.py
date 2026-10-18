"""Opt-in Qt interaction acceptance check, shared by source and frozen builds.

Invoked only by --check-evidence-ui. All records, keys, exports and the image
removed by the check are disposable fixtures in a fresh temporary workspace.
"""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading

from PySide6.QtCore import Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (
    QApplication, QDialog, QDialogButtonBox, QFileDialog, QInputDialog,
    QLineEdit, QMessageBox, QPlainTextEdit,
)

from . import __version__
from . import desktop
from .certificate import attached_record
from .evidence import now, verify_record


def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    app = QApplication.instance() or QApplication([])
    app.setStyle('Fusion')
    app.setStyleSheet(desktop.STYLE)
    checks = []
    original_save = QFileDialog.getSaveFileName
    original_open = desktop.open_local
    original_warning = QMessageBox.warning
    warnings = []
    desktop.open_local = lambda path: True
    QMessageBox.warning = lambda parent, title, message: warnings.append(message)
    QFileDialog.getSaveFileName = lambda *args, **kwargs: original_save(
        *args, **kwargs, options=QFileDialog.Option.DontUseNativeDialog)
    try:
        with tempfile.TemporaryDirectory(prefix='eraseproof-evidence-ui-') as temporary:
            root = Path(temporary)
            window = desktop.MainWindow(root/'workspace')
            try:
                def record(suffix, image=None):
                    size = image.stat().st_size if image else 8192
                    return window.store.certify({
                        'schema': 'eraseproof.native-evidence.v1',
                        'id': 'ep-123456789012345678-'+suffix, 'issued_at': now(),
                        'target': {'kind': 'image', 'path': str(image or root/'fixture.img'), 'size': size},
                        'plan': {'method': 'single-pass-zero-overwrite'} if image else {},
                        'assurance': 'Disposable UI acceptance fixture; not real user evidence.',
                        'verification': {'passed': True, 'bytes_checked': size, 'rrs': 0,
                                         'nonzero_bytes': 0, 'sha256': hashlib.sha256(bytes(size)).hexdigest(),
                                         'independent_attack': {'passed': True}},
                    })
                for suffix in ('one', 'two', 'three'):
                    require(verify_record(record(suffix)), 'Fixture signature failed')
                window.refresh_evidence()
                window.switch(3)
                window.resize(1024, 768)
                window.show()
                app.processEvents()
                table = window.records_table

                def click(row):
                    window.page_scroll.verticalScrollBar().setValue(0)
                    table.scrollToItem(table.item(row, 0))
                    app.processEvents()
                    point = table.visualItemRect(table.item(row, 0)).center()
                    require(window.childAt(table.viewport().mapTo(window, point)) is table.viewport(),
                            'Another widget intercepts the record row')
                    QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, pos=point)
                    app.processEvents()

                def show_control(control):
                    window.page_scroll.ensureWidgetVisible(control)
                    app.processEvents()
                    require(window.childAt(control.mapTo(window, control.rect().center())) is control,
                            'Action button is not reachable')

                def modal(action, inspect):
                    observed, errors = [], []
                    timer = QTimer()
                    ticks = [0]
                    def visit():
                        ticks[0] += 1
                        dialog = app.activeModalWidget()
                        if dialog and not observed:
                            observed.append(True)
                            try:
                                inspect(dialog)
                            except Exception as error:
                                errors.append(str(error))
                                dialog.reject()
                        if ticks[0] >= 200 and dialog:
                            errors.append('Modal UI operation timed out')
                            dialog.reject()
                    timer.timeout.connect(visit)
                    timer.start(50)
                    try:
                        action()
                        QTest.qWait(30)
                    finally:
                        timer.stop()
                    require(observed and not errors, '; '.join(errors) or 'Expected a dialog')

                def details(action, expected):
                    def inspect(dialog):
                        try:
                            body = dialog.findChild(QPlainTextEdit, 'signedRecordJson')
                            require(body is not None and json.loads(body.toPlainText()) == expected,
                                    'Details opened the wrong certificate')
                        finally:
                            dialog.reject()
                    modal(action, inspect)

                click(0)
                require([i.row() for i in table.selectionModel().selectedRows()] == [0], 'First row did not select')
                click(1)
                selected = window.current_record()
                require([i.row() for i in table.selectionModel().selectedRows()] == [1], 'Second row did not select')
                window.trusted_fingerprint.setFocus()
                app.processEvents()
                pixel = table.viewport().grab().toImage().pixelColor(3, 47+20)
                require(pixel.name() == '#2c7052', 'Selected row is not visibly highlighted after focus loss')
                checks.append('mouse-selection-and-visible-highlight')
                point = table.visualItemRect(table.item(1, 0)).center()
                details(lambda: QTest.mouseDClick(table.viewport(), Qt.MouseButton.LeftButton, pos=point), selected)
                show_control(window.view_record_button)
                details(lambda: QTest.mouseClick(window.view_record_button, Qt.MouseButton.LeftButton), selected)
                checks.append('double-click-and-view-button')

                database = window.store.db.read_bytes()
                key = (window.store.root/'operator-ed25519.key').read_bytes()
                for control, name in ((window.export_record_button, 'record.json'),
                                      (window.export_pdf_button, 'record.pdf')):
                    destination = root/name
                    def choose(dialog):
                        require(isinstance(dialog, QFileDialog), 'Expected a real Qt save dialog')
                        field = dialog.findChild(QLineEdit, 'fileNameEdit')
                        field.setFocus()
                        QTest.keyClick(field, Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
                        QTest.keyClicks(field, str(destination))
                        QTest.keyClick(field, Qt.Key.Key_Tab)
                        QTest.qWait(30)
                        buttons = dialog.findChild(QDialogButtonBox)
                        QTest.mouseClick(buttons.button(QDialogButtonBox.StandardButton.Save), Qt.MouseButton.LeftButton)
                    show_control(control)
                    modal(lambda: QTest.mouseClick(control, Qt.MouseButton.LeftButton), choose)
                    exported = attached_record(destination) if name.endswith('.pdf') else json.loads(destination.read_text())
                    require(exported == selected and verify_record(exported, selected['signer_fingerprint']),
                            'Export changed the selected record or signature')
                require(window.store.db.read_bytes() == database, 'Browsing/export changed the audit database')
                require((window.store.root/'operator-ed25519.key').read_bytes() == key, 'Signing key changed')
                checks.append('real-save-dialogs-json-pdf-signatures-and-audit')

                record('newest')
                window.refresh_evidence()
                require(window.current_record() == selected and table.currentRow() == 2,
                        'Refresh selected a different certificate')
                table.clearSelection()
                require(window.current_record() is None and not window.export_record_button.isEnabled(),
                        'Cleared selection still allows export')
                window.export_record()
                window.export_pdf()
                require('Select a signed record' in window.status_label.text(), 'Missing selection feedback')
                checks.append('stable-full-id-refresh-and-missing-selection')

                click(0)
                QTest.keyClick(table, Qt.Key.Key_Down)
                require(table.currentRow() == 1, 'Down arrow did not select the next record')
                details(lambda: QTest.keyClick(table, Qt.Key.Key_Return), window.current_record())
                QTest.keyClick(table, Qt.Key.Key_Up)
                require(table.currentRow() == 0, 'Up arrow did not select the previous record')
                details(lambda: QTest.keyClick(table, Qt.Key.Key_Enter), window.current_record())
                checks.append('keyboard-arrows-return-and-keypad-enter')

                release = threading.Event()
                def operation(progress, cancel):
                    while not release.wait(.01):
                        if cancel():
                            return
                window.execute(operation, lambda result: None)
                try:
                    require(table.isEnabled() and not window.erase_source.isEnabled(),
                            'Evidence and storage controls have incorrect busy states')
                    click(1)
                    selected = window.current_record()
                finally:
                    release.set()
                    require(window.job.wait(10000), 'Background fixture did not stop')
                    app.processEvents()
                require(window.current_record() == selected, 'Job completion changed the selected certificate')
                checks.append('background-job-selection-and-storage-safety-lock')

                for size in ((1024, 768), (1920, 1080)):
                    window.resize(*size)
                    app.processEvents()
                    for control in (window.view_record_button, window.export_record_button, window.export_pdf_button):
                        show_control(control)
                    require(window.page_scroll.horizontalScrollBar().maximum() == 0, 'Horizontal layout overflow')
                checks.append('1024x768-and-1920x1080-layouts')

                image = root/'overwritten.img'
                image.write_bytes(bytes(8192))
                removal_record = record('zero-image', image)
                window.refresh_evidence()
                click(0)
                require(window.current_record() == removal_record and window.delete_image_button.isEnabled(),
                        'Verified-image removal is unavailable')
                database = window.store.db.read_bytes()
                def confirm(dialog):
                    require(isinstance(dialog, QInputDialog), 'Expected filename confirmation')
                    require(str(image) in dialog.labelText(), 'Confirmation omitted the image path')
                    field = dialog.findChild(QLineEdit)
                    QTest.keyClicks(field, image.name)
                    QTest.keyClick(field, Qt.Key.Key_Return)
                show_control(window.delete_image_button)
                modal(lambda: QTest.mouseClick(window.delete_image_button, Qt.MouseButton.LeftButton), confirm)
                for _ in range(1000):
                    app.processEvents()
                    if window.job and not window.job.isRunning():
                        break
                    QTest.qWait(10)
                app.processEvents()
                require(not image.exists() and window.store.db.read_bytes() == database and window.store.check(),
                        'Image removal failed or changed signed evidence')
                require(not warnings, '; '.join(warnings))
                checks.append('confirmed-zero-image-removal-preserves-evidence')
                result = {'version': __version__, 'frozen': bool(getattr(sys, 'frozen', False)),
                          'qt_platform': app.platformName(), 'checks': checks, 'passed': True,
                          'virtualbox_manual_acceptance': False}
            finally:
                if window.job and window.job.isRunning():
                    window.job.requestInterruption()
                    window.job.wait(10000)
                window.close()
                app.processEvents()
        print(json.dumps(result, indent=2))
        return 0
    finally:
        QFileDialog.getSaveFileName = original_save
        desktop.open_local = original_open
        QMessageBox.warning = original_warning

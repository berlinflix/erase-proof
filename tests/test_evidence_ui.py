"""Real Qt interactions with disposable, Ed25519-signed operator records."""
import json
import os
import threading

import pytest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
pytest.importorskip('PySide6')
from PySide6.QtCore import Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog, QFileDialog, QPlainTextEdit, QMessageBox

from eraseproof.certificate import attached_record
from eraseproof.desktop import MainWindow, STYLE
from eraseproof.evidence import now, verify_record


def add_record(window, suffix):
    return window.store.certify({
        'schema': 'eraseproof.native-evidence.v1',
        # The visible prefix deliberately collides: identities must use full IDs.
        'id': 'ep-123456789012345678-'+suffix, 'issued_at': now(),
        'target': {'path': str(window.workspace/'experiment.img'),
                   'kind': 'image', 'size': 4096},
        'verification': {'passed': True, 'bytes_checked': 4096, 'rrs': 0,
                         'independent_attack': {'passed': True}},
    })


@pytest.fixture
def evidence_window(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    app.setStyle('Fusion')
    app.setStyleSheet(STYLE)
    window = MainWindow(tmp_path/'workspace')
    for suffix in ('first', 'second', 'third'):
        assert verify_record(add_record(window, suffix))
    window.refresh_evidence()
    window.switch(3)
    window.resize(1024, 768)
    window.show()
    app.processEvents()
    monkeypatch.setattr('eraseproof.desktop.open_local', lambda path: True)
    warnings = []
    monkeypatch.setattr(QMessageBox, 'warning', lambda parent, title, message: warnings.append(message))
    try:
        yield app, window
    finally:
        if window.job and window.job.isRunning():
            window.job.requestInterruption()
            window.job.wait(10000)
        window.close()
        app.processEvents()
    assert not warnings, '\n'.join(warnings)


def click_record(app, window, row, modifier=Qt.KeyboardModifier.NoModifier):
    table = window.records_table
    window.page_scroll.verticalScrollBar().setValue(0)
    table.scrollToItem(table.item(row, 0))
    app.processEvents()
    point = table.visualItemRect(table.item(row, 0)).center()
    # Hit testing uses the real hierarchy, in addition to sending viewport events.
    assert app.widgetAt(table.viewport().mapToGlobal(point)) is table.viewport()
    QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, modifier, point)
    app.processEvents()


def capture_details(app, trigger):
    seen = []
    timer = QTimer()
    def inspect():
        dialog = app.activeModalWidget()
        if isinstance(dialog, QDialog):
            body = dialog.findChild(QPlainTextEdit)
            seen.append(json.loads(body.toPlainText()) if body else None)
            dialog.reject()
    timer.timeout.connect(inspect)
    timer.start(10)
    try:
        trigger()
        QTest.qWait(30)
    finally:
        timer.stop()
    assert len(seen) == 1, 'Exactly one record details dialog must open'
    return seen[0]


def test_mouse_selects_one_complete_row_with_visible_unfocused_highlight(evidence_window):
    app, window = evidence_window
    table = window.records_table
    click_record(app, window, 0)
    assert [i.row() for i in table.selectionModel().selectedRows()] == [0]
    first = window.current_record()['payload']['id']
    assert len(table.selectedIndexes()) == table.columnCount()
    before = table.viewport().grab().toImage()
    window.trusted_fingerprint.setFocus()
    app.processEvents()
    unfocused = table.viewport().grab().toImage()
    point = table.visualItemRect(table.item(0, 0)).topLeft()
    # Sample empty cell padding, not text or the keyboard focus rectangle.
    selected = unfocused.pixelColor(point.x()+3, point.y()+20)
    unselected = unfocused.pixelColor(point.x()+3, point.y()+67)
    assert selected.name() == '#2c7052'
    assert selected != unselected
    assert before.pixelColor(point.x()+3, point.y()+20) == selected
    QTest.mouseMove(table.viewport(), table.visualItemRect(table.item(1, 0)).center())
    QTest.qWait(20)
    hovered = table.viewport().grab().toImage()
    assert hovered.pixelColor(point.x()+3, point.y()+67).name() == '#e3eddc'
    click_record(app, window, 1)
    assert [i.row() for i in table.selectionModel().selectedRows()] == [1]
    assert window.current_record()['payload']['id'] != first
    click_record(app, window, 2, Qt.KeyboardModifier.ControlModifier)
    assert len(table.selectionModel().selectedRows()) == 1


def test_double_click_and_view_button_open_the_selected_certificate(evidence_window):
    app, window = evidence_window
    click_record(app, window, 1)
    selected = window.current_record()
    point = window.records_table.visualItemRect(window.records_table.item(1, 0)).center()
    displayed = capture_details(app, lambda: QTest.mouseDClick(
        window.records_table.viewport(), Qt.MouseButton.LeftButton, pos=point))
    assert displayed == selected
    window.page_scroll.ensureWidgetVisible(window.view_record_button)
    app.processEvents()
    displayed = capture_details(app, lambda: QTest.mouseClick(
        window.view_record_button, Qt.MouseButton.LeftButton))
    assert displayed == selected


def test_json_and_pdf_exports_preserve_exact_signature_and_audit(evidence_window, tmp_path, monkeypatch):
    app, window = evidence_window
    click_record(app, window, 1)
    selected = window.current_record()
    database = window.store.db.read_bytes()
    key = (window.store.root/'operator-ed25519.key').read_bytes()
    events = window.store.events()
    for control, name in ((window.export_record_button, 'signed.json'),
                          (window.export_pdf_button, 'signed.pdf')):
        destination = tmp_path/name
        monkeypatch.setattr(QFileDialog, 'getSaveFileName', lambda *a, path=destination, **k: (str(path), ''))
        window.page_scroll.ensureWidgetVisible(control)
        app.processEvents()
        QTest.mouseClick(control, Qt.MouseButton.LeftButton)
        assert destination.exists()
        exported = attached_record(destination) if destination.suffix == '.pdf' else json.loads(destination.read_text())
        assert exported == selected
        assert verify_record(exported, selected['signer_fingerprint'])
    window.refresh_evidence()
    assert window.store.check()
    assert window.store.events() == events
    assert window.store.db.read_bytes() == database
    assert (window.store.root/'operator-ed25519.key').read_bytes() == key


def test_json_save_dialog_accepts_a_path_through_real_qt_widgets(evidence_window, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QDialogButtonBox, QLineEdit
    app, window = evidence_window
    click_record(app, window, 1)
    selected = window.current_record()
    destination = tmp_path/'chosen-through-dialog.json'
    original = QFileDialog.getSaveFileName
    monkeypatch.setattr(QFileDialog, 'getSaveFileName', lambda *a, **k: original(
        *a, **k, options=QFileDialog.Option.DontUseNativeDialog))
    seen = []
    ticks = []
    def choose():
        dialog = app.activeModalWidget()
        ticks.append(True)
        if len(ticks) > 200 and dialog:
            dialog.reject()
        if isinstance(dialog, QFileDialog) and not seen:
            seen.append(True)
            dialog.setDirectory(str(destination.parent))
            app.processEvents()
            field = dialog.findChild(QLineEdit, 'fileNameEdit')
            # Synthetic typing must not leave a platform completion popup
            # grabbing the Save click. Filename completion is not under test.
            field.setCompleter(None)
            field.setFocus()
            QTest.keyClick(field, Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
            QTest.keyClicks(field, destination.name)
            QTest.keyClick(field, Qt.Key.Key_Tab)
            QTest.qWait(30)
            buttons = dialog.findChild(QDialogButtonBox)
            QTest.mouseClick(buttons.button(QDialogButtonBox.StandardButton.Save), Qt.MouseButton.LeftButton)
    timer = QTimer()
    timer.timeout.connect(choose)
    timer.start(50)
    window.page_scroll.ensureWidgetVisible(window.export_record_button)
    app.processEvents()
    try:
        QTest.mouseClick(window.export_record_button, Qt.MouseButton.LeftButton)
    finally:
        timer.stop()
    assert seen and json.loads(destination.read_text()) == selected


@pytest.mark.parametrize('kind', ['json', 'pdf'])
def test_export_uses_captured_certificate_if_refresh_occurs_inside_save_dialog(
        evidence_window, tmp_path, monkeypatch, kind):
    app, window = evidence_window
    click_record(app, window, 1)
    selected = window.current_record()
    destination = tmp_path/('captured.'+kind)
    def choose(*args, **kwargs):
        add_record(window, 'during-save')
        window.refresh_evidence()
        window.records_table.selectRow(0)
        return str(destination), ''
    monkeypatch.setattr(QFileDialog, 'getSaveFileName', choose)
    control = window.export_record_button if kind == 'json' else window.export_pdf_button
    window.page_scroll.ensureWidgetVisible(control)
    app.processEvents()
    QTest.mouseClick(control, Qt.MouseButton.LeftButton)
    exported = json.loads(destination.read_text()) if kind == 'json' else attached_record(destination)
    assert exported == selected
    assert verify_record(exported)


def test_refresh_preserves_full_certificate_identity_and_clears_missing_selection(evidence_window, monkeypatch):
    app, window = evidence_window
    click_record(app, window, 1)
    selected = window.current_record()
    add_record(window, 'newest')
    window.refresh_evidence()
    assert window.current_record() == selected
    assert window.records_table.currentRow() == 2
    records = window.store.records()
    monkeypatch.setattr(window.store, 'records', lambda: list(reversed(records)))
    window.refresh_evidence()
    assert window.current_record() == selected
    monkeypatch.setattr(window.store, 'records', lambda: [r for r in records if r != selected])
    window.refresh_evidence()
    assert window.current_record() is None
    assert not window.records_table.selectedIndexes()
    assert not window.export_record_button.isEnabled()
    assert not window.export_pdf_button.isEnabled()


def test_cleared_selection_cannot_export_a_stale_current_row(evidence_window, monkeypatch):
    app, window = evidence_window
    click_record(app, window, 1)
    window.records_table.clearSelection()
    app.processEvents()
    # Qt retains currentIndex after clearSelection; it is not a selection.
    assert window.records_table.currentRow() == 1
    assert window.current_record() is None
    calls = []
    monkeypatch.setattr(QFileDialog, 'getSaveFileName', lambda *a, **k: calls.append(a))
    window.export_record()
    window.export_pdf()
    window.view_record()
    assert calls == []
    assert not window.view_record_button.isEnabled()
    assert 'Select a signed record' in window.record_selection_label.text()


def test_arrows_and_enter_activate_the_selected_record(evidence_window):
    app, window = evidence_window
    click_record(app, window, 0)
    QTest.keyClick(window.records_table, Qt.Key.Key_Down)
    assert window.records_table.currentRow() == 1
    selected = window.current_record()
    assert capture_details(app, lambda: QTest.keyClick(window.records_table, Qt.Key.Key_Return)) == selected
    QTest.keyClick(window.records_table, Qt.Key.Key_Up)
    assert window.records_table.currentRow() == 0
    selected = window.current_record()
    assert capture_details(app, lambda: QTest.keyClick(window.records_table, Qt.Key.Key_Enter)) == selected


def test_evidence_browsing_stays_interactive_during_background_jobs(evidence_window):
    app, window = evidence_window
    release = threading.Event()
    def operation(progress, cancel):
        while not release.wait(.01):
            if cancel():
                return
    window.execute(operation, lambda result: None)
    try:
        app.processEvents()
        assert window.records_table.isEnabled()
        # Storage target controls retain the existing job safety lock.
        assert not window.erase_source.isEnabled()
        click_record(app, window, 1)
        selected = window.current_record()
        window.page_scroll.ensureWidgetVisible(window.view_record_button)
        app.processEvents()
        assert capture_details(app, lambda: QTest.mouseClick(
            window.view_record_button, Qt.MouseButton.LeftButton)) == selected
    finally:
        release.set()
        assert window.job.wait(10000)
        app.processEvents()
    assert window.current_record() == selected


def test_image_removal_button_uses_real_confirmation_and_keeps_records(evidence_window):
    from PySide6.QtWidgets import QInputDialog, QLineEdit
    from test_imagecleanup import zero_record
    app, window = evidence_window
    image = window.workspace/'overwritten.img'
    image.write_bytes(bytes(8192))
    record = zero_record(image, window.store)
    window.refresh_evidence()
    click_record(app, window, 0)
    assert window.current_record() == record
    assert window.delete_image_button.isEnabled()
    database = window.store.db.read_bytes()
    key = (window.store.root/'operator-ed25519.key').read_bytes()
    confirmations = []
    def confirm():
        dialog = app.activeModalWidget()
        if isinstance(dialog, QInputDialog):
            confirmations.append(dialog.labelText())
            QTest.keyClicks(dialog.findChild(QLineEdit), image.name)
            QTest.keyClick(dialog.findChild(QLineEdit), Qt.Key.Key_Return)
    timer = QTimer()
    timer.timeout.connect(confirm)
    timer.start(10)
    window.page_scroll.ensureWidgetVisible(window.delete_image_button)
    app.processEvents()
    try:
        QTest.mouseClick(window.delete_image_button, Qt.MouseButton.LeftButton)
    finally:
        timer.stop()
    assert len(confirmations) == 1 and str(image) in confirmations[0]
    for _ in range(500):
        app.processEvents()
        if not window.job or not window.job.isRunning():
            break
        QTest.qWait(10)
    assert window.job and not window.job.isRunning()
    app.processEvents()
    assert not image.exists()
    assert window.store.db.read_bytes() == database
    assert (window.store.root/'operator-ed25519.key').read_bytes() == key
    assert window.store.check() and window.current_record() == record
    assert 'Signed evidence and audit history were kept' in window.status_label.text()


@pytest.mark.parametrize('size', [(1024, 768), (1920, 1080)])
def test_evidence_actions_remain_reachable_after_resize(evidence_window, size):
    app, window = evidence_window
    window.resize(*size)
    app.processEvents()
    click_record(app, window, 0)
    for control in (window.view_record_button, window.export_record_button, window.export_pdf_button):
        window.page_scroll.ensureWidgetVisible(control)
        app.processEvents()
        assert control.isVisible() and control.isEnabled()
        # Offscreen Qt's virtual screen may be smaller than the requested test
        # window. Hit-test the full window hierarchy at both requested sizes.
        assert window.childAt(control.mapTo(window, control.rect().center())) is control
    assert window.page_scroll.horizontalScrollBar().maximum() == 0

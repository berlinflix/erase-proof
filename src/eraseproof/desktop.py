"""Native Qt desktop frontend. No browser, HTTP server or web view."""
from datetime import datetime
import json
import os
from pathlib import Path
import sys
import uuid

from PySide6.QtCore import Qt, QThread, Signal, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QFont, QIcon
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSizePolicy,
    QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from . import __version__, demo, tsk
from .cli import recover, references
from .engine import erase, plan, verify
from .evidence import EvidenceStore, verify_record
from .targets import describe, devices, descendants


STYLE = """
QWidget { font-family: 'Ubuntu', 'DejaVu Sans', sans-serif; font-size: 12px; color: #25362e; }
QMainWindow, QWidget#surface { background: #f3f5f0; }
QFrame#sidebar { background: #19382d; border: none; }
QLabel#brand { color: #f0f6e8; font-size: 23px; font-weight: 700; }
QLabel#sideNote { color: #a0b89e; font-size: 11px; }
QLabel#sideCaption { color: #8eac8b; font-size: 10px; font-weight: 600; }
QPushButton#nav { background: transparent; border: none; border-radius: 5px; color: #afc4a6; text-align: left; padding: 13px 15px; }
QPushButton#nav:checked { color: #27432c; background: #d4e5bc; font-weight: 600; }
QPushButton#nav:hover:!checked { background: #294b38; }
QLabel#eyebrow { color: #788c6a; font-size: 10px; font-weight: 600; }
QLabel#title { font-size: 29px; font-weight: 600; color: #243b2b; }
QLabel#subtitle { color: #7b8d71; font-size: 12px; }
QFrame#panel { background: #ffffff; border: 1px solid #dfe6d7; border-radius: 7px; }
QLabel#panelTitle { font-size: 14px; font-weight: 600; color: #344e32; }
QLabel#body { color: #7c8e70; line-height: 150%; }
QLabel#metric { font-size: 28px; font-weight: 600; color: #4e783c; }
QLabel#tag { background: #eaf1e0; border: 1px solid #d7e3c8; color: #688553; padding: 5px 8px; border-radius: 4px; font-size: 10px; }
QPushButton { background: #fff; border: 1px solid #d9e2ce; border-radius: 4px; padding: 9px 13px; color: #567347; }
QPushButton:hover { background: #f3f8ec; border-color: #b4c7a4; }
QPushButton:disabled { color: #a5b29a; background: #f3f5ef; border-color: #e2e7da; }
QPushButton#primary { color: #fff; background: #2c7052; border-color: #2c7052; font-weight: 600; }
QPushButton#primary:hover { background: #205b40; }
QPushButton#primary:disabled { background: #a6baa1; border-color: #a6baa1; }
QPushButton#danger { background: #9c493a; color: white; border-color: #9c493a; }
QLineEdit, QComboBox { background: #fbfcf8; padding: 9px; border: 1px solid #dce4d2; border-radius: 4px; color: #48603b; selection-background-color: #d1e2bc; }
QLineEdit:focus, QComboBox:focus, QPushButton:focus { border: 2px solid #7f9f68; }
QTableWidget { background: #fff; border: none; gridline-color: #edf0e7; selection-background-color: #eef5e5; selection-color: #405d32; alternate-background-color: #fcfdf9; }
QHeaderView::section { border: none; border-bottom: 1px solid #e5eadc; background: #f6f9f1; color: #7c8f6b; font-size: 10px; padding: 11px 8px; }
QTableWidget::item { padding: 9px; border-bottom: 1px solid #edf1e5; }
QTableWidget::item:selected { background: #edf5e2; }
QProgressBar { border: none; border-radius: 3px; background: #e7edde; height: 5px; text-align: center; color: #536e42; }
QProgressBar::chunk { background: #719b54; border-radius: 3px; }
QPlainTextEdit { border: 1px solid #dfe7d5; border-radius: 5px; background: #fafcf6; font-family: 'DejaVu Sans Mono', monospace; color: #718760; font-size: 10px; }
QDialog { background: #f8faf4; }
QCheckBox { spacing: 8px; color: #7d8e70; }
QToolTip { background: #203e2b; color: #e6f0db; padding: 7px; border: none; }
"""


def label(text, name="body", wrap=False):
    widget = QLabel(text)
    widget.setObjectName(name)
    widget.setWordWrap(wrap)
    return widget


def button(text, action=None, primary=False):
    widget = QPushButton(text)
    if primary:
        widget.setObjectName("primary")
    if action:
        widget.clicked.connect(action)
    return widget


def panel(title, description=""):
    frame = QFrame()
    frame.setObjectName("panel")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(22, 20, 22, 20)
    layout.setSpacing(13)
    if title:
        layout.addWidget(label(title, "panelTitle"))
    if description:
        layout.addWidget(label(description, wrap=True))
    return frame, layout


def table(headers):
    widget = QTableWidget(0, len(headers))
    widget.setHorizontalHeaderLabels(headers)
    widget.horizontalHeader().setStretchLastSection(True)
    widget.verticalHeader().hide()
    widget.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    widget.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    widget.setAlternatingRowColors(True)
    widget.setShowGrid(False)
    widget.verticalHeader().setDefaultSectionSize(47)
    widget.setMinimumHeight(180)
    return widget


def fill_table(widget, rows):
    widget.setRowCount(len(rows))
    for row, values in enumerate(rows):
        for column, value in enumerate(values):
            widget.setItem(row, column, QTableWidgetItem(str(value)))
    widget.resizeColumnsToContents()


class Job(QThread):
    progress = Signal(str, float, str)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, operation):
        super().__init__()
        self.operation = operation

    def run(self):
        try:
            self.completed.emit(self.operation(self.progress.emit, self.isInterruptionRequested))
        except Exception as error:
            self.failed.emit(str(error))


class MainWindow(QMainWindow):
    def __init__(self, workspace=None):
        super().__init__()
        self.setWindowTitle("EraseProof — Native Linux workbench")
        self.setWindowIcon(QIcon(str(Path(__file__).parent/"resources"/"eraseproof.svg")))
        self.resize(1240, 850)
        self.setMinimumSize(1020, 710)
        self.workspace = Path(workspace or Path.home()/"EraseProof").expanduser().resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.store = EvidenceStore(self.workspace/"evidence")
        self.target = ""
        self.reference_file = None
        self.demo_dir = None
        self.job = None
        self.action_buttons = []
        self.recovered = []
        self._build()
        self.refresh_evidence()
        self.switch(0)

    def _build(self):
        surface = QWidget()
        surface.setObjectName("surface")
        outer = QHBoxLayout(surface)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self.setCentralWidget(surface)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(20, 30, 20, 23)
        side.setSpacing(7)
        side.addWidget(label("E_  EraseProof", "brand"))
        side.addSpacing(7)
        side.addWidget(label("NATIVE LINUX WORKBENCH", "sideCaption"))
        side.addSpacing(34)
        side.addWidget(label("WORKSPACE", "sideCaption"))
        side.addSpacing(7)
        self.nav = []
        for index, title in enumerate(("01   Experiment", "02   Recover files", "03   Erase & verify", "04   Evidence", "05   Device inventory")):
            item = button(title, lambda checked=False, i=index: self.switch(i))
            item.setObjectName("nav")
            item.setCheckable(True)
            self.nav.append(item)
            side.addWidget(item)
        side.addStretch()
        side.addWidget(label("LOCAL ENGINE · v"+__version__, "sideCaption"))
        side.addSpacing(8)
        side.addWidget(label("Real Linux I/O.\nYour data stays on this machine.\n\nImage and virtual-disk support.\nPhysical-media sanitization\nis a separate milestone.", "sideNote"))
        outer.addWidget(sidebar)

        main = QVBoxLayout()
        main.setContentsMargins(30, 25, 30, 20)
        main.setSpacing(17)
        top = QHBoxLayout()
        top.addWidget(label("RESEARCH WORKSPACE / UBUNTU", "eyebrow"))
        top.addStretch()
        top.addWidget(label("●  Native Qt · no browser", "tag"))
        main.addLayout(top)
        self.title = label("", "title")
        self.subtitle = label("", "subtitle", True)
        main.addWidget(self.title)
        main.addWidget(self.subtitle)
        self.stack = QStackedWidget()
        main.addWidget(self.stack, 1)
        self._experiment()
        self._recovery()
        self._erasure()
        self._evidence()
        self._devices()

        progress_panel, status = panel("")
        status.setContentsMargins(16, 12, 16, 12)
        progress_row = QHBoxLayout()
        self.status_label = label("Ready. Create an experiment or open a disk image.")
        self.cancel_button = button("Cancel operation", self.cancel)
        self.cancel_button.setEnabled(False)
        progress_row.addWidget(self.status_label, 1)
        progress_row.addWidget(self.cancel_button)
        status.addLayout(progress_row)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1000)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(5)
        status.addWidget(self.progress_bar)
        main.addWidget(progress_panel)
        outer.addLayout(main, 1)

    def registered(self, text, action, primary=False):
        widget = button(text, action, primary)
        self.action_buttons.append(widget)
        return widget

    def source_row(self, layout, edit):
        row = QHBoxLayout()
        edit.setPlaceholderText("Select a .img / .raw image, or enter a Linux device path")
        row.addWidget(edit, 1)
        row.addWidget(self.registered("Open image…", self.choose_source))
        layout.addLayout(row)

    def _experiment(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(17)
        hero, box = panel("A real deletion. A measurable recovery.", "Create a genuine 64 MiB FAT32 filesystem, add four real files, delete them with mdel, and recover the surviving data. Then overwrite the image and challenge the result.")
        row = QHBoxLayout()
        row.addWidget(self.registered("Create FAT32 experiment", self.create_demo, True))
        self.normal_delete = self.registered("Delete files normally", self.delete_demo)
        row.addWidget(self.normal_delete)
        row.addStretch()
        box.addLayout(row)
        self.demo_status = label("No experiment created yet. All writes are to a new file in your experiment folder.", wrap=True)
        box.addWidget(self.demo_status)
        layout.addWidget(hero)

        cards = QHBoxLayout()
        for number, title, description in (
            ("01", "Ordinary deletion", "Directory entries disappear. Unallocated clusters can still contain the original bytes."),
            ("02", "Forensic recovery", "Use actual fls/icat metadata recovery and EraseProof's own signature carver."),
            ("03", "Verified overwrite", "Overwrite the actual image, fsync, read every byte, attack it, and sign the result."),
        ):
            card, inner = panel("")
            inner.addWidget(label(number, "metric"))
            inner.addWidget(label(title, "panelTitle"))
            inner.addWidget(label(description, wrap=True))
            cards.addWidget(card)
        layout.addLayout(cards)
        fixture, contents = panel("Ground truth", "Each original has a SHA-256 fingerprint. After recovery, compare the extracted bytes with these originals.")
        self.originals = table(["ORIGINAL FILE", "BYTES", "SHA-256"])
        self.originals.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        contents.addWidget(self.originals)
        layout.addWidget(fixture, 1)
        self.stack.addWidget(page)

    def _recovery(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        options, settings = panel("Recover deleted data", "The source is opened read-only. Choose an output directory on a different disk when recovering a real device.")
        self.recovery_source = QLineEdit()
        self.source_row(settings, self.recovery_source)
        destination = QHBoxLayout()
        destination.addWidget(label("Recover to"))
        self.recovery_destination = QLineEdit(str(self.workspace/"recovered"))
        self.recovery_destination.setAccessibleName("Recovery output directory")
        destination.addWidget(self.recovery_destination, 1)
        destination.addWidget(self.registered("Choose folder…", self.choose_destination))
        settings.addLayout(destination)
        row = QHBoxLayout()
        self.mode = QComboBox()
        self.mode.addItems(["Filesystem + signature carving", "Deleted filesystem entries only", "Signature carving only"])
        row.addWidget(self.mode, 1)
        row.addWidget(self.registered("Scan & recover", self.start_recovery, True))
        settings.addLayout(row)
        layout.addWidget(options)
        findings, contents = panel("Recovered files", "Metadata findings and carved copies are listed separately. Open an extracted file to inspect the actual recovered content.")
        self.results = table(["FILE", "METHOD", "BYTES", "SHA-256 / EVIDENCE"])
        self.results.doubleClicked.connect(self.open_recovered)
        self.results.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        contents.addWidget(self.results, 1)
        contents.addWidget(button("Open selected recovered file", self.open_recovered))
        layout.addWidget(findings, 1)
        self.stack.addWidget(page)

    def _erasure(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        source, contents = panel("Select the actual target", "An image overwrite changes the real file on disk. An eligible VirtualBox disk overwrite changes all guest-visible sectors. Mounted disks and their children are refused.")
        self.erase_source = QLineEdit()
        self.source_row(contents, self.erase_source)
        row = QHBoxLayout()
        row.addWidget(self.registered("Inspect plan", self.show_plan))
        row.addWidget(self.registered("Read-only verification", self.start_verification))
        row.addStretch()
        row.addWidget(self.registered("Prepare overwrite…", self.prepare_erase, True))
        contents.addLayout(row)
        layout.addWidget(source)
        plan_panel, methods = panel("The verification gate", "One zero pass → fsync → complete read-back → signature carving → known reference search → Ed25519 record. A cancelled or failed operation produces no certificate.")
        self.verification_details = QPlainTextEdit()
        self.verification_details.setReadOnly(True)
        self.verification_details.setPlaceholderText("Verification measurements and the selected plan appear here.\n\nPhysical ATA/NVMe sanitization, hidden areas, snapshots and flash remanence are not covered by logical overwrite.")
        methods.addWidget(self.verification_details)
        layout.addWidget(plan_panel, 1)
        self.stack.addWidget(page)

    def _evidence(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        evidence, box = panel("Signed operator records", "Ed25519 signatures bind the measurements to the target and audit head. These are self-signed local records, not external operator identity or compliance attestations.")
        self.integrity_label = label("")
        box.addWidget(self.integrity_label)
        self.records_table = table(["RECORD", "TARGET", "CHECKED BYTES", "ISSUED UTC"])
        self.records_table.doubleClicked.connect(self.view_record)
        box.addWidget(self.records_table)
        row = QHBoxLayout()
        row.addWidget(button("View selected record", self.view_record))
        row.addWidget(button("Export signed JSON…", self.export_record))
        row.addStretch()
        row.addWidget(button("Verify a record…", self.check_record))
        row.addWidget(button("Export audit…", self.export_audit))
        box.addLayout(row)
        layout.addWidget(evidence, 1)
        self.stack.addWidget(page)

    def _devices(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        inventory, box = panel("Read-only Linux discovery", "Actual lsblk data. Only recognized secondary virtual disks with a serial and no mounted children are eligible for logical overwrite. Physical disk sanitize/secure-erase commands are not enabled.")
        box.addWidget(self.registered("Refresh devices", self.refresh_devices))
        self.devices_table = table(["PATH", "MODEL", "SIZE", "SERIAL", "MOUNTS / STATE"])
        self.devices_table.doubleClicked.connect(self.select_device)
        box.addWidget(self.devices_table)
        box.addWidget(label("Double-click a device to inspect its path in Erase & verify. This does not start a write.", wrap=True))
        layout.addWidget(inventory, 1)
        self.stack.addWidget(page)

    def switch(self, index):
        titles = [("The recovery experiment", "A reproducible filesystem experiment for your Ubuntu VM."),
                  ("See what survives.", "Filesystem metadata recovery and native contiguous file carving."),
                  ("Erase. Attack. Verify.", "Measured logical erasure, with explicit target identity and evidence."),
                  ("Keep the proof.", "Signed results and a transactional, hash-chained audit history."),
                  ("Know your target.", "Inspect actual Linux devices before preparing an operation.")]
        self.title.setText(titles[index][0])
        self.subtitle.setText(titles[index][1])
        self.stack.setCurrentIndex(index)
        for i, item in enumerate(self.nav):
            item.setChecked(i == index)

    def set_target(self, path, reference_file=None):
        self.target = str(path)
        self.reference_file = reference_file
        self.recovery_source.setText(self.target)
        self.erase_source.setText(self.target)

    def choose_source(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open raw disk image", str(self.workspace), "Raw images (*.img *.raw *.dd *.bin);;All files (*)")
        if path:
            self.set_target(path)

    def choose_destination(self):
        path = QFileDialog.getExistingDirectory(self, "Choose a separate recovery destination", str(self.workspace))
        if path:
            self.recovery_destination.setText(path)

    def execute(self, operation, success):
        if self.job and self.job.isRunning():
            return
        for item in self.action_buttons:
            item.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.job = Job(operation)
        self.job.progress.connect(self.on_progress)
        self.job.completed.connect(success)
        self.job.failed.connect(self.on_error)
        self.job.finished.connect(self.on_finished)
        self.status_label.setText("Starting local operation…")
        self.job.start()

    def on_progress(self, stage, fraction, message):
        self.status_label.setText(f"{stage}  ·  {message}")
        self.progress_bar.setValue(int(fraction*1000))

    def on_finished(self):
        for item in self.action_buttons:
            item.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.refresh_evidence()

    def on_error(self, message):
        self.status_label.setText("Stopped: "+message)
        self.verification_details.appendPlainText("STOPPED: "+message)
        QMessageBox.warning(self, "Operation stopped", message)

    def cancel(self):
        if self.job and self.job.isRunning():
            self.job.requestInterruption()
            self.status_label.setText("Cancellation requested. Any partially overwritten target remains uncertified.")

    def create_demo(self):
        root = self.workspace/"experiments"/(datetime.now().strftime("%Y%m%d-%H%M%S")+"-"+uuid.uuid4().hex[:6])
        def done(manifest):
            self.demo_dir = Path(manifest["image"]).parent
            self.set_target(manifest["image"], self.demo_dir/"manifest.json")
            self.demo_status.setText("FAT32 created. Four files exist in the filesystem. Next: Delete files normally.\n"+manifest["image"])
            fill_table(self.originals, [(item["name"], item["size"], item["sha256"]) for item in manifest["files"]])
            self.status_label.setText("Experiment created with mkfs.fat and mcopy. The files have not been deleted yet.")
            self.progress_bar.setValue(1000)
        self.execute(lambda progress, cancel: demo.create(root), done)

    def delete_demo(self):
        if not self.demo_dir:
            QMessageBox.information(self, "Create an experiment", "Create a FAT32 experiment first.")
            return
        def done(manifest):
            self.demo_status.setText("Ordinary deletion completed by mdel. The directory entries are deleted; file data is still recoverable.\n"+manifest["image"])
            self.status_label.setText("Files deleted normally inside the demo filesystem. Continue to Recover files.")
        self.execute(lambda progress, cancel: demo.delete(self.demo_dir), done)

    def start_recovery(self):
        target = self.recovery_source.text().strip()
        if not target:
            return self.on_error("Select an image or create an experiment first.")
        destination = self.recovery_destination.text().strip()
        if not destination:
            return self.on_error("Choose a recovery output directory first.")
        output = Path(destination).expanduser()/(datetime.now().strftime("%Y%m%d-%H%M%S")+"-"+uuid.uuid4().hex[:6])
        mode = ("both", "deleted", "carve")[self.mode.currentIndex()]
        def done(report):
            self.recovered = report["candidates"]
            fill_table(self.results, [(c["name"], "Filesystem" if c["method"] == "sleuthkit-metadata" else "Carving", c["length"], c["sha256"]) for c in self.recovered])
            self.status_label.setText(f"Recovery complete: {len(self.recovered)} findings saved to {output}" + (" · "+"; ".join(report["warnings"]) if report["warnings"] else ""))
            self.progress_bar.setValue(1000)
        self.execute(lambda progress, cancel: recover(target, output, mode, progress=progress, cancel=cancel), done)

    def open_recovered(self, *_):
        row = self.results.currentRow()
        if 0 <= row < len(self.recovered):
            QDesktopServices.openUrl(QUrl.fromLocalFile(self.recovered[row]["output"]))

    def show_plan(self):
        try:
            path = self.erase_source.text().strip()
            info = describe(path)
            prepared = plan(path, path if info["kind"] == "block-device" else None, info["serial"])
            self.verification_details.setPlainText(json.dumps(prepared, indent=2))
        except Exception as error:
            self.on_error(str(error))

    def start_verification(self):
        path = self.erase_source.text().strip()
        def done(result):
            self.verification_details.setPlainText(json.dumps(result, indent=2))
            self.status_label.setText("Verification PASSED: every logical byte reads zero." if result["passed"] else "Verification FAILED: residual data remains. No certificate issued.")
            self.progress_bar.setValue(1000)
        self.execute(lambda progress, cancel: verify(path, references(self.reference_file) if self.reference_file and path == self.target else None, progress, cancel), done)

    def prepare_erase(self):
        path = self.erase_source.text().strip()
        try:
            info = describe(path)
            device = path if info["kind"] == "block-device" else None
            prepared = plan(path, device, info["serial"])
        except Exception as error:
            return self.on_error(str(error))
        dialog = QDialog(self)
        dialog.setWindowTitle("Confirm actual target overwrite")
        dialog.setMinimumWidth(560)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(15)
        layout.addWidget(label("This changes the actual selected target.", "panelTitle"))
        layout.addWidget(label(f"{prepared['target']['path']}\n{prepared['target']['size']:,} bytes\n\nAll logical contents, including the filesystem, will be overwritten. Cancellation may leave a partially erased target.", wrap=True))
        layout.addWidget(label("Type this exact filename or serial:  "+info["serial"], wrap=True))
        confirmation = QLineEdit()
        confirmation.setAccessibleName("Target confirmation")
        layout.addWidget(confirmation)
        consent = QCheckBox("I have selected the intended disposable target and kept any needed backup.")
        layout.addWidget(consent)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        proceed = buttons.addButton("Overwrite & verify", QDialogButtonBox.ButtonRole.AcceptRole)
        proceed.setObjectName("danger")
        proceed.setEnabled(False)
        def update():
            proceed.setEnabled(confirmation.text() == info["serial"] and consent.isChecked())
        confirmation.textChanged.connect(update)
        consent.toggled.connect(update)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        refs = references(self.reference_file) if self.reference_file and path == self.target else None
        def done(record):
            self.verification_details.setPlainText(json.dumps(record, indent=2))
            self.status_label.setText("Overwrite VERIFIED. Ed25519 evidence saved. Recovery scan found no supported candidates.")
            self.progress_bar.setValue(1000)
        self.execute(lambda progress, cancel: erase(path, info["serial"], self.store.root, refs, device, progress, cancel), done)

    def refresh_evidence(self):
        self.records = self.store.records()
        fill_table(self.records_table, [(r["payload"]["id"][:19], Path(r["payload"]["target"]["path"]).name, r["payload"]["verification"]["bytes_checked"], r["payload"]["issued_at"][:19]) for r in self.records])
        self.integrity_label.setText(f"Audit chain {'intact' if self.store.check() else 'FAILED'} · {len(self.store.events())} linked events · {len(self.records)} signed records")

    def current_record(self):
        row = self.records_table.currentRow()
        return self.records[row] if 0 <= row < len(self.records) else None

    def view_record(self, *_):
        record = self.current_record()
        if not record:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Signed verification evidence")
        dialog.resize(760, 650)
        layout = QVBoxLayout(dialog)
        layout.addWidget(label("Ed25519 signature "+("VALID" if verify_record(record) else "INVALID"), "panelTitle"))
        body = QPlainTextEdit(json.dumps(record, indent=2))
        body.setReadOnly(True)
        layout.addWidget(body)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(dialog.reject)
        layout.addWidget(close)
        dialog.exec()

    def export_record(self):
        record = self.current_record()
        if record:
            self.export_json(record, record["payload"]["id"]+".epcert.json")

    def export_json(self, value, default):
        path, _ = QFileDialog.getSaveFileName(self, "Export evidence", str(self.workspace/default), "JSON (*.json)")
        if path:
            try:
                Path(path).write_text(json.dumps(value, indent=2)+"\n")
            except OSError as error:
                self.on_error(str(error))

    def export_audit(self):
        self.export_json({"schema": "eraseproof.audit.v1", "intact": self.store.check(), "events": self.store.events()}, "eraseproof-audit.json")

    def check_record(self):
        path, _ = QFileDialog.getOpenFileName(self, "Verify signed evidence", str(self.workspace), "JSON (*.json)")
        if path:
            try:
                valid = verify_record(json.loads(Path(path).read_text()))
                QMessageBox.information(self, "Evidence verification", "Signature and payload match. The embedded key is self-signed; operator identity is not independently authenticated." if valid else "Record integrity failed. Payload, signature or signer fingerprint differs.")
            except Exception as error:
                self.on_error(str(error))

    def refresh_devices(self):
        def done(inventory):
            self.device_rows = [item for root in inventory for item in descendants(root)]
            fill_table(self.devices_table, [(item["name"], (item.get("model") or "").strip(), f"{int(item.get('size') or 0)/1024**3:.2f} GiB", (item.get("serial") or "").strip(), ", ".join(p for p in item.get("mountpoints") or [] if p) or ("Read-only" if item.get("ro") else "Unmounted")) for item in self.device_rows])
            self.status_label.setText("Linux inventory refreshed. No device was modified.")
        self.execute(lambda progress, cancel: devices(), done)

    def select_device(self, *_):
        row = self.devices_table.currentRow()
        if row >= 0:
            self.set_target(self.device_rows[row]["name"])
            self.switch(2)

    def closeEvent(self, event):
        if self.job and self.job.isRunning():
            self.cancel()
            event.ignore()
            QMessageBox.information(self, "Operation is finishing", "Cancellation was requested. Wait for the operation to stop before closing. A partial overwrite will not be certified.")
        else:
            event.accept()


def main():
    application = QApplication.instance() or QApplication(sys.argv)
    application.setApplicationName("EraseProof")
    application.setStyle("Fusion")
    application.setStyleSheet(STYLE)
    window = MainWindow()
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())

# Evidence selection and export correction

Development build: `0.12.2.dev1`, branch `fix/evidence-record-interaction`.
This is a separately packaged development build, not a published release.

## Confirmed causes

Three failing regression tests reproduced distinct bugs in the previous code:

1. `MainWindow.execute()` disabled every `QTableWidget` during any background
   job. Evidence buttons were outside that lock, so an unselected Evidence table
   stopped receiving selection input while View and export buttons remained
   enabled. Their handlers silently returned when no current row existed.
2. `current_record()` used `currentRow()` as an index into `self.records`.
   Qt keeps its current index after `clearSelection()`, so a visibly unselected
   table could still export an old record.
3. `refresh_evidence()` replaced rows without retaining certificate identity.
   Certificates are returned newest first. Adding a record shifted the old row
   to another certificate, silently changing the subject of View/export.

Additional usability gaps were a low-contrast selection color, the default
multiple-selection mode, and no explicit Return/keypad-Enter activation.

Idle single-click and double-click activation worked in the baseline Qt test.
The double-click signal was already connected. Window/viewport hit tests at the
requested sizes found no intercepting overlay. This investigation does not claim
to have reproduced an additional idle-only VirtualBox event-delivery failure.
The confirmed busy-state and selection defects are corrected and tested.

The installed 0.12.1 executable's embedded `eraseproof.desktop` bytecode matched
the baseline source exactly after normalizing its compile filename. There was
no separate frozen implementation of this page. The rebuilt executable's
`desktop`, `imagecleanup`, and `ui_check` modules likewise match the fixed source.

## Implementation

Evidence now uses Qt single-row selection and retains normal arrow navigation.
Full certificate IDs live in `Qt.UserRole`; actions resolve the selected row
through an ID map, never through a stale row number or truncated display label.
Refresh blocks intermediate table signals, clears the old current item, and
restores the same full ID only when it still exists. A missing selection disables
View/JSON/PDF and displays instructions; direct handler calls also give feedback.

Double-click and both Enter keys open the exact signed JSON. Exports capture the
selected record before opening the chooser, so a concurrent refresh cannot
change which record is written. Dark-green/white highlighting persists after
focus moves to a button. Hover styling, accessible names, a selected-ID label,
and a two-column action grid preserve the existing visual design and keep
actions reachable through the page scroll container at 1024x768 and 1920x1080.

Read-only Evidence interaction remains available during a background storage
job. Existing target controls stay locked; no device, confirmation, overwrite,
recovery, signing, or certificate-verification algorithms were changed.

## Explicit removal of an overwritten image

The user clarified that the requested extra action should remove the entire
overwritten file. Select its successful whole-image overwrite record and use
**Delete overwritten image file…**. This is a separate, confirmed host-file
unlink; it is never triggered automatically by overwrite or by selecting a row.

The action requires an intact signed record, whole-image zero readback and a
successful independent attack. It reuses existing protected-path, symlink and
hard-link guards, refuses devices and attached images, pins the file identity,
reads every byte again, compares the full SHA-256 with the signed verification,
and checks for changes before unlinking through an opened parent directory.
Cancellation and mismatched confirmation leave the file in place.

This action does not alter the certificate, database, signing key or audit
history. Previously recovered files, reference originals, other files, host
snapshots and physical storage remnants are outside its scope. Ordinary Unix
directory permissions and concurrent-writer assumptions still apply, as with
the existing pinned-file erasure path.

## Repeatable validation

The fresh full source run passed **245 tests and 13 subtests**, with 10 tests
skipped because they require root/private mounts. All **27 new regression
cases** passed. Source and frozen Evidence interaction diagnostics both passed
all eight groups, including actual Qt save/confirmation dialogs. These results
do not stand in for the skipped privileged tests or manual VirtualBox acceptance.

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q -rs
QT_QPA_PLATFORM=offscreen PYTHONPATH=src .venv/bin/python \
  scripts/desktop-entry.py --check-evidence-ui
QT_QPA_PLATFORM=offscreen dist/EraseProof/EraseProof --check-evidence-ui
```

`tests/test_evidence_ui.py` contains real viewport clicks, double-clicks, button
clicks, arrow/Enter events, screenshot-pixel selection/hover checks, real Qt
filename and confirmation dialogs, refresh/reordering/removal cases, and
JSON/PDF checks against complete signed records. It checks database and key
bytes before/after read-only operations. Export tests also refresh/change the
selection while the save chooser is active to prove the captured record is used.

`tests/test_imagecleanup.py` exercises actual disposable image unlink, nonzero
data refusal, replacement after confirmation, modification of already-read
bytes, hard/symbolic links, cancellation, mismatched confirmation, attachment
refusal, evidence-directory exclusion, and ineligible/tampered records.

The opt-in `--check-evidence-ui` diagnostic runs the same eight acceptance groups
in source and inside the actual frozen executable. It uses temporary keys,
records and files only, including real Qt JSON/PDF save dialogs and confirmed
removal of a disposable zero-filled image. It never opens the real evidence
workspace. Pytest is not bundled or required by this diagnostic.

Package validation can additionally exercise the extracted executable:

```bash
.venv/bin/python scripts/verify-package.py \
  --artifacts qa/evidence-ui-fix/artifacts --evidence-ui
```

The local build platform is Ubuntu 26.04 LTS / Python 3.12 / PySide6 6.8.3.
The graphical XCB session was inaccessible from the execution sandbox, and no
Xvfb server was available. Offscreen checks sent actual Qt input events and
exercised modal dialogs; they were not startup-only tests. A manual Ubuntu
VirtualBox acceptance run remains unverified. A locally built binary is not
claimed compatible with earlier Ubuntu releases; build from source there.

## Install and run without replacing existing artifacts

The fixed bundle is `dist/EraseProof/EraseProof`. The separate native/source
archives and checksums are under `qa/evidence-ui-fix/artifacts/`.

Extract the new archive into a new application directory, keep the complete
`EraseProof` bundle together, and run its `EraseProof` executable. Install missing
system tools with its `install-runtime.sh` if needed. Its ordinary GUI uses the
existing `~/EraseProof` workspace; copying or regenerating the signing key is
neither necessary nor appropriate. Keep the existing evidence directory and
its permissions. Existing signed records remain compatible.

On an older Ubuntu installation, use this source branch, run
`bash scripts/setup-ubuntu.sh`, then `bash scripts/launch-ubuntu.sh`.
No release has been published and the existing 0.12.1 release archives have
not been overwritten.

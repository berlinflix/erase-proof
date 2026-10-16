# Bundled components

The native Linux distribution includes unmodified Python, Qt/PySide, Pillow,
cryptography, pypdf, ReportLab, qrcode and pyahocorasick components with their dependencies.
`BUILD-PACKAGES.txt` records the actual build environment versions. Available
wheel license/notice files are collected under `THIRD-PARTY-LICENSES`; DejaVu's
font license is also included beside the source font files.

PySide6 Essentials 6.8.3's wheel declares
`LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only` but supplies no license-text
files in its wheel metadata. The release therefore includes the GNU LGPLv3,
GPLv2 and GPLv3 texts separately. Qt and PySide shared libraries are unmodified
and remain separate files under `_internal`; the distribution does not prevent
replacing these libraries with compatible builds. Their upstream source and
notices are available through the Qt source repositories:

- [Qt for Python / PySide](https://code.qt.io/cgit/pyside/pyside-setup.git/)
- [Qt 6.8 source archives](https://download.qt.io/archive/qt/6.8/6.8.3/)
- [GNU LGPLv3](https://www.gnu.org/licenses/lgpl-3.0.html),
  [GPLv2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html),
  [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html)

System tools installed by apt are supplied by Ubuntu as separate packages.
The live image records all installed Ubuntu package versions in its filesystem
manifest and retains their package copyright files.

The EraseProof ext4 helper is built against Ubuntu's libext2fs and libcom_err,
provided by e2fsprogs. PyInstaller also collects ELF dependencies as separate
shared libraries. Ubuntu package copyright files for discovered system libraries
are collected under `THIRD-PARTY-LICENSES/Ubuntu-libraries`, with full common
license texts alongside them. The adapter invokes system tools with a clean
library environment; runtime tools are installed through apt. The source archive
includes the helper's complete C source and build command. Upstream implementation
and licensing notices are available in
[e2fsprogs](https://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git/) and Ubuntu's
`/usr/share/doc/e2fsprogs/copyright`.

The NTFS helper links Ubuntu's libntfs-3g. The release keeps its Ubuntu library
copyright notices alongside the other collected ELF dependencies.

`scripts/build-forensic-tools.sh` builds the upstream bulk_extractor 2.2.0 release
archive, pinned to SHA-256
`b9e15d40d711aa43590e1bf1a25d30943e3bad8371281d7c80d3803a6f34c268`.
It runs the upstream test suite before copying a stripped executable into the
native resources. E01 support is disabled; EraseProof uses raw sources. Source
and release licensing files are preserved under `docs/licenses/bulk-extractor`
and included in distribution documentation. The build recipe and original
archive remain available from
[the upstream release](https://github.com/simsong/bulk_extractor/releases/tag/v2.2.0).
Bundled helper executables use their collected shared libraries; system tools
continue to use the system library environment.

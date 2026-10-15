# Native architecture and implementation boundary

## Execution

```text
Qt desktop / CLI
      |
      +-- target discovery and plan policy (lsblk + stat + device identity)
      |
      +-- native recovery
      |     +-- chunked binary signature carver (PNG / PDF / JPEG / ZIP)
      |     +-- independent filesystem adapter (fls / icat)
      |
      +-- overwrite engine
      |     +-- pinned file descriptor, exclusive file lock
      |     +-- O_EXCL block-device open, explicit path + serial allowlist
      |     +-- actual bounded writes, fsync, cache-drop advice
      |     +-- complete byte read-back and reference search
      |     +-- recovery attack using the native carver
      |
      +-- evidence
            +-- Ed25519 local operator key
            +-- signed target / plan / before hash / after hash / measurements
            +-- SQLite certificate + audit append transaction
```

The native application runs Qt widgets directly. There is no web view, web server, hosted backend or remote data path. The GUI performs long-running engine operations in a background QThread and passes progress/results back through Qt signals. The CLI invokes the same engine.

## Trust boundaries

- A regular user can perform the filesystem-image experiment and recovery. The app never silently grants itself root access.
- Actual block-device writes require Linux device permissions. The engine only enables them for recognized virtual-disk models, a complete disk, a matching explicit path and exact serial, no mounted descendants, and a writable target. System-disk/mount refusal policy is checked again after opening the device. Linux's exclusive block-device open adds a kernel-level in-use check.
- Input paths are not interpolated into shell commands. The forensic and demo adapters pass argument arrays to installed system executables.
- Recovery sources are opened read-only. New extraction outputs use exclusive creation. Raw-device recovery refuses a destination on the same source device.
- Image writes refuse symbolic links, hard links, target identity changes, invalid reference manifests, empty images and unsupported filename suffixes. A cancelled write remains a real partial overwrite; it is not rolled back or certified.

## What is measured

The reference score counts matched unique aligned block hashes and matched metadata byte patterns against a provided baseline. It is not a measure of all possible recoverability. A missing baseline yields an unavailable score. Full zero read-back is an additional certificate requirement, even when reference score is zero.

The native carver scans all logical bytes in 4 MiB chunks. Candidate parsing is bounded to 256 MiB per file. PNG chunk CRCs are checked; ZIP members are CRC-checked after extraction. PDF/JPEG confidence currently reflects contiguous boundary evidence, not full semantic decoding or probability of correctness. The Sleuth Kit adapter supplies actual metadata-based deleted-file recovery independently of the carver.

## Delivered versus research milestones

Delivered: native GUI/CLI, real FAT32 creation and ordinary deletion, byte-matching recovery, a custom contiguous carver, actual image overwrite, complete read-back, reference search, signed audit evidence, read-only Linux discovery, and a guarded secondary-virtual-disk logical-overwrite path.

Still to implement and independently evaluate: targeted ext4/NTFS/FAT residue scrubbing, filesystem history/journals/snapshots, fragmentation reconstruction, media-aware ATA/NVMe firmware sanitization, HPA/DCO checks, a privileged broker with a smaller native/C I/O component, bootable live-USB packaging, trusted operator identities, PDF/QR verification, and measured comparisons with PhotoRec and other independent tools.

The default image experiment and GUI flow are tested in WSL Ubuntu. VirtualBox guest device I/O and physical media need separate acceptance tests; a VM result must not be presented as host SSD sanitization.

## API references used

- [Linux open(2): O_EXCL for block devices](https://man7.org/linux/man-pages/man2/open.2.html)
- [The Sleuth Kit fls](https://www.sleuthkit.org/sleuthkit/man/fls.html)
- [The Sleuth Kit icat](https://www.sleuthkit.org/sleuthkit/man/icat.html)
- [Qt for Python](https://doc.qt.io/qtforpython-6/)

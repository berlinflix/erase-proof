# Ubuntu 24.04 live image

The primary demo remains the native app inside your installed Ubuntu desktop.
The live image provides an additional boot environment built from Ubuntu's
signed archive packages. It does not contain an installer, a web server or a
command that automatically writes a physical disk.

## Build

Build the standalone application first. On Ubuntu x86-64, install the image
construction tools:

```bash
sudo apt-get install -y debootstrap squashfs-tools grub-common grub-pc-bin \
  grub-efi-amd64-bin xorriso mtools ubuntu-keyring python3
sudo bash scripts/build-live-ubuntu.sh "$PWD/dist/EraseProof" "$PWD/artifacts/EraseProof-live.iso"
```

The builder uses a private mount namespace and a new protected directory under
`/var/tmp/eraseproof-live.*`. It retains that directory for inspection. Mounts
are released when the process exits. It refuses an existing ISO output path.
It never invokes a disk-writing or USB-burning command.

Package indexes are verified against signed Ubuntu InRelease files. Large
downloads use bounded byte ranges and hashes; apt independently checks package
integrity again before installation. Verified caches survive network failures.
Resume an initialized build with the directory printed by the builder:

```bash
sudo bash scripts/build-live-ubuntu.sh --resume /var/tmp/eraseproof-live.BUILD_ID \
  "$PWD/dist/EraseProof" "$PWD/artifacts/EraseProof-live.iso"
```

The image contains the Qt app, Openbox/Xorg, forensic tools, capability tools,
the VM kernel package, and a package-version manifest. The `linux-image-virtual`
metapackage supplies Ubuntu's generic kernel with its base module set. Broad
physical-hardware firmware/extra-driver coverage is not included by default.
Extend `live-packages.txt` and evaluate the specific spare hardware before
using the image for that purpose. Secure Boot is not configured for this
custom image; use a test VM with Secure Boot disabled.

## Workspace persistence

The default live home directory is temporary. Export signed JSON/PDF records
and an audit checkpoint to a separate persistent destination before shutdown.
The native app displays a live-session reminder. For a persistent full case,
start the app with a private directory on a Linux filesystem:

```bash
ERASEPROOF_WORKSPACE=/path/on/persistent/linux-storage/EraseProof /opt/eraseproof/EraseProof
```

Private signing keys require Linux permission support. An exported report alone
does not preserve the private key or the case database for future operations.
Evidence must be on a different device from the one being erased.

## Boot checks

`verify-live.py` uses a disposable QEMU VM with no hard disks attached. It
captures the actual VGA screen and serial log. BIOS/UEFI GRUB checks boot the
real ISO; the optional direct-kernel route requests a generated-image engine
check through `eraseproof.selftest=1`.

```bash
sudo /path/to/build-venv/bin/python scripts/verify-live.py artifacts/EraseProof-live.iso \
  --output qa/live-bios
sudo /path/to/build-venv/bin/python scripts/verify-live.py artifacts/EraseProof-live.iso \
  --uefi --output qa/live-uefi
sudo /path/to/build-venv/bin/python scripts/verify-live.py artifacts/EraseProof-live.iso \
  --kernel /var/tmp/eraseproof-live.BUILD_ID/iso/casper/vmlinuz \
  --initrd /var/tmp/eraseproof-live.BUILD_ID/iso/casper/initrd \
  --output qa/live-engine
```

These checks require QEMU, OVMF for UEFI, and Pillow for screen conversion. KVM
is used when available; otherwise QEMU falls back to software emulation. The
engine check creates its own temporary FAT32 image, normally deletes files,
recovers and hash-matches four originals, overwrites/verifies the image and
checks its signed JSON/PDF/audit results. It never selects a block device.
The graphical screen still requires visual inspection.

Actual build/boot results are tracked in [MILESTONES.md](MILESTONES.md).
Oracle VirtualBox acceptance is deferred at the user's request.

The 0.3 image was built and booted on 16 October 2026 using QEMU/KVM. Its real
BIOS and UEFI GRUB routes reached the native desktop. Screens were reviewed at
1920×1080 and 1024×768; the smaller display uses a scrolling content area.
The independent direct-kernel check completed the four-file recovery/hash
comparison, full overwrite/read-back, signature, PDF attachment and audit
workflow inside the live guest. All three guests had no hard disks attached.
This validates the live software environment, not VirtualBox device access or
physical storage sanitization.

References: [Ubuntu casper](https://manpages.ubuntu.com/manpages/noble/man7/casper.7.html),
[GNU GRUB rescue image construction](https://www.gnu.org/software/grub/manual/grub/html_node/Invoking-grub_002dmkrescue.html).

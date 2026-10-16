#!/usr/bin/env bash
# Build an Ubuntu 24.04 live ISO. Never writes a physical disk or USB device.
set -euo pipefail
if [[ "$EUID" != 0 || "$(uname -m)" != x86_64 || ( $# != 2 && $# != 4 ) ]]; then
  echo "Usage (Ubuntu x86-64): sudo bash scripts/build-live-ubuntu.sh /path/to/dist/EraseProof /path/to/new.iso" >&2
  exit 1
fi
if [[ "${ERASEPROOF_LIVE_PRIVATE_NS:-}" != 1 ]]; then
  exec unshare --mount --propagation private -- env ERASEPROOF_LIVE_PRIVATE_NS=1 bash "$0" "$@"
fi
scripts="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
resume=""
if [[ $# == 4 && "$1" == --resume ]]; then
  resume="$(realpath -e -- "$2")"
  shift 2
fi
[[ $# == 2 ]] || { echo "Invalid arguments." >&2; exit 1; }
bundle="$(realpath -e -- "$1")"
output="$(realpath -m -- "$2")"
[[ -d "$bundle/_internal" && -x "$bundle/EraseProof" ]] || { echo "Build the standalone bundle first." >&2; exit 1; }
[[ "$output" == *.iso && ! -e "$output" && ! -L "$output" ]] || { echo "Choose a new .iso output path." >&2; exit 1; }
[[ -d "$(dirname -- "$output")" ]] || { echo "Output directory does not exist." >&2; exit 1; }
for executable in debootstrap mksquashfs grub-mkrescue xorriso chroot mount; do
  command -v "$executable" >/dev/null || { echo "Install debootstrap squashfs-tools grub-common grub-pc-bin grub-efi-amd64-bin xorriso mtools." >&2; exit 1; }
done
[[ -d /usr/lib/grub/i386-pc && -d /usr/lib/grub/x86_64-efi ]] || { echo "Both BIOS and EFI GRUB modules are required." >&2; exit 1; }
if [[ -n "$resume" ]]; then
  work="$resume"
  [[ "$work" == /var/tmp/eraseproof-live.* && -f "$work/ERASEPROOF_BUILD_ROOT" && "$(cat "$work/ERASEPROOF_BUILD_ROOT")" == "$work" && -f "$work/rootfs/etc/os-release" ]] || { echo "Not a managed initialized EraseProof rootfs." >&2; exit 1; }
else
  work="$(mktemp -d /var/tmp/eraseproof-live.XXXXXXXX)"
  chmod 700 "$work"
  printf '%s\n' "$work" > "$work/ERASEPROOF_BUILD_ROOT"
fi
root="$work/rootfs"
iso="$work/iso"
mkdir -p "$iso/casper" "$iso/boot/grub"
echo "Managed build directory: $work"
cleanup_mounts() {
  for target in "$root/dev/pts" "$root/sys" "$root/proc"; do
    if mountpoint -q "$target"; then umount "$target" || true; fi
  done
}
trap cleanup_mounts EXIT
if [[ -z "$resume" ]]; then
  debootstrap --arch=amd64 --variant=minbase --include=ca-certificates --keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg \
    noble "$root" https://archive.ubuntu.com/ubuntu
fi
cat > "$root/etc/apt/sources.list" <<'EOF'
deb https://archive.ubuntu.com/ubuntu noble main universe
deb https://archive.ubuntu.com/ubuntu noble-updates main universe
deb https://security.ubuntu.com/ubuntu noble-security main universe
EOF
cp --remove-destination /etc/resolv.conf "$root/etc/resolv.conf"
cat > "$root/usr/sbin/policy-rc.d" <<'EOF'
#!/bin/sh
exit 101
EOF
chmod 755 "$root/usr/sbin/policy-rc.d"
mount -t proc proc "$root/proc"
mount -t sysfs -o ro sysfs "$root/sys"
mkdir -p "$root/dev/pts"
mount -t devpts -o newinstance,ptmxmode=0666 devpts "$root/dev/pts"
ln -sf pts/ptmx "$root/dev/ptmx"
python3 "$scripts/fetch-ubuntu-indexes.py" "$root"
chroot "$root" /usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get update
python3 "$scripts/fetch-ubuntu-packages.py" "$root" --apt
mapfile -t packages < "$scripts/live-packages.txt"
chroot "$root" /usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
chroot "$root" locale-gen en_US.UTF-8
printf '%s\n' 'LANG=en_US.UTF-8' > "$root/etc/default/locale"
printf '%s\n' 'eraseproof' > "$root/etc/hostname"
printf '%s\n' '127.0.0.1 localhost' '127.0.1.1 eraseproof' > "$root/etc/hosts"
cat > "$root/etc/casper.conf" <<'EOF'
export USERNAME="eraseproof"
export USERFULLNAME="EraseProof Live"
export HOST="eraseproof"
export FLAVOUR="EraseProof"
export BUILD_SYSTEM="Ubuntu"
EOF
mkdir -p "$root/etc/systemd/system/getty@tty1.service.d" "$root/etc/skel/Desktop" "$root/opt"
cat > "$root/etc/systemd/system/getty@tty1.service.d/autologin.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin eraseproof --noclear %I $TERM
EOF
cat > "$root/etc/skel/.profile" <<'EOF'
if [ -z "${DISPLAY:-}" ] && [ "$(tty)" = /dev/tty1 ]; then
  exec startx -- -nolisten tcp
fi
EOF
cat > "$root/etc/skel/.xinitrc" <<'EOF'
#!/bin/sh
xsetroot -solid '#19382d'
openbox-session &
exec dbus-run-session -- /opt/eraseproof/EraseProof
EOF
chmod 755 "$root/etc/skel/.xinitrc"
install -m 755 "$scripts/live-boot-check.sh" "$root/usr/local/bin/eraseproof-boot-check"
mkdir -p "$root/usr/local/lib"
install -m 644 "$scripts/verify-frozen.py" "$root/usr/local/lib/eraseproof-verify-frozen.py"
install -m 644 "$scripts/eraseproof-boot-check.service" "$root/etc/systemd/system/eraseproof-boot-check.service"
mkdir -p "$root/etc/systemd/system/multi-user.target.wants"
ln -sf ../eraseproof-boot-check.service "$root/etc/systemd/system/multi-user.target.wants/eraseproof-boot-check.service"
app_stage="$(mktemp -d "$work/app-stage.XXXXXXXX")"
cp -a -- "$bundle/." "$app_stage/"
python3 "$scripts/release_permissions.py" "$app_stage" --root-owner
# A resumed build must not retain obsolete binaries from the previous bundle.
# Keep the old application recoverable outside the rootfs snapshot.
if [[ -e "$root/opt/eraseproof" ]]; then
  mv -T -- "$root/opt/eraseproof" "$work/previous-app-$(date +%s%N)"
fi
mv -T -- "$app_stage" "$root/opt/eraseproof"
mkdir -p "$iso/.disk"
"$bundle/EraseProof" --cli --version > "$iso/.disk/eraseproof-version"
printf '%s\n' 'EraseProof Ubuntu 24.04 Live - amd64' > "$iso/.disk/info"
touch "$iso/.disk/base_installable"
cat > "$root/etc/skel/Desktop/EraseProof.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=EraseProof
Exec=/opt/eraseproof/EraseProof
Terminal=false
Categories=System;Utility;
EOF
cat > "$root/etc/skel/Desktop/Terminal.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Terminal
Exec=xterm
Terminal=false
EOF
chmod 755 "$root/etc/skel/Desktop/"*.desktop
chroot "$root" update-initramfs -u -k all
chroot "$root" apt-get clean
printf '%s\n' '# Configure a resolver through the live network session if needed.' > "$root/etc/resolv.conf"
truncate -s 0 "$root/etc/machine-id"
chroot "$root" dpkg-query -W --showformat='${Package} ${Version}\n' > "$iso/casper/filesystem.manifest"
cp -- "$(find "$root/boot" -maxdepth 1 -name 'vmlinuz-*' | sort -V | tail -1)" "$iso/casper/vmlinuz"
cp -- "$(find "$root/boot" -maxdepth 1 -name 'initrd.img-*' | sort -V | tail -1)" "$iso/casper/initrd"
cleanup_mounts
for target in "$root/dev/pts" "$root/sys" "$root/proc"; do
  if mountpoint -q "$target"; then
    echo "A build mount remains active; filesystem snapshot refused: $target" >&2
    exit 1
  fi
done
du -sx --block-size=1 "$root" | cut -f1 > "$iso/casper/filesystem.size"
mksquashfs "$root" "$iso/casper/filesystem.squashfs" -comp xz -noappend -processors 4 -no-progress
bash "$scripts/assemble-live-iso.sh" "$work" "$output"

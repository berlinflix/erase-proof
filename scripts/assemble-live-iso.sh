#!/usr/bin/env bash
# Resume ISO assembly from a completed, managed squashfs/kernel/initrd stage.
set -euo pipefail
[[ $# == 2 ]] || { echo "Usage: assemble-live-iso.sh MANAGED_BUILD_DIRECTORY NEW_ISO_PATH" >&2; exit 1; }
work="$(realpath -e -- "$1")"
output="$(realpath -m -- "$2")"
[[ "$work" == /var/tmp/eraseproof-live.* && -f "$work/ERASEPROOF_BUILD_ROOT" && "$(cat "$work/ERASEPROOF_BUILD_ROOT")" == "$work" ]] || { echo "Not a managed EraseProof build directory." >&2; exit 1; }
[[ "$output" == *.iso && ! -e "$output" && ! -L "$output" ]] || { echo "Choose a new regular .iso output path." >&2; exit 1; }
iso="$work/iso"
for file in filesystem.squashfs vmlinuz initrd; do
  [[ -s "$iso/casper/$file" && -f "$iso/casper/$file" && ! -L "$iso/casper/$file" ]] || { echo "Missing completed live stage: $file" >&2; exit 1; }
done
unsquashfs -s "$iso/casper/filesystem.squashfs" >/dev/null
mkdir -p "$iso/boot/grub"
cat > "$iso/boot/grub/grub.cfg" <<'EOF'
set timeout=5
set default=0
menuentry "EraseProof - Ubuntu 24.04 Live" {
  linux /casper/vmlinuz boot=casper quiet username=eraseproof hostname=eraseproof noprompt noeject console=tty0 console=ttyS0,115200n8 ---
  initrd /casper/initrd
}
menuentry "EraseProof - safe graphics" {
  linux /casper/vmlinuz boot=casper quiet username=eraseproof hostname=eraseproof noprompt noeject nomodeset ---
  initrd /casper/initrd
}
EOF
grub-script-check "$iso/boot/grub/grub.cfg"
(cd "$iso" && find . -type f ! -name md5sum.txt -print0 | LC_ALL=C sort -z | xargs -0 md5sum > md5sum.txt)
grub-mkrescue -o "$output" "$iso" -volid ERASEPROOF_LIVE
sha256sum "$output" > "$output.sha256"
printf '%s\n' "ISO built: $output" "SHA-256: $output.sha256" \
  "Build workspace retained: $work" "No physical disks were written. Secure Boot is not configured."

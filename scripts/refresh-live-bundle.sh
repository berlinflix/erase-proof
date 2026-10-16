#!/usr/bin/env bash
# Refresh an already initialized, unmounted managed rootfs; no host disks used.
set -euo pipefail
[[ "$EUID" == 0 && $# == 3 ]] || { echo 'Usage: sudo refresh-live-bundle.sh MANAGED_BUILD BUNDLE NEW_ISO'; exit 1; }
work="$(realpath -e -- "$1")"
bundle="$(realpath -e -- "$2")"
output="$(realpath -m -- "$3")"
[[ "$work" == /var/tmp/eraseproof-live.* && -f "$work/ERASEPROOF_BUILD_ROOT" && "$(cat "$work/ERASEPROOF_BUILD_ROOT")" == "$work" ]] || { echo 'Not a managed build root'; exit 1; }
[[ -x "$bundle/EraseProof" && -d "$bundle/_internal" && -d "$bundle/THIRD-PARTY-LICENSES" ]] || { echo 'Package the verified bundle and notices first'; exit 1; }
[[ "$output" == *.iso && ! -e "$output" && ! -L "$output" ]] || { echo 'Choose a new ISO file'; exit 1; }
root="$work/rootfs"
for target in "$root/dev/pts" "$root/sys" "$root/proc"; do
  if mountpoint -q "$target"; then echo "Build mount is active: $target"; exit 1; fi
done
grep -q '^CONFIG_SQUASHFS_ZSTD=y' "$(find "$root/boot" -maxdepth 1 -name 'config-*' | sort -V | tail -1)" || { echo 'Live kernel lacks built-in SquashFS zstd support'; exit 1; }
scripts="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
stage="$(mktemp -d "$work/app-stage.XXXXXXXX")"
cp -a -- "$bundle/." "$stage/"
python3 "$scripts/release_permissions.py" "$stage" --root-owner
if [[ -e "$root/opt/eraseproof" ]]; then
  mv -T -- "$root/opt/eraseproof" "$work/previous-app-$(date +%s%N)"
fi
mv -T -- "$stage" "$root/opt/eraseproof"
"$bundle/EraseProof" --cli --version > "$work/iso/.disk/eraseproof-version"
du -sx --block-size=1 "$root" | cut -f1 > "$work/iso/casper/filesystem.size"
mksquashfs "$root" "$work/iso/casper/filesystem.squashfs" -comp zstd -Xcompression-level 15 -noappend -processors 4 -no-progress
bash "$scripts/assemble-live-iso.sh" "$work" "$output"

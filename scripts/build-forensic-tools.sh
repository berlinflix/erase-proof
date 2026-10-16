#!/usr/bin/env bash
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
vendor_cache="${ERASEPROOF_VENDOR_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/eraseproof/vendor}"
version=2.2.0
archive_hash=b9e15d40d711aa43590e1bf1a25d30943e3bad8371281d7c80d3803a6f34c268
archive="$vendor_cache/bulk_extractor-$version.tar.gz"
source_dir="$vendor_cache/bulk_extractor-$version"
mkdir -p "$vendor_cache" "$project_root/src/eraseproof/resources/native"
if [[ ! -f "$archive" ]]; then
  curl --fail --location --retry 2 --output "$archive.download" \
    "https://github.com/simsong/bulk_extractor/releases/download/v$version/bulk_extractor-$version.tar.gz"
  printf '%s  %s\n' "$archive_hash" "$archive.download" | sha256sum --check -
  mv -- "$archive.download" "$archive"
fi
printf '%s  %s\n' "$archive_hash" "$archive" | sha256sum --check -
if [[ ! -d "$source_dir" ]]; then
  tar -xzf "$archive" -C "$vendor_cache"
fi
cd "$source_dir"
if [[ ! -f .eraseproof-tested.sha256 ]] || ! sha256sum --check --status .eraseproof-tested.sha256; then
  echo "Building and testing checksum-pinned bulk_extractor $version."
  ./configure --disable-libewf --prefix="$vendor_cache/runtime" > configure-eraseproof.log 2>&1 || {
    tail -n 40 configure-eraseproof.log >&2; exit 1;
  }
  make -j "${ERASEPROOF_BUILD_JOBS:-2}" > build-eraseproof.log 2>&1 || {
    tail -n 40 build-eraseproof.log >&2; exit 1;
  }
  make check -j "${ERASEPROOF_BUILD_JOBS:-2}" > check-eraseproof.log 2>&1 || {
    tail -n 60 check-eraseproof.log >&2; exit 1;
  }
  sha256sum src/bulk_extractor > .eraseproof-tested.sha256
fi
install -m 755 src/bulk_extractor "$project_root/src/eraseproof/resources/native/bulk_extractor"
strip --strip-unneeded "$project_root/src/eraseproof/resources/native/bulk_extractor"
license_dir="$project_root/docs/licenses/bulk-extractor"
mkdir -p "$license_dir"
cp -- LICENSE.md COPYING AUTHORS "$license_dir/"
cp -R -- licenses "$license_dir/"
echo "Built tested bulk_extractor $version for raw-image verification (E01 disabled)."

#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
mkdir -p src/eraseproof/resources/native
stage="$(mktemp -d src/eraseproof/resources/native/.build.XXXXXXXX)"
trap 'rm -f -- "$stage/"*; rmdir -- "$stage"' EXIT
fuzzy_library="$(cc -print-file-name=libfuzzy.so.2)"
cp --dereference "$fuzzy_library" "$stage/libfuzzy.so.2"
cc -std=c11 -O2 -fPIC -shared -Wall -Wextra -Werror \
  -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wl,-z,relro,-z,now \
  native/firmware.c -o "$stage/liberaseproof_firmware.so"
cc -std=c11 -O2 -fPIC -shared -Wall -Wextra -Werror \
  -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wl,-z,relro,-z,now \
  native/jpeg.c -ljpeg -o "$stage/liberaseproof_jpeg.so"
cc -std=c11 -O2 -fPIC -shared -Wall -Wextra -Werror \
  -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wl,-z,relro,-z,now \
  native/sqlite.c -lsqlite3 -o "$stage/liberaseproof_sqlite.so"
cc -std=c11 -O2 -fPIC -shared -Wall -Wextra -Werror \
  -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wl,-z,relro,-z,now \
  native/io.c -o "$stage/liberaseproof_io.so"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wl,-z,relro,-z,now \
  native/ext4.c -lext2fs -lcom_err -o "$stage/eraseproof-ext4"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wl,-z,relro,-z,now \
  native/ext4_journal.c -lext2fs -lcom_err -o "$stage/eraseproof-ext4-journal"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wl,-z,relro,-z,now \
  native/ntfs.c -lntfs-3g -o "$stage/eraseproof-ntfs"
# Atomic replacement preserves the mapped inode of every running operation.
# Truncating a loaded shared library can corrupt calls in an existing process.
for file in "$stage/"*; do
  mv -fT -- "$file" "src/eraseproof/resources/native/$(basename -- "$file")"
done
echo 'Built unprivileged Linux I/O and filesystem adapters.'

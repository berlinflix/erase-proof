#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
mkdir -p src/eraseproof/resources/native
cc -std=c11 -O2 -fPIC -shared -Wall -Wextra -Werror \
  -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wl,-z,relro,-z,now \
  native/io.c -o src/eraseproof/resources/native/liberaseproof_io.so
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wl,-z,relro,-z,now \
  native/ext4.c -lext2fs -lcom_err -o src/eraseproof/resources/native/eraseproof-ext4
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wl,-z,relro,-z,now \
  native/ext4_journal.c -lext2fs -lcom_err -o src/eraseproof/resources/native/eraseproof-ext4-journal
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wl,-z,relro,-z,now \
  native/ntfs.c -lntfs-3g -o src/eraseproof/resources/native/eraseproof-ntfs
echo 'Built unprivileged Linux I/O and filesystem adapters.'

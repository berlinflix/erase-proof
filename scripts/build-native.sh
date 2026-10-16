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
echo 'Built unprivileged Linux I/O library.'

#!/bin/bash -e
if [[ "${TARGETARCH}" == "amd64" ]]; then
    CARGO_INCREMENTAL=0 cargo build --target x86_64-unknown-linux-gnu $*
elif [[ "${TARGETARCH}" == "arm64" ]]; then
    PKG_CONFIG_ALLOW_CROSS=1 \
    RUSTFLAGS="-C linker=aarch64-linux-gnu-gcc -L/usr/aarch64-linux-gnu/lib -L/build/sysroot/usr/lib/aarch64-linux-gnu" \
    C_INCLUDE_PATH=/build/sysroot/usr/include \
    JEMALLOC_SYS_WITH_LG_PAGE=16 \
    cargo build --target aarch64-unknown-linux-gnu $*
fi

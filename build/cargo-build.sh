#!/bin/bash -e
if [[ "${TARGETARCH}" == "amd64" ]]; then
    CARGO_INCREMENTAL=0 cargo build --target x86_64-unknown-linux-gnu $*
elif [[ "${TARGETARCH}" == "arm64" ]]; then
    PKG_CONFIG_ALLOW_CROSS=1 \
    RUSTFLAGS="-C linker=aarch64-linux-gnu-gcc -L/usr/aarch64-linux-gnu/lib -L/build/sysroot/usr/lib/aarch64-linux-gnu" \
    C_INCLUDE_PATH=/build/sysroot/usr/include \
    OPENSSL_LIB_DIR=/build/sysroot/usr/lib/aarch64-linux-gnu \
    OPENSSL_INCLUDE_DIR=/build/sysroot/usr/include/aarch64-linux-gnu \
    PYO3_CROSS_INCLUDE_DIR=/build/sysroot/usr/include \
    PYO3_CROSS_LIB_DIR=/build/sysroot/usr/ \
    PYO3_CROSS_PYTHON_VERSION=3.9 \
    cargo build --target aarch64-unknown-linux-gnu $*
fi

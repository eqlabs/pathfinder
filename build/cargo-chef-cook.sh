#!/bin/bash -ex
if [[ "${TARGETARCH}" == "amd64" ]]; then
    MLIR_SYS_190_PREFIX="/usr/lib/llvm-19" \
        LLVM_SYS_191_PREFIX="/usr/lib/llvm-19" \
        TABLEGEN_190_PREFIX="/usr/lib/llvm-19" \
        CARGO_BUILD_TARGET=x86_64-unknown-linux-gnu \
        cargo chef cook $*
elif [[ "${TARGETARCH}" == "arm64" ]]; then
    PKG_CONFIG_ALLOW_CROSS=1 \
        RUSTFLAGS="-C linker=aarch64-linux-gnu-gcc -L/usr/aarch64-linux-gnu/lib -L/build/sysroot/usr/lib/aarch64-linux-gnu" \
        C_INCLUDE_PATH=/build/sysroot/usr/include \
        JEMALLOC_SYS_WITH_LG_PAGE=16 \
        CARGO_BUILD_TARGET=aarch64-unknown-linux-gnu \
        cargo chef cook $*
fi

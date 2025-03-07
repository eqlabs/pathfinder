#!/bin/bash -e
if [[ "${TARGETARCH}" == "amd64" ]]; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y pkg-config libzstd-dev protobuf-compiler make llvm-19 llvm-19-dev llvm-19-runtime clang-19 clang-tools-19 lld-19 libpolly-19-dev libmlir-19-dev mlir-19-tools build-essential
elif [[ "${TARGETARCH}" == "arm64" ]]; then
    echo "deb [arch=arm64] http://deb.debian.org/debian bookworm main" >>/etc/apt/sources.list
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y pkg-config libzstd-dev protobuf-compiler gcc-aarch64-linux-gnu libc6-arm64-cross libc6-dev-arm64-cross make
    apt-get download libzstd-dev:arm64
    mkdir -p /build/sysroot
    dpkg -x libzstd-dev_*.deb /build/sysroot/
    rustup target add aarch64-unknown-linux-gnu
fi

#!/bin/bash -e
if [[ "${TARGETARCH}" == "amd64" ]]; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y pkg-config libssl-dev protobuf-compiler
elif [[ "${TARGETARCH}" == "arm64" ]]; then
    echo "deb [arch=arm64] http://deb.debian.org/debian bookworm main" >>/etc/apt/sources.list
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y libssl-dev protobuf-compiler gcc-aarch64-linux-gnu libc6-arm64-cross libc6-dev-arm64-cross
    apt-get download libssl-dev:arm64 libssl3:arm64
    mkdir -p /build/sysroot
    dpkg -x libssl-dev_*.deb /build/sysroot/
    dpkg -x libssl3_*.deb /build/sysroot/
    rustup target add aarch64-unknown-linux-gnu
fi

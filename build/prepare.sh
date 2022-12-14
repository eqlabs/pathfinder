#!/bin/bash -e
if [[ "${TARGETARCH}" == "amd64" ]]; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y libssl-dev
elif [[ "${TARGETARCH}" == "arm64" ]]; then
    echo "deb [arch=arm64] http://deb.debian.org/debian bullseye main" >>/etc/apt/sources.list
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y libssl-dev gcc-aarch64-linux-gnu libc6-arm64-cross libc6-dev-arm64-cross
    apt-get download libssl-dev:arm64 libssl1.1:arm64
    mkdir -p /build/sysroot
    dpkg -x libssl-dev_*.deb /build/sysroot/
    dpkg -x libssl1.1_*.deb /build/sysroot/
    rustup target add aarch64-unknown-linux-gnu
fi

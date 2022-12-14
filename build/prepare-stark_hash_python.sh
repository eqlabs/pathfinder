#!/bin/bash -e
if [[ "${TARGETARCH}" == "amd64" ]]; then
    echo "nothing to do"
elif [[ "${TARGETARCH}" == "arm64" ]]; then
    echo "deb [arch=arm64] http://deb.debian.org/debian bullseye main" >>/etc/apt/sources.list
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y gcc-aarch64-linux-gnu libc6-arm64-cross libc6-dev-arm64-cross
    apt-get download libpython3.9-dev:arm64 libpython3.9:arm64 libpython3.9-minimal:arm64 python3.9:arm64 python3-dev:arm64 libpython3.9-stdlib:arm64
    mkdir -p /build/sysroot
    dpkg -x python3.9_*.deb /build/sysroot/
    dpkg -x python3-dev_*.deb /build/sysroot/
    dpkg -x libpython3.9_*.deb /build/sysroot/
    dpkg -x libpython3.9-minimal_*.deb /build/sysroot/
    dpkg -x libpython3.9-dev_*.deb /build/sysroot/
    dpkg -x libpython3.9-stdlib_*.deb /build/sysroot/
    cd /build/sysroot/usr/lib/aarch64-linux-gnu
    ln -s libpython3.9.so libpython.so 
    ln -s ../python3.9/_sysconfigdata__linux_aarch64-linux-gnu.py _sysconfigdata__linux_aarch64-linux-gnu.py
    rustup target add aarch64-unknown-linux-gnu
fi

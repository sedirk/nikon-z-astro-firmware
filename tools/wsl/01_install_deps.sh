#!/bin/sh
# Run as root inside WSL: installs the Z6 QEMU build dependencies listed in the
# pinned upstream docs/build.md, plus ARM disassembly/debug tools for analysis.
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update
# Upstream build.md list (419a1f2).
apt-get install -y build-essential ninja-build pkg-config python3-venv \
    libglib2.0-dev libpixman-1-dev zlib1g-dev libfdt-dev
# Analysis tools (not required by upstream).
apt-get install -y gdb-multiarch binutils-arm-none-eabi xz-utils file
echo "--- versions"
gcc --version | head -1
ninja --version
python3 --version
gdb-multiarch --version | head -1
arm-none-eabi-objdump --version | head -1
dpkg-query -W -f='${Package} ${Version}\n' build-essential ninja-build pkg-config \
    python3-venv libglib2.0-dev libpixman-1-dev zlib1g-dev libfdt-dev \
    gdb-multiarch binutils-arm-none-eabi

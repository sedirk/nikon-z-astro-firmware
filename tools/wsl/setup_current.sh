#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Dependency installation requires Linux root'; exit 1; }
export DEBIAN_FRONTEND=noninteractive
if ! id z6lab >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash z6lab
fi
# The build account has no password or sudo membership. Admin operations use
# explicit `wsl -u root`; firmware and builds run as z6lab.
apt-get update
apt-get install -y build-essential ninja-build pkg-config python3-venv \
    libglib2.0-dev libpixman-1-dev zlib1g-dev libfdt-dev \
    gdb-multiarch binutils-arm-none-eabi xz-utils file
python3 --version
gcc --version
ninja --version
printf 'DEPENDENCIES_COMPLETE\n'

#!/bin/sh
# Run as the normal WSL user after 02_build.sh. Firmware-free checks from the pinned
# upstream docs/testing.md; none of these load Nikon firmware.
set -eu
REPO=$HOME/z6lab/z6-qemu
QEMU=$REPO/.build/build/qemu-system-arm
cd "$REPO"
. .venv/bin/activate
echo "--- verify_release"; python tools/verify_release.py
echo "--- tests/run.sh";   sh tests/run.sh
echo "--- make_cmos";      python tools/make_cmos.py
echo "--- test_irq99";     python tests/test_irq99.py --qemu "$QEMU"
echo "--- counter_timing"; python tests/test_counter_timing.py --qemu "$QEMU"
echo "--- done"

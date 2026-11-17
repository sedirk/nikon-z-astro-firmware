#!/bin/sh
# Run as the normal WSL user (not root). Copies the pinned z6-qemu source from the
# Windows work tree into WSL ext4, creates the venv, checks the source inventory and
# builds qemu-system-arm offline from the hash-checked QEMU 10.2.4 archive.
set -eu
WIN="$(cd "$(dirname "$0")/../.." && pwd)"
SRC=$WIN/work/src/z6-qemu-419a1f2a91a1f2d3a0209027c29606475f7fe26f
ARCHIVE=$WIN/work/dl/qemu-10.2.4.tar.xz
LAB=$HOME/z6lab
REPO=$LAB/z6-qemu
JOBS=${JOBS:-6}

mkdir -p "$LAB"
if [ ! -d "$REPO" ]; then
    cp -a "$SRC" "$REPO"
    # ZIP extraction on Windows may leave CRLF-free files but drops exec bits.
    chmod +x "$REPO"/tests/run.sh
fi
cd "$REPO"
echo "--- source inventory"
python3 tools/verify_release.py
echo "--- venv"
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip freeze
echo "--- archive"
sha256sum "$ARCHIVE"
echo "--- build (jobs=$JOBS)"
python tools/build.py --archive "$ARCHIVE" --jobs "$JOBS"
sha256sum .build/build/qemu-system-arm
cat .local/build-manifest.json

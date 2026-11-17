#!/bin/sh
# Run as a normal Linux user; takes the mounted project root as its first arg.
set -eu
PROJECT=${1:?Pass the Linux path to Z6_firmware}
LAB="$HOME/z6lab"
REPO="$LAB/z6-qemu"
SOURCE="$PROJECT/work/src/z6-qemu-419a1f2a91a1f2d3a0209027c29606475f7fe26f"
ARCHIVE="$PROJECT/work/dl/qemu-10.2.4.tar.xz"
JOBS=${JOBS:-8}
[ "$(id -u)" -ne 0 ] || { echo 'Build as a normal Linux user'; exit 1; }
mkdir -p "$LAB"
if [ ! -d "$REPO" ]; then
    cp -a "$SOURCE" "$REPO"
fi
cd "$REPO"
python3 tools/verify_release.py
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
WHEELS="$PROJECT/work/wheels/linux312"
if [ -d "$WHEELS" ]; then
    export PIP_NO_INDEX=1
    export PIP_FIND_LINKS="$WHEELS"
fi
python -m pip install -r requirements.txt meson==1.9.0 pycotap==1.3.1
python -m pip freeze
python tools/build.py --archive "$ARCHIVE" --jobs "$JOBS"
sh tests/run.sh
python tools/make_cmos.py
python tests/test_irq99.py --qemu .build/build/qemu-system-arm
python tests/test_counter_timing.py --qemu .build/build/qemu-system-arm
mkdir -p "$LAB/fw"
python - "$PROJECT" "$LAB/fw" <<'PY'
from pathlib import Path
import hashlib,sys
src=Path(sys.argv[1])/'firmware/decoded/eg1620_038000.bi'
dst=Path(sys.argv[2])/'eg1620_038000.bi'
data=src.read_bytes()
assert hashlib.sha256(data).hexdigest()=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
if dst.exists():
    assert dst.read_bytes()==data
else:
    dst.write_bytes(data)
dst.chmod(0o444)
PY
printf 'BUILD_AND_TESTS_COMPLETE\n'

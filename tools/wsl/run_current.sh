#!/bin/sh
# Launch the unmodified upstream controller after build_current.sh succeeds.
set -eu
REPO="$HOME/z6lab/z6-qemu"
FW="$HOME/z6lab/fw/eg1620_038000.bi"
cd "$REPO"
. .venv/bin/activate
exec python tools/interactive.py --firmware "$FW" --port 8787 "$@"

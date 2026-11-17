#!/bin/sh
# Run as the normal WSL user. Makes a read-only working copy of the official MAIN
# (the project's firmware/ files are never passed to the emulator directly) and
# starts the pinned upstream browser controller. Extra arguments are passed through,
# e.g.: sh 04_run.sh --profile menu
#       sh 04_run.sh --profile shooting --photo-liveview
set -eu
WIN="$(cd "$(dirname "$0")/../.." && pwd)"
REPO=$HOME/z6lab/z6-qemu
FW=$HOME/z6lab/fw/eg1620_038000.bi
mkdir -p "$(dirname "$FW")"
if [ ! -f "$FW" ]; then
    cp "$WIN/firmware/decoded/eg1620_038000.bi" "$FW"
    chmod 444 "$FW"
fi
echo "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c  $FW" | sha256sum -c -
cd "$REPO"
. .venv/bin/activate
exec python tools/interactive.py --firmware "$FW" --port 8787 "$@"

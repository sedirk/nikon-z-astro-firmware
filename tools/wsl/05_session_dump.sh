#!/bin/sh
# Copy one controller session directory (default: current session) into the
# project's logs folder and list it. Usage: sh 05_session_dump.sh [session-id] [dest-dir]
set -eu
SESS=$HOME/z6lab/z6-qemu/.local/sessions
ID=${1:-$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["session"])' "$SESS/current.json")}
D=$SESS/$ID
WIN="$(cd "$(dirname "$0")/../.." && pwd)"
DEST=${2:-"$WIN/logs/sessions"}/$ID
echo "session: $D -> $DEST"
mkdir -p "$DEST"
cp -a "$D"/. "$DEST"/
cd "$DEST" && sha256sum *

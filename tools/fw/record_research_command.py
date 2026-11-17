"""Record one local research command without shell interpolation or overwrites."""
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import subprocess
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--record', type=Path, required=True)
p.add_argument('command', nargs=argparse.REMAINDER)
a = p.parse_args()
command = a.command[1:] if a.command[:1] == ['--'] else a.command
if not command:
    p.error('a command is required')
a.record.mkdir(parents=True, exist_ok=False)
meta = dict(argv=command, cwd=str(Path.cwd()),
            started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            recorder_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
(a.record / 'command.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
start = time.monotonic()
with (a.record / 'stdout.txt').open('wb') as stdout, (a.record / 'stderr.txt').open('wb') as stderr:
    result = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)
meta.update(exit_code=result.returncode, elapsed_seconds=round(time.monotonic() - start, 3))
(a.record / 'command.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
print(json.dumps(meta, indent=2))
raise SystemExit(result.returncode)

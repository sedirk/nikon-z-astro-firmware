"""Read-only, path-independent verification of the transfer package (stdlib)."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'manifests/transfer_manifest_2026-11-02.json'

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def main():
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
    failures = []
    skipped_git = 0
    checked = 0
    for row in manifest['files']:
        rel = PurePosixPath(row['path'])
        if rel.is_absolute() or '..' in rel.parts:
            raise ValueError(f'Unsafe manifest path: {rel}')
        # Git metadata changes during ordinary Git operations; ZIP verification
        # at creation covers it, while portable verification focuses on data.
        if '.git' in rel.parts:
            skipped_git += 1
            continue
        path = ROOT.joinpath(*rel.parts)
        if not path.is_file():
            failures.append({'path': str(rel), 'reason': 'missing'})
        elif path.stat().st_size != row['bytes'] or digest(path) != row['sha256']:
            failures.append({'path': str(rel), 'reason': 'size/hash mismatch'})
        checked += 1
    print(json.dumps({'root': str(ROOT), 'checked_files': checked,
                      'mutable_git_metadata_skipped': skipped_git,
                      'failures': failures, 'ok': not failures},
                     ensure_ascii=True, indent=2))
    return 1 if failures else 0

if __name__ == '__main__':
    sys.exit(main())

"""Archive research sources and build a complete, verified transfer ZIP.

Uses only Python standard-library code. Downloaded source is never executed.
The ZIP is written beside the project to avoid recursive inclusion/staging.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DATE = '2026-11-02'
INDEX = ROOT / f'references/transfer_sources_{DATE}.json'
MANIFEST = ROOT / f'manifests/transfer_manifest_{DATE}.json'
OUTPUT = ROOT.parent / f'Z6_firmware_handoff_{DATE}.zip'

VERSIONS = {
    'z6-qemu': ('WonderLantern/z6-qemu', '419a1f2a91a1f2d3a0209027c29606475f7fe26f'),
    'z9-qemu': ('WonderLantern/z9-qemu', 'deb3a75df1795924e9be8f814d9a24ce6b439a67'),
    'z72-qemu': ('JKWTCN/z72-qemu', 'd91718fd5c7de88bb48abdc6469669170d6f20d6'),
    'z6-mod': ('WonderLantern/WonderLantern-z6', 'f63af8f21671013163ed2657b43d77ef9fda8b75'),
    'z30-mod': ('WonderLantern/wonder-lantern-z30', '0634d591de6f482baa0f97574eed654729ea2645'),
    'fenestra': ('WonderLantern/Fenestra', '67774849c9dd97cc7127066190528e245ee25650'),
    'z8-patch': ('XinmiaoZhao/NikonFirmwarePatch', 'cd1e46332c5ef2796276dfe0d19ce9b9bc68a145'),
    'zf-qemu': ('WonderLantern/zf-qemu', '099c96e13035df48b68a8f64b237f2722740fed9'),
    'nightglasses-z7ii': ('nightglasses/z7ii-qemu', '0e53ea5a6d4f3fc635d63c195a92e943370ac5e9'),
}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def source_list():
    rows = []
    for key in ('z6-qemu', 'z9-qemu', 'z72-qemu'):
        repo, commit = VERSIONS[key]
        rows.append(dict(id=key + '-source', repo=repo, commit=commit,
                         url=f'https://codeload.github.com/{repo}/zip/{commit}',
                         local_path=f'references/upstream-source/{key}-{commit[:12]}.zip',
                         kind='fixed source archive; not executed'))
    docs = {
        'z6-qemu': ['README.zh-CN.md', 'docs/build.md', 'docs/firmware.md', 'docs/debugging.md', 'docs/testing.md'],
        'z9-qemu': ['README.md', 'docs/capture.zh-CN.md', 'docs/testing.md'],
        'z72-qemu': ['README.md', 'research/z7ii/capture_release_submit.md'],
        'z6-mod': ['README.md'], 'z30-mod': ['README.md'],
        'fenestra': ['README.md', 'docs/validation.md', 'LICENSE'],
        'z8-patch': ['README.md', 'CHANGELOG.md', 'docs/validation.md', 'docs/known-issues.md'],
        'zf-qemu': ['README.md'], 'nightglasses-z7ii': ['README.md'],
    }
    for key, paths in docs.items():
        repo, commit = VERSIONS[key]
        for path in paths:
            rows.append(dict(id=f'{key}/{path}', repo=repo, commit=commit,
                             url=f'https://raw.githubusercontent.com/{repo}/{commit}/{path}',
                             local_path=f'references/web/{DATE}/{key}/{path}',
                             kind='fixed upstream document'))
    for key, url in (
        ('z8-issue17.json', 'https://api.github.com/repos/XinmiaoZhao/NikonFirmwarePatch/issues/17'),
        ('z8-issue17-comments.json', 'https://api.github.com/repos/XinmiaoZhao/NikonFirmwarePatch/issues/17/comments'),
        ('bilibili-z8-report.json', 'https://api.bilibili.com/x/web-interface/view?bvid=BV17Nx16oE6S'),
        ('bilibili-cacl2-wifi.json', 'https://api.bilibili.com/x/web-interface/view?bvid=BV1eAs96TEWE'),
    ):
        rows.append(dict(id=key, url=url, local_path=f'references/web/{DATE}/{key}',
                         kind='mutable API snapshot; retrieval time applies'))
    return rows

def download(row):
    row = dict(row)
    path = ROOT / row['local_path']
    try:
        req = urllib.request.Request(row['url'], headers={'User-Agent': 'Mozilla/5.0 Z6-research-handoff'})
        with urllib.request.urlopen(req, timeout=45) as response:
            data = response.read(80 * 1024 * 1024 + 1)
            row['final_url'] = response.geturl()
        if len(data) > 80 * 1024 * 1024:
            raise ValueError('Archive exceeds the 80 MiB per-source limit')
        if path.suffix == '.zip':
            import io
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if archive.testzip() is not None:
                    raise ValueError('Source ZIP CRC verification failed')
        elif path.suffix == '.json':
            payload = json.loads(data)
            if 'bilibili-' in path.name and payload.get('code') != 0:
                raise ValueError(f'Bilibili API code: {payload.get("code")}')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        row.update(status='saved', bytes=len(data), sha256=sha(data),
                   retrieved_utc=datetime.now(timezone.utc).isoformat())
    except Exception as exc:
        row.update(status='failed', error=f'{type(exc).__name__}: {exc}',
                   retrieved_utc=datetime.now(timezone.utc).isoformat())
    print(json.dumps({k: row.get(k) for k in ('id', 'status', 'bytes', 'error')}, ensure_ascii=True), flush=True)
    return row

def main():
    if OUTPUT.exists():
        raise FileExistsError(f'Refusing to overwrite {OUTPUT}')
    if INDEX.exists():
        rows = json.loads(INDEX.read_text(encoding='utf-8'))
        # Preserve the original acquisition record on a rebuild.
        for row in rows:
            if row['status'] == 'saved':
                data = (ROOT / row['local_path']).read_bytes()
                if len(data) != row['bytes'] or sha(data) != row['sha256']:
                    raise ValueError(f'Archived source changed: {row["id"]}')
    else:
        with ThreadPoolExecutor(max_workers=6) as pool:
            rows = list(pool.map(download, source_list()))
        INDEX.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    required = next(r for r in rows if r['id'] == 'z6-qemu-source')
    if required['status'] != 'saved':
        raise RuntimeError('Required Z6 source archive is missing')

    files = []
    for path in sorted(ROOT.rglob('*')):
        if not path.is_file() or path == MANIFEST:
            continue
        rel = path.relative_to(ROOT)
        if any(p in ('__pycache__', '.venv', 'venv') for p in rel.parts):
            continue
        if path.is_symlink():
            raise ValueError(f'Symlink requires explicit packaging handling: {path}')
        files.append(path)
    records = []
    for path in files:
        data = path.read_bytes()
        records.append(dict(path=path.relative_to(ROOT).as_posix(), bytes=len(data), sha256=sha(data)))
    payload = dict(created_utc=datetime.now(timezone.utc).isoformat(),
                   root_folder='Z6_firmware',
                   note='Manifest excludes itself; Git metadata is included in ZIP but mutable after extraction.',
                   source_download_failures=[r['id'] for r in rows if r['status'] != 'saved'],
                   files=records)
    MANIFEST.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    expected = {r['path']: r for r in records}
    data = MANIFEST.read_bytes()
    expected[MANIFEST.relative_to(ROOT).as_posix()] = dict(bytes=len(data), sha256=sha(data))
    with zipfile.ZipFile(OUTPUT, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
        for path in files + [MANIFEST]:
            rel = path.relative_to(ROOT).as_posix()
            compression = zipfile.ZIP_STORED if path.suffix.lower() in ('.zip', '.pack', '.exe') else zipfile.ZIP_DEFLATED
            archive.write(path, 'Z6_firmware/' + rel, compress_type=compression)
    # Verify every archived file against the source manifest, not just ZIP CRC.
    with zipfile.ZipFile(OUTPUT) as archive:
        if len(archive.infolist()) != len(expected):
            raise ValueError('ZIP file-count mismatch')
        for info in archive.infolist():
            rel = info.filename.removeprefix('Z6_firmware/')
            data = archive.read(info)
            row = expected[rel]
            if len(data) != row['bytes'] or sha(data) != row['sha256']:
                raise ValueError(f'ZIP content mismatch: {rel}')
    h = hashlib.sha256()
    with OUTPUT.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    OUTPUT.with_suffix('.zip.sha256').write_text(f'{h.hexdigest()}  {OUTPUT.name}\n', encoding='ascii')
    result = dict(zip=str(OUTPUT), bytes=OUTPUT.stat().st_size, files=len(expected),
                  sha256=h.hexdigest(), all_archived_file_hashes_verified=True,
                  source_saved=sum(r['status'] == 'saved' for r in rows),
                  source_failed=[r['id'] for r in rows if r['status'] != 'saved'])
    print(json.dumps(result, ensure_ascii=True, indent=2), flush=True)

if __name__ == '__main__':
    main()

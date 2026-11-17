"""Archive the fixed sources for the October 11–12 research update.

Existing snapshots are preserved; downloaded content is never executed.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
import hashlib
import json
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'references/web/2026-10-12'
SOURCES = [
    ('z6-qemu', '419a1f2a91a1f2d3a0209027c29606475f7fe26f', ['README.zh-CN.md', 'docs/display-counter.md', 'docs/testing.md', 'docs/architecture.md']),
    ('wonder-lantern-z30', 'c296b7240f36ffe1098786cbf1e4c5c25e396bb0', ['README.md', 'docs/modules.md']),
    ('z30-qemu', '0ba0c3547ccbec09e7c861eaca35db8e82795f15', ['README.md']),
    ('z9-qemu', 'deb3a75df1795924e9be8f814d9a24ce6b439a67', ['README.md', 'docs/capture.zh-CN.md', 'docs/testing.md', 'tools/audit_native_nef.py']),
]


def main():
    entries = []
    for repo, commit, paths in SOURCES:
        for path in paths:
            entries.append(dict(
                id=f'update_20261012_{repo}_{path.replace("/", "_")}',
                title=f'{repo} / {path}', category='2026年10月11日至12日研究增量',
                url=f'https://github.com/WonderLantern/{repo}/blob/{commit}/{path}',
                download_url=f'https://raw.githubusercontent.com/WonderLantern/{repo}/{commit}/{path}',
                commit=commit, local_path=f'references/web/2026-10-12/{repo}/{path}',
                scope='固定版本的上游资料；作者报告与模型实现，不是本项目真机验收'))
    for number in (2, 4):
        entries.append(dict(
            id=f'update_20261012_z30_pr{number}', title=f'Z30 PR #{number}',
            category='2026年10月11日至12日研究增量',
            url=f'https://github.com/WonderLantern/wonder-lantern-z30/pull/{number}',
            download_url=f'https://api.github.com/repos/WonderLantern/wonder-lantern-z30/pulls/{number}',
            local_path=f'references/web/2026-10-12/z30-pr{number}.json',
            scope='可变讨论的归档时点快照；以后状态可能变化'))
    for repo in ('WonderLantern-z6', 'z6-qemu', 'wonder-lantern-z30', 'z9-qemu'):
        entries.append(dict(
            id=f'update_20261012_{repo}_commits', title=f'{repo} 提交列表',
            category='2026年10月11日至12日研究增量',
            url=f'https://github.com/WonderLantern/{repo}/commits/main/',
            download_url=f'https://api.github.com/repos/WonderLantern/{repo}/commits?per_page=5',
            local_path=f'references/web/2026-10-12/{repo}-commits.json',
            scope='默认分支在归档时点的提交记录；不覆盖私有工作'))

    index = ROOT / 'references/sources.json'
    records = json.loads(index.read_text(encoding='utf-8'))
    by_id = {r.get('id'): r for r in records if r.get('id')}

    def fetch(entry):
        path = ROOT / entry['local_path']
        if path.exists():
            prior = by_id.get(entry['id'])
            if not prior or hashlib.sha256(path.read_bytes()).hexdigest() != prior['sha256']:
                raise ValueError(f'Unregistered or changed snapshot: {path}')
            return prior
        request = urllib.request.Request(entry['download_url'], headers={'User-Agent': 'Z6-research'})
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read()
            final_url = response.url
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(data)
        now = datetime.now(ZoneInfo('Asia/Shanghai'))
        return dict(entry, final_url=final_url, retrieved_at=now.isoformat(),
                    retrieved_date=now.date().isoformat(), timezone='Asia/Shanghai',
                    bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), status='saved')

    # Merge each completed result so partial downloads remain registered on failure.
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(fetch, entry) for entry in entries]
        errors = []
        for future in futures:
            try:
                record = future.result()
                records = [r for r in records if r.get('id') != record['id']]
                records.append(record)
                index.write_text(json.dumps(records, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            except Exception as error:
                errors.append(str(error))
    print(json.dumps(dict(sources=len(entries), errors=errors), ensure_ascii=False))
    if errors:
        raise SystemExit(1)


if __name__ == '__main__':
    main()

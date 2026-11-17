"""Index finalized preflash evidence after the last command recorder exits."""
from pathlib import Path
import datetime,hashlib,json,sys
ROOT=Path(__file__).resolve().parents[2];ROUND=ROOT/'analysis/preflash-review-2026-11-09'
NAMES=['review_preflash_static.py','inspect_flash_backend.py','probe_preflash_review.py',
       'archive_preflash_sources.py','probe_preflash_abi.py','verify_preflash_kit.py',
       'package_preflash_review.py','test_preflash_verifier.py','verify_preflash_review.py',
       'index_preflash_review.py','probe_eg_update_route.py','probe_raw_candidates.py',
       'probe_still_neighborhood_off.py','record_research_command.py']
def item(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return dict(path=path.relative_to(ROOT).as_posix(),bytes=path.stat().st_size,sha256=h.hexdigest())
def main():
    target=ROUND/'evidence-index.json'
    if target.exists():raise ValueError('Index already exists')
    snapshots=ROUND/'source-snapshots';snapshots.mkdir(exist_ok=False)
    for name in NAMES:(snapshots/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    files=[p for p in ROUND.rglob('*') if p.is_file() and p!=target]
    for directory in ('outputs/Z6-C380-preflash-reviewed-2026-11-09','references/web/2026-11-09/preflash-review'):
        files.extend(p for p in (ROOT/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    files.extend(ROOT/p for p in ('docs/PREFLASH_REVIEW_2026-11-09.md','docs/Z6_PREFLASH_STEPS_2026-11-09.txt'))
    commands=[json.loads(p.read_text()) for p in sorted((ROUND/'commands').glob('*/command.json'))]
    if len(commands)!=13 or any('exit_code' not in c for c in commands):raise ValueError('Command logs not finalized')
    report=dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),argv=sys.argv,
        cwd=str(Path.cwd()),indexer_sha256=item(Path(__file__))['sha256'],commands=len(commands),
        source_snapshots=len(NAMES),files=[item(p) for p in sorted(set(files))],
        scope='Final review artifacts; old frozen round left intact; no physical flash or actual card access.')
    with target.open('x',encoding='utf8') as f:json.dump(report,f,indent=2)
    print(json.dumps(dict(index=str(target),files=len(report['files']),commands=len(commands),snapshots=len(NAMES))))
if __name__=='__main__':main()

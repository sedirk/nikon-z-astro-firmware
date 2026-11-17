"""Freeze completed first physical NEF study and explicit progress-document edits."""
from pathlib import Path
import datetime,hashlib,json,sys
ROOT=Path(__file__).resolve().parents[2];ROUND=ROOT/'analysis/modified1-nef-2026-11-09'
SCRIPTS=['analyze_modified1_nef.py','verify_modified1_decode.py','assess_modified1_signal.py',
         'update_modified1_progress.py','verify_modified1_study.py','index_modified1_study.py',
         'audit_nef.py','inventory_nas_nef.py','record_research_command.py']
def row(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return dict(path=p.relative_to(ROOT).as_posix(),bytes=p.stat().st_size,sha256=h.hexdigest())
def main():
    target=ROUND/'evidence-index.json'
    if target.exists():raise ValueError('Index already exists')
    snapshots=ROUND/'source-snapshots';snapshots.mkdir(exist_ok=False)
    for name in SCRIPTS:(snapshots/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    commands=[json.loads(p.read_text()) for p in sorted((ROUND/'commands').glob('*/command.json'))]
    if len(commands)!=8 or any('exit_code' not in c for c in commands):raise ValueError('Commands not finalized')
    files=[p for p in ROUND.rglob('*') if p.is_file() and p!=target]
    files.extend(ROOT/p for p in ('README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md','docs/MODIFIED1_REAL_NEF_2026-11-09.md'))
    report=dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),argv=sys.argv,cwd=str(Path.cwd()),
        commands=len(commands),source_snapshots=len(SCRIPTS),files=[row(p) for p in sorted(set(files))],
        scope='First physical candidate NEF study; original/candidate binaries and NEFs preserved; prior documentation retained in progress-update backups.')
    with target.open('x',encoding='utf8') as f:json.dump(report,f,indent=2)
    print(json.dumps(dict(index=str(target),files=len(files),commands=len(commands),snapshots=len(SCRIPTS))))
if __name__=='__main__':main()

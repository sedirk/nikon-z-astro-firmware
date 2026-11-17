"""Freeze finalized commands/evidence and current scripts after the recorder exits."""
from pathlib import Path
import datetime,json,sys
from audit_nef import file_sha

ROOT=Path(__file__).resolve().parents[2];DIR=ROOT/'analysis/raw-control-convergence-2026-11-09'
SCRIPTS=['probe_still_neighborhood_off.py','probe_raw_candidates.py','build_raw_candidates.py',
    'build_raw_container.py','build_still_neighborhood_container.py','archive_update_references.py',
    'probe_eg_update_route.py','package_still_neighborhood.py','verify_neighborhood_package.py',
    'verify_raw_control_convergence.py','inspect_native.py','record_research_command.py',
    'audit_nef.py','index_raw_control_convergence.py']

def main():
    assert json.loads((DIR/'verification.json').read_text())['ok']
    output=DIR/'evidence-index.json';assert not output.exists()
    snapshots=DIR/'source-snapshots';snapshots.mkdir(exist_ok=False)
    for name in SCRIPTS:(snapshots/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    def record(path):return dict(path=path.relative_to(ROOT).as_posix(),bytes=path.stat().st_size,sha256=file_sha(path))
    commands=[]
    for path in sorted((DIR/'commands').glob('*/command.json')):
        m=json.loads(path.read_text());assert 'exit_code' in m
        commands.append(dict(folder=path.parent.name,exit_code=m['exit_code']))
    files=[record(p) for p in sorted(DIR.rglob('*')) if p.is_file() and p!=output]
    external=[ROOT/p for p in ('README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md',
        'docs/RAW_CONTROL_CONVERGENCE_2026-11-09.md','patches/z6-c380-still-neighborhood-off.json')]
    external += [ROOT/'tools/fw'/s for s in SCRIPTS]
    for folder in ('outputs/Z6-C380-neighborhood-candidate-2026-11-09','references/web/2026-11-09/update-routes'):
        external += [p for p in sorted((ROOT/folder).rglob('*')) if p.is_file()]
    result=dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        argv=[sys.executable,*sys.argv],cwd=str(Path.cwd()),script_sha256=file_sha(__file__),
        files=files,indexed_files=len(files),commands=commands,source_snapshots=len(SCRIPTS),
        current_docs_scripts_package_sources=[record(p) for p in external],
        scope='Finalized evidence except this index; failed runs and former script snapshots are retained.')
    output.write_text(json.dumps(result,indent=2),encoding='utf8')
    print(json.dumps(dict(ok=True,indexed_files=len(files),external_files=len(external),commands=len(commands),snapshots=len(SCRIPTS))))

if __name__=='__main__':main()

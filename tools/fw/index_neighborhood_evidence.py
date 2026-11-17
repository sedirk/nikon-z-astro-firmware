"""Freeze this research round's scripts and hash its final evidence/docs.

Run directly after recorded commands have completed, so no command metadata is
hashed while a recorder is still updating it. The index records its own argv.
"""
from pathlib import Path
import datetime,json,sys
from audit_nef import file_sha

ROOT=Path(__file__).resolve().parents[2]
DIR=ROOT/'analysis/raw-neighborhood-2026-11-09'


def main():
    output=DIR/'evidence-index.json';assert not output.exists()
    commands=[]
    for q in sorted((DIR/'commands').glob('*/command.json')):
        m=json.loads(q.read_text());assert 'exit_code' in m
        commands.append(dict(folder=q.parent.name,exit_code=m['exit_code']))
    assert len(commands)==36
    assert [q['folder'] for q in commands if q['exit_code']!=0]==['01-native-entry','31-native-modes']
    scripts=['scan_neighborhood_fields.py','export_neighborhood_targets.py',
        'verify_neighborhood_fingerprint.py','probe_exposure_neighborhood.py',
        'probe_cluster_repair.py','probe_neighborhood_modes.py','probe_still_class_candidate.py',
        'verify_neighborhood_study.py','render_neighborhood_evidence.py',
        'inspect_native.py','build_raw_candidates.py','probe_raw_candidates.py',
        'record_research_command.py','audit_nef.py','index_neighborhood_evidence.py']
    snapshots=DIR/'source-snapshots';snapshots.mkdir(exist_ok=False)
    for name in scripts:(snapshots/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    files=[]
    for q in sorted(DIR.rglob('*')):
        if q.is_file() and q!=output:
            files.append(dict(path=q.relative_to(ROOT).as_posix(),bytes=q.stat().st_size,sha256=file_sha(q)))
    external=[]
    for path in ['README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md','docs/RAW_NEIGHBORHOOD_2026-11-09.md',
                 'patches/z6-c380-still-class-experiment.json']+['tools/fw/'+s for s in scripts]:
        q=ROOT/path;external.append(dict(path=path,bytes=q.stat().st_size,sha256=file_sha(q)))
    result=dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        argv=[sys.executable,*sys.argv],cwd=str(Path.cwd()),script_sha256=file_sha(__file__),
        indexed_files=len(files),bytes=sum(x['bytes'] for x in files),commands=commands,
        source_snapshots=len(scripts),files=files,current_docs_recipe_scripts=external,
        scope='All finalized round files except this index. Earlier per-run script snapshots, including failed runs, remain intact.')
    output.write_text(json.dumps(result,indent=2),encoding='utf8')
    print(json.dumps(dict(indexed_files=len(files),bytes=result['bytes'],scripts=len(scripts),recorded_commands=len(commands))))


if __name__=='__main__':main()

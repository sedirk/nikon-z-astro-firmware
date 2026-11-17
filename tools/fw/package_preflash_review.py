"""Create a fresh reviewed test/rollback kit without modifying prior artifacts."""
from pathlib import Path
import argparse,datetime,hashlib,json,shutil
from verify_preflash_kit import DIGESTS,PATHS,read_module,check_kit,need
ROOT=Path(__file__).resolve().parents[2]
ROUND=ROOT/'analysis/preflash-review-2026-11-09'

def record(path,root):
    data=path.read_bytes();return dict(path=path.relative_to(root).as_posix(),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    old=ROOT/'outputs/Z6-C380-neighborhood-candidate-2026-11-09'
    source={'test':old/'candidate/EG162080.BIN','rollback':ROOT/'firmware/decoded/eg1620_038000.bi'}
    evidence=[]
    for file in (ROUND/'static-final/result.json',ROUND/'abi/result.json',ROUND/'rollback-scheduler/result.json'):
        need(json.loads(file.read_text())['ok'],f'Unpassed review: {file}')
        evidence.append(record(file,ROOT))
    sources=ROOT/'references/web/2026-11-09/preflash-review/manifest.json'
    need(any(x.get('identical_to_preserved_original') is True for x in json.loads(sources.read_text())),'Official baseline not matched')
    evidence.append(record(sources,ROOT))
    for mode,path in source.items():
        data=read_module(path,mode);target=out/PATHS[mode];target.parent.mkdir();target.write_bytes(data)
    shutil.copyfile(ROOT/'docs/Z6_PREFLASH_STEPS_2026-11-09.txt',out/'START_HERE.txt')
    shutil.copyfile(ROOT/'docs/PREFLASH_REVIEW_2026-11-09.md',out/'REVIEW.md')
    shutil.copyfile(ROOT/'tools/fw/verify_preflash_kit.py',out/'verify.py')
    shutil.copyfile(old/'baseline112.json',out/'baseline112.json')
    manifest=dict(schema=1,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        purpose='First-generation Z6 C3.80 controlled first physical test',
        camera_basis='User confirmed original C3.80 on 2026-11-09; no camera connection performed',
        verdict='Conditional first hardware test; no physical installation, recovery or pixel acceptance yet',
        candidate_unchanged_from_prior_package=True,evidence=evidence,
        original_container=dict(path='firmware/original/Z_6_0380.bin',sha256='ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54'),
        files=[record(f,out) for f in sorted(out.rglob('*')) if f.is_file()])
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
    print(json.dumps(dict(output=str(out),**check_kit(out)),indent=2))
if __name__=='__main__':main()

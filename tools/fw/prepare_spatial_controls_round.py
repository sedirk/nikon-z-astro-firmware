"""Start a new round using verified real calibration backups; preserve all prior artifacts."""
from pathlib import Path
import datetime,hashlib,json,subprocess,sys
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'analysis/raw-spatial-controls-2026-11-10'
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    OUT.mkdir(exist_ok=False);(OUT/'progress-before').mkdir()
    for n in ('README.md','docs/PROJECT_GOALS.md','docs/NEXT_STEPS.md'):
        (OUT/'progress-before'/n.replace('/','-')).write_bytes((ROOT/n).read_bytes())
    expected={
      'firmware/decoded/eg1620_038000.bi':'1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c',
      'analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/CAL38.bin':'914884aa8f0db4d407fd15eb6731ca6f7f388c62c109407e733d09d5ec760372',
      'analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/ID35.bin':'d52210383ec47bb473f2faebf3e1b7dd60bcf77f3b018dcba89fdec2bef48baf',
      'outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN':'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b'}
    for name,h in expected.items():assert sha((ROOT/name).read_bytes())==h,name
    prior=json.loads((ROOT/'analysis/raw-calibration-access-2026-11-10/evidence-index.json').read_text())
    for r in prior['files']:assert sha((ROOT/r['path']).read_bytes())==r['sha256'],r['path']
    (OUT/'inputs.json').write_text(json.dumps(dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        argv=sys.argv,inputs=expected,prior_frozen_files_verified=len(prior['files']),
        objective='Identify CAL33 control semantics and converge on still-only single-variable candidate while preserving ID35 transfer and dark patches.'),indent=2),encoding='utf8')
    (OUT/'git-status-before.txt').write_bytes(subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True).stdout)
    print(json.dumps(dict(ok=True,prior_frozen_files_verified=len(prior['files']))))
if __name__=='__main__':main()

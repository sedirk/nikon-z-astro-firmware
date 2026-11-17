"""Start a new round for CAL33 control1a (modified7); preserve all prior artifacts."""
from pathlib import Path
import datetime, hashlib, json, subprocess, sys

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/raw-spatial-controls-2026-11-12'

def sha(b):
    return hashlib.sha256(b).hexdigest()

def main():
    OUT.mkdir(exist_ok=False)
    (OUT / 'progress-before').mkdir()
    for n in ('README.md', 'docs/PROJECT_GOALS.md', 'docs/NEXT_STEPS.md'):
        (OUT / 'progress-before' / n.replace('/', '-')).write_bytes((ROOT / n).read_bytes())
    expected = {
        'firmware/decoded/eg1620_038000.bi': '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c',
        'analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/CAL38.bin': '914884aa8f0db4d407fd15eb6731ca6f7f388c62c109407e733d09d5ec760372',
        'analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/ID35.bin': 'd52210383ec47bb473f2faebf3e1b7dd60bcf77f3b018dcba89fdec2bef48baf',
        'outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN': 'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b',
        'outputs/Z6-C380-cal33-control18-reviewed-2026-11-10/01_TEST_MODIFIED6/EG162080.BIN': '5c1cdfcd11ccfef301317118c43954bf6b55a50e6574ea66ba941e2f9a716003',
    }
    for name, h in expected.items():
        assert sha((ROOT / name).read_bytes()) == h, name
    prior_indices = [
        'analysis/raw-calibration-access-2026-11-10/evidence-index.json',
        'analysis/raw-spatial-controls-2026-11-10/evidence-index.json',
        'analysis/modified6-real-2026-11-10/evidence-index.json',
    ]
    total_prior_files = 0
    for idx_path in prior_indices:
        prior = json.loads((ROOT / idx_path).read_text(encoding='utf-8'))
        for r in prior['files']:
            assert sha((ROOT / r['path']).read_bytes()) == r['sha256'], r['path']
        total_prior_files += len(prior['files'])
    (OUT / 'inputs.json').write_text(json.dumps(dict(
        created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        argv=sys.argv, inputs=expected, prior_frozen_files_verified=total_prior_files,
        objective='Isolate CAL33 +1a control (modified7) in static frontend after Route B full operator survey. Target MMIO 0x20068704 (1->0), keeping +18 at baseline 1 and preserving ID35 transmission and dark current suppression bypass.'
    ), indent=2), encoding='utf8')
    (OUT / 'git-status-before.txt').write_bytes(subprocess.run(['git', 'status', '--short'], cwd=ROOT, capture_output=True, check=True).stdout)
    print(json.dumps(dict(ok=True, prior_frozen_files_verified=total_prior_files)))

if __name__ == '__main__':
    main()

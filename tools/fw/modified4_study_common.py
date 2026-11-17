"""Pinned preparation for three confirmed modified4 flats; no new darks supplied."""
from pathlib import Path
import datetime, json, subprocess
from audit_nef import file_sha
from modified3_study_common import read, write, need, record

ROOT = Path(__file__).resolve().parents[2]
ROUND = ROOT/'analysis/modified4-real-2026-11-09'
GROUPS = {'modified3_flat': [4886, 4888, 4889], 'modified4_flat': [4902, 4904, 4905]}


def prepare():
    metadata = {int(Path(m['SourceFile']).stem.split('_')[-1]): m for m in read(ROUND/'metadata/metadata.json')}
    old_path = ROOT/'analysis/modified3-real-2026-11-09/inputs.json'
    old = {r['id']: r for r in read(old_path)['files']}
    audit_path = ROUND/'raw-audit.json'
    audit = read(audit_path)
    new = {int(Path(r['path']).stem.split('_')[-1]): r for r in audit['files']}
    need(set(new) == set(GROUPS['modified4_flat']), 'Unexpected new input set')
    cases = []
    for group, ids in GROUPS.items():
        for ident in ids:
            row = old[ident]['audit'] if group == 'modified3_flat' else new[ident]
            path = Path(row['path']).resolve()
            need(file_sha(path) == row['sha256'], 'Input changed '+str(path))
            m = metadata[ident]
            need(str(m['Nikon:SerialNumber']) == '8006677', 'Different body')
            need(m['ExifIFD:ISO'] == 1600 and m['ExifIFD:FNumber'] == 1.8, 'Different ISO/aperture')
            need(m['ExifIFD:ExposureTime'] == '1/8000', 'Different exposure')
            need(m['Nikon:NEFCompression'] == 'Lossless', 'Compression changed')
            cases.append(dict(id=ident, group=group, path=str(path), sha256=row['sha256'],
                audit=row, metadata=m, capture_time=m.get('Composite:SubSecDateTimeOriginal')))
    keys = ['IFD0:Model', 'ExifIFD:ISO', 'ExifIFD:ExposureTime', 'ExifIFD:FNumber', 'ExifIFD:LensModel',
        'Nikon:ShutterMode', 'Nikon:NEFCompression', 'Nikon:BlackLevel', 'Nikon:NoiseReduction',
        'Nikon:HighISONoiseReduction', 'Nikon:VignetteControl', 'Nikon:VibrationReduction',
        'Nikon:FocusMode', 'Nikon:FocusDistance', 'Nikon:ActiveD-Lighting',
        'Nikon:AutoDistortionControl', 'Nikon:DiffractionCompensation']
    differences = {k: [r['metadata'].get(k) for r in cases] for k in keys
                   if len({str(r['metadata'].get(k)) for r in cases}) > 1}
    write(ROUND/'inputs.json', dict(ok=True, created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        groups=GROUPS, files=cases, recorded_setting_differences=differences,
        firmware_confirmation='User explicitly confirms modified4 installed for supplied 4902/4904/4905.',
        setup_confirmation='同设备和亮度，位置或对焦可能移动',
        dark_confirmation='还没拍新暗场', new_dark_frames=0,
        design='Three earlier modified3 and three new modified4 1/8000 tablet flats; not fixed-placement A/B. No new bias or dark.',
        source_audits=[record(old_path), record(audit_path)],
        inherited_dark_evidence=record(ROOT/'analysis/modified3-real-2026-11-09/assessment.json')))
    audit['files'] = [dict(r, id=int(Path(r['path']).stem.split('_')[-1])) for r in audit['files']]
    write(ROUND/'decoder-input.json', audit)
    folder = ROUND/'progress-before'
    folder.mkdir(exist_ok=False)
    for name in ('README.md', 'docs/NEXT_STEPS.md', 'docs/PROJECT_GOALS.md'):
        (folder/name.replace('/', '-')).write_bytes((ROOT/name).read_bytes())
    (ROUND/'git-status-before.txt').write_bytes(subprocess.run(['git', 'status', '--short'], cwd=ROOT, capture_output=True, check=True).stdout)
    print(json.dumps(dict(ok=True, files=len(cases), differences=differences, new_dark_frames=0)))


if __name__ == '__main__':
    prepare()

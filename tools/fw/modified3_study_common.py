"""Shared paths and pinned input preparation for the confirmed modified3 captures."""
from pathlib import Path
import datetime, json, subprocess
from audit_nef import file_sha

ROOT = Path(__file__).resolve().parents[2]
ROUND = ROOT / 'analysis/modified3-real-2026-11-09'
GROUPS = {'modified2_earlier_flat':[4870,4873], 'modified2_flat':[4878,4879,4880],
          'modified3_flat':[4886,4888,4889], 'modified2_dark':[4874,4875,4876],
          'modified3_dark':[4890,4891,4892]}

def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))

def need(value, message):
    if not value:
        raise ValueError(message)

def write(path, value):
    path = Path(path)
    need(not path.exists(), 'Refusing overwrite: ' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False), encoding='utf8')

def record(path):
    path=Path(path)
    return dict(path=path.relative_to(ROOT).as_posix(), bytes=path.stat().st_size, sha256=file_sha(path))

def prepare():
    metadata={int(Path(m['SourceFile']).stem.split('_')[-1]):m for m in read(ROUND/'metadata/metadata.json')}
    sources=[ROOT/'analysis/modified2-flat-2026-11-09/raw-audit.json',
             ROOT/'analysis/modified2-extra-2026-11-09/raw-audit-corrected.json', ROUND/'raw-audit.json']
    cases={}
    for source in sources:
        for row in read(source)['files']:
            path=Path(row['path']); ident=int(path.stem.split('_')[-1]); m=metadata[ident]
            need(file_sha(path)==row['sha256'], 'Source changed: '+str(path))
            need(str(m['Nikon:SerialNumber'])=='8006677', 'Different body')
            group=next(g for g,ids in GROUPS.items() if ident in ids)
            need(m['ExifIFD:ISO']==1600 and m['ExifIFD:FNumber']==1.8, 'Different ISO/aperture')
            need(m['ExifIFD:ExposureTime']==(5 if group.endswith('dark') else '1/8000'), 'Different exposure')
            need(m['Nikon:NEFCompression']=='Lossless', 'Compression changed')
            row['id']=ident
            cases[ident]=dict(id=ident,group=group,path=str(path),sha256=row['sha256'],audit=row,metadata=m,
                             capture_time=m.get('Composite:SubSecDateTimeOriginal'))
    need(len(cases)==14, 'Expected 14 frames including two earlier context flats')
    keys=['IFD0:Model','ExifIFD:ISO','ExifIFD:ExposureTime','ExifIFD:FNumber','ExifIFD:LensModel',
          'Nikon:ShutterMode','Nikon:NEFCompression','Nikon:BlackLevel','Nikon:NoiseReduction',
          'Nikon:HighISONoiseReduction','Nikon:VignetteControl','Nikon:VibrationReduction',
          'Nikon:FocusMode','Nikon:FocusDistance','Nikon:ActiveD-Lighting',
          'Nikon:AutoDistortionControl','Nikon:DiffractionCompensation']
    comparisons={}
    for kind in ('flat','dark'):
        seq=[cases[i] for g in ('modified2_'+kind,'modified3_'+kind) for i in GROUPS[g]]
        comparisons[kind]={k:[r['metadata'].get(k) for r in seq] for k in keys
                           if len({str(r['metadata'].get(k)) for r in seq})>1}
    write(ROUND/'inputs.json',dict(ok=True,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
          groups=GROUPS,files=list(cases.values()),recorded_setting_differences=comparisons,
          firmware_confirmation='User explicitly confirmed modified3 installed for 4886/4888/4889/4890/4891/4892. Earlier 4874-4880 were explicitly reclassified as modified2.',
          setup_confirmation='同一设备和亮度，位置或对焦可能移动',
          design='Primary comparison: three modified2 and three modified3 flats; three 5s darks each. Earlier two modified2 flats kept as within-version context. No new bias or multiple flat exposure levels.',
          source_audits=[record(p) for p in sources]))
    decoder=read(ROUND/'raw-audit.json')
    decoder['files']=[dict(row,id=int(Path(row['path']).stem.split('_')[-1])) for row in decoder['files']]
    write(ROUND/'decoder-input.json',decoder)
    backup=ROUND/'progress-before';backup.mkdir(exist_ok=False)
    for name in ('README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md'):
        (backup/name.replace('/','-')).write_bytes((ROOT/name).read_bytes())
    result=subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True)
    (ROUND/'git-status-before.txt').write_bytes(result.stdout)
    print(json.dumps(dict(ok=True,files=len(cases),differences=comparisons),ensure_ascii=False))

if __name__=='__main__':
    prepare()

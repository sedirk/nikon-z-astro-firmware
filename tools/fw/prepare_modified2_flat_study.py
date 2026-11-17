"""Pin the user's two modified2 flats against the earlier modified1 baseline."""
from pathlib import Path
import datetime,json
from audit_nef import file_sha

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/modified2-flat-2026-11-09'


def need(test,text):
    if not test:raise ValueError(text)


def read(p):return json.loads(p.read_text(encoding='utf8'))


def main():
    old=read(ROOT/'analysis/modified1-flat-2026-11-09/raw-audit.json')
    new=read(OUT/'raw-audit.json')
    metas={}
    for p in (ROOT/'analysis/modified1-flat-2026-11-09/metadata/metadata.json',OUT/'metadata/metadata.json'):
        for row in read(p):metas[Path(row['SourceFile']).name]=row
    need(len(old['files'])==len(new['files'])==2,'Unexpected file count')
    keys=['IFD0:Model','IFD0:Software','Nikon:SerialNumber','ExifIFD:ISO','ExifIFD:ExposureTime',
          'ExifIFD:FNumber','ExifIFD:FocalLength','ExifIFD:LensModel','Nikon:ShutterMode',
          'Nikon:NEFCompression','Nikon:BlackLevel','Nikon:NoiseReduction',
          'Nikon:HighISONoiseReduction','Nikon:VignetteControl','Nikon:VibrationReduction',
          'Nikon:ActiveD-Lighting','Nikon:AutoDistortionControl','Nikon:DiffractionCompensation']
    rows=[]
    for group,audit,ids in (('A_modified1',old,(4864,4865)),('B_modified2',new,(4870,4873))):
        for record,ident in zip(audit['files'],ids):
            path=Path(record['path']);need(path.stem==f'Z61_{ident}','Wrong file selection')
            need(file_sha(path)==record['sha256'],'Input changed')
            m=metas[path.name]
            need(str(m['Nikon:SerialNumber'])=='8006677','Different body')
            record['id']=ident
            rows.append(dict(group=group,id=ident,path=str(path),sha256=record['sha256'],
                stored_pixels_sha256=record['stored_pixels_sha256'],metadata={k:m.get(k) for k in keys},
                capture_time=m.get('Composite:SubSecDateTimeOriginal'),audit=record))
    differing={key:[r['metadata'][key] for r in rows] for key in keys if any(r['metadata'][key]!=rows[0]['metadata'][key] for r in rows)}
    value=dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),files=rows,
        capture_setting_differences=differing,
        user_confirmation='Same equipment; position or focus may have changed. User explicitly chose earlier A flats as baseline.',
        provenance='User supplied folder as B after reviewed modified2; NEF firmware text 3.80 alone does not identify installed bytes.',
        design='Two A and two B exposures with equal recorded exposure settings. No matched placement/focus guarantee; no new dark or bias supplied.',
        actual_dark_regression_available=False,ok=True)
    for name,data in (('inputs.json',value),('decoder-input.json',new)):
        path=OUT/name;need(not path.exists(),'Refusing overwrite');path.write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding='utf8')
    (OUT/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(ok=True,capture_setting_differences=differing,files=[dict(group=r['group'],id=r['id'],time=r['capture_time']) for r in rows]),indent=2))


if __name__=='__main__':main()

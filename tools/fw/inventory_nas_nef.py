"""Read-only metadata inventory of explicitly supplied NAS directories/files."""
from pathlib import Path
import argparse, collections, datetime, hashlib, json, subprocess

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('paths', nargs='+', type=Path)
p.add_argument('--output', required=True, type=Path)
a=p.parse_args(); a.output.mkdir(parents=True, exist_ok=False)
root=Path(__file__).resolve().parents[2]
install=json.loads((root/'analysis/real-nef-2026-11-09/sources/exiftool-install.json').read_text())
exe=Path(install['executable'])
assert hashlib.sha256(exe.read_bytes()).hexdigest()==install['sha256']
paths=[]
for x in a.paths:
    paths.extend(sorted(x.glob('*.NEF')) if x.is_dir() else [x])
assert paths and len(paths)==len(set(paths))
states=[dict(path=str(f),bytes=f.stat().st_size,mtime_ns=f.stat().st_mtime_ns) for f in paths]
args=['-charset','filename=UTF8','-j','-G1','-s','-a']+[str(f) for f in paths]
argfile=a.output/'exiftool-arguments.txt'
argfile.write_text('\n'.join(args)+'\n',encoding='utf8')
cmd=[str(exe),'-@',str(argfile)]
r=subprocess.run(cmd,capture_output=True,check=False)
(a.output/'exiftool.stderr.txt').write_bytes(r.stderr)
(a.output/'metadata.json').write_bytes(r.stdout)
assert r.returncode==0, r.stderr.decode('utf8','replace')
rows=json.loads(r.stdout)
assert len(rows)==len(paths)
assert not any('ExifTool:Error' in v or 'Error' in v for v in rows)
for s in states:
    q=Path(s['path']).stat()
    assert (q.st_size,q.st_mtime_ns)==(s['bytes'],s['mtime_ns'])
fields=['IFD0:Model','IFD0:Software','ExifIFD:ISO','ExifIFD:ExposureTime','ExifIFD:FNumber',
        'Nikon:NEFCompression','Nikon:BlackLevel','Nikon:NoiseReduction','Nikon:HighISONoiseReduction',
        'Nikon:VignetteControl','Nikon:ActiveD-Lighting','Composite:LensID']
groups=collections.Counter(tuple(str(v.get(k)) for k in fields) for v in rows)
summary=dict(count=len(rows),total_bytes=sum(v['bytes'] for v in states),
    groups=[dict(count=n,fields=dict(zip(fields,key))) for key,n in groups.items()],
    source_states=states,argv=cmd,exiftool_sha256=install['sha256'],
    script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
(a.output/'inventory.json').write_text(json.dumps(summary,indent=2,ensure_ascii=False),encoding='utf8')
print(json.dumps({k:summary[k] for k in ['count','total_bytes','groups']},indent=2,ensure_ascii=False))

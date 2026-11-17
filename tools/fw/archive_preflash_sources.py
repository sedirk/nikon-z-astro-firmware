"""Archive primary update guidance and independently hash Nikon's stock download."""
from pathlib import Path
import argparse,datetime,hashlib,json,urllib.request
ROOT=Path(__file__).resolve().parents[2]
SOURCES=[
('nikon-c380.html','https://downloadcenter.nikonimglib.com/en/download/fw/557.html'),
('nikon-update-guide.pdf','https://download.nikonimglib.com/archive3/jFBMN00KI4Ix03x9LuU85FxJko41/Z-series_FirmUp_Win_En.pdf'),
('wonderlantern-pinned-readme.md','https://raw.githubusercontent.com/WonderLantern/WonderLantern-z6/f63af8f21671013163ed2657b43d77ef9fda8b75/README.en.md'),
('wonderlantern-issues.json','https://api.github.com/repos/WonderLantern/WonderLantern-z6/issues?state=all&per_page=100'),
('stock-file-hash-only','https://download.nikonimglib.com/archive7/3wYNs00xVSiD07LB2RY19q7I3N76/Z_6_0380.bin')]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);rows=[]
    for name,url in SOURCES:
        row=dict(name=name,url=url,retrieved_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        try:
            with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Z6-local-preflash-review'}),timeout=45) as r:
                content=r.read();row.update(final_url=r.url,http_status=r.status)
            row.update(bytes=len(content),sha256=hashlib.sha256(content).hexdigest())
            if name=='stock-file-hash-only':
                local=(ROOT/'firmware/original/Z_6_0380.bin').read_bytes()
                row['identical_to_preserved_original']=content==local
                if not row['identical_to_preserved_original']:raise ValueError('Official source changed or local original mismatches')
            else:
                (a.output/name).write_bytes(content);row['path']=str(a.output/name)
        except Exception as exc:row['error']=repr(exc)
        rows.append(row);print(json.dumps(row),flush=True)
    (a.output/'manifest.json').write_text(json.dumps(rows,indent=2),encoding='utf8')
    (a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    if any('error' in r for r in rows):raise SystemExit(1)
if __name__=='__main__':main()

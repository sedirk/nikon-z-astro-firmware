"""Archive pinned primary sources used for the Z6 upgrade-route investigation."""
from pathlib import Path
import datetime, hashlib, json, urllib.request

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'references/web/2026-11-09/update-routes'
SOURCES={
    'WonderLantern/nikon-fw-key-tool':('33426e892afd329a3b366b73776bcf53b9ac4ee8',
        ['README.md','LICENSE','solve_signature_e7.py','repack_firmware.py']),
    'WonderLantern/WonderLantern-z6':('f63af8f21671013163ed2657b43d77ef9fda8b75',
        ['README.en.md','README.md','SHA256.txt','LICENSE']),
}

def main():
    OUT.mkdir(parents=True,exist_ok=False)
    rows=[]
    for repo,(commit,files) in SOURCES.items():
        for name in files:
            url=f'https://raw.githubusercontent.com/{repo}/{commit}/{name}'
            req=urllib.request.Request(url,headers={'User-Agent':'Z6-local-research'})
            with urllib.request.urlopen(req,timeout=30) as r: data=r.read()
            path=OUT/repo.split('/')[-1]/name
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
            rows.append(dict(repo=repo,commit=commit,url=url,path=str(path.relative_to(ROOT)),
                bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),
                retrieved_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()))
    (OUT/'manifest.json').write_text(json.dumps(rows,indent=2),encoding='utf8')
    print(json.dumps(dict(ok=True,files=len(rows),path=str(OUT))))

if __name__=='__main__':main()

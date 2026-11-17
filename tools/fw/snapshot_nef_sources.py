"""Preserve primary decoder documentation used for this NEF serialization study."""
from pathlib import Path
import argparse,datetime,hashlib,json,urllib.request

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',required=True,type=Path);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=False)
urls={
    'libraw-0.22.2-nikon.cpp':'https://raw.githubusercontent.com/LibRaw/LibRaw/0.22.2/src/metadata/nikon.cpp',
    'libraw-0.22.2-open.cpp':'https://raw.githubusercontent.com/LibRaw/LibRaw/0.22.2/src/utils/open.cpp',
    'rawpy-RawPy.html':'https://letmaik.github.io/rawpy/api/rawpy.RawPy.html',
    'nikon-z6-specifications.html':'https://imaging.nikon.com/imaging/lineup/mirrorless/z_6/'
}
rows=[]
for name,url in urls.items():
    with urllib.request.urlopen(url,timeout=30) as response:
        body=response.read(2*1024*1024+1)
        assert len(body)<=2*1024*1024
        row=dict(file=name,url=url,final_url=response.url,retrieved_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            size=len(body),sha256=hashlib.sha256(body).hexdigest())
    (a.output/name).write_bytes(body);rows.append(row)
    (a.output/'sources.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
    print(name,len(body),flush=True)

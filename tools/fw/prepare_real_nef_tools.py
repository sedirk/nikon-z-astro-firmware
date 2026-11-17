"""Install a project-local ExifTool and preserve this study's primary sources."""
from pathlib import Path
import datetime, hashlib, io, json, shutil, urllib.request, zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/real-nef-2026-11-09/sources'
OUT.mkdir(parents=True, exist_ok=False)
rows = []

def fetch(name, url, limit=32*1024*1024):
    req = urllib.request.Request(url, headers={'User-Agent': 'Z6-RAW-research/1.0'})
    with urllib.request.urlopen(req, timeout=45) as r:
        body = r.read(limit+1)
        assert len(body) <= limit
        rows.append(dict(name=name, url=url, final_url=r.url, bytes=len(body),
                         sha256=hashlib.sha256(body).hexdigest(),
                         retrieved_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()))
    (OUT/name).write_bytes(body)
    (OUT/'sources.json').write_text(json.dumps(rows, indent=2), encoding='utf8')
    print(name, len(body), flush=True)
    return body

fetch('exiftool-official-index.html', 'https://raw.githubusercontent.com/exiftool/exiftool/master/html/index.html')
body = fetch('exiftool-13.61_64.zip', 'https://sourceforge.net/projects/exiftool/files/exiftool-13.61_64.zip/download')
dest = ROOT / 'work/exiftool-13.61-portable'
dest.mkdir(exist_ok=False)
with zipfile.ZipFile(io.BytesIO(body)) as z:
    for entry in z.infolist():
        target = (dest / entry.filename).resolve()
        assert target.is_relative_to(dest.resolve())
    z.extractall(dest)
exe = list(dest.rglob('exiftool(-k).exe'))
assert len(exe) == 1
shutil.copyfile(exe[0], exe[0].with_name('exiftool.exe'))
(OUT/'exiftool-install.json').write_text(json.dumps(dict(executable=str(exe[0].with_name('exiftool.exe')),
    sha256=hashlib.sha256(exe[0].read_bytes()).hexdigest(), source_archive=rows[-1]), indent=2), encoding='utf8')
fetch('nikon-hardcoded-correction.html', 'https://www.markshelley.co.uk/Astronomy/NikonConcentricRings/nikon_hardcoded_correction.html')
fetch('exiftool-13.61-Nikon.pm', 'https://raw.githubusercontent.com/exiftool/exiftool/13.61/lib/Image/ExifTool/Nikon.pm')
fetch('libraw-0.22.2-unpack.cpp', 'https://raw.githubusercontent.com/LibRaw/LibRaw/0.22.2/src/decoders/unpack.cpp')

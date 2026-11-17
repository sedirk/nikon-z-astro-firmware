"""Identify consecutive native menu records and preserve associated bytes."""
from pathlib import Path
import argparse,hashlib,json,struct,re
ROOT=Path(__file__).resolve().parents[2];BASE=0x10020000
ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
b=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes();sha=hashlib.sha256(b).hexdigest()
assert sha=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
rows=[];pos=0
while True:
    pos=b.find(struct.pack('<H',0x1ee2),pos)
    if pos<0:break
    p=pos;pos+=1
    if p<52 or p+84>=len(b):continue
    if struct.unpack_from('<H',b,p-28)[0]!=0x1ee1 or struct.unpack_from('<H',b,p+28)[0]!=0x1ee3:continue
    start=p-24;records=[]
    for k in range(-2,5):
        at=start+28*k;w=struct.unpack_from('<7I',b,at);ptrs=[]
        for x in w:
            if BASE<=x<BASE+len(b)-100:
                s=b[x-BASE:x-BASE+100];ptrs.append(dict(address=hex(x),hex=s.hex(),ascii=s.split(b'\0')[0].decode('ascii',errors='replace'),utf16=s.decode('utf-16le',errors='replace').split('\0')[0]))
        records.append(dict(address=hex(BASE+at),words=[hex(x) for x in w],pointers=ptrs))
    rows.append(dict(id_at=hex(BASE+p),records=records))
default=b[0x114732e0-BASE+0x3c0:0x114732e0-BASE+0x3f0]
report=dict(scope=__doc__,firmware_sha256=sha,menu_candidates=rows,rom_default_configuration_3c0_3f0=default.hex(),config3d2_default=default[0x12])
a.output.parent.mkdir(parents=True,exist_ok=True);assert not a.output.exists();a.output.write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps(report,indent=2,ensure_ascii=True))

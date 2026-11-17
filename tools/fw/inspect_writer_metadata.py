"""Read original buffer descriptors and receiver dispatch entries; no pixel semantics."""
from pathlib import Path
import argparse, hashlib, json, struct

ROOT=Path(__file__).resolve().parents[2]
BASE=0x10020000
SHA='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
assert hashlib.sha256(blob).hexdigest()==SHA
def area(addr,n):
    data=blob[addr-BASE:addr-BASE+n]
    assert len(data)==n
    return dict(address=hex(addr),size=n,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())
rows=[]
for slot in (14,15,16,17):
    desc=area(0x11f70404+slot*24,24)
    b=bytes.fromhex(desc['bytes'])
    rows.append(dict(slot=slot,descriptor=desc,id_bytes=list(b[:2]),
        lengths=list(struct.unpack_from('<2H',b,4)),staging=hex(struct.unpack_from('<I',b,8)[0]),
        buffers=[hex(x) for x in struct.unpack_from('<2I',b,12)],
        dispatch_entry=hex(0x10131dee+slot),
        dispatch_target=hex(0x10131dee+2*blob[0x10131dee-BASE+slot])))
table=area(0x10131dee,0x58)
report=dict(scope=__doc__,firmware_sha256=SHA,rows=rows,receiver_jump_table=table,
            limitation='Descriptors and dispatch bytes do not prove physical data provenance or hardware pixel behavior.')
a.output.parent.mkdir(parents=True,exist_ok=True)
a.output.write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(rows,indent=2))

"""Resolve original spatial-input properties and buffer descriptors; no pixel claims."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct
import capstone

ROOT=Path(__file__).resolve().parents[2]
BASE=0x10020000
SHA='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
assert not a.output.exists()
blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
assert hashlib.sha256(blob).hexdigest()==SHA
md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)

def area(addr,size):
    data=blob[addr-BASE:addr-BASE+size]
    assert len(data)==size
    return dict(address=hex(addr),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())

def initial(addr,size):
    for off in range(0x14000,0x14120,16):
        src,dst,length,handler=struct.unpack_from('<4I',blob,off)
        if handler==0x1002006c and dst<=addr and addr+size<=dst+length:
            return dict(**area(src+addr-dst,size),destination=hex(addr),startup_record=hex(off+BASE))
    raise ValueError(hex(addr))

def word(addr): return struct.unpack_from('<I',blob,addr-BASE)[0]

group=0x114dd478+0x1c*28
base_index,count=struct.unpack_from('<HH',blob,group-BASE+12)
assert count>0x14
descriptor=0x114d4ff8+(base_index+0x14)*16
prop=dict(id='0x1c14',group=area(group,28),descriptor=area(descriptor,16),
          type=blob[descriptor-BASE],value_address=hex(word(descriptor+8)))
arrays=[]
routes=[]
for addr,count in ((0x11526e94,12),(0x11526ec4,10)):
    ids=list(struct.unpack_from('<'+str(count)+'I',blob,addr-BASE))
    arrays.append(dict(**area(addr,count*4),ids=[hex(x) for x in ids]))
    for ident in ids:
        if ident&0xf000!=0x3000: continue
        entry=0x1015c388+(ident-0x3000)*4
        target=0x1015c388+word(entry)
        ins=[dict(pc=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)
             for i in md.disasm(blob[target-BASE:target-BASE+8],target)]
        routes.append(dict(id=hex(ident),entry=hex(entry),target=hex(target),instructions=ins))
buffers=[dict(slot=slot,**initial(0xc18db630+slot*24,24)) for slot in (0,7,8,14,15,16,17)]
immediates=[]
for pos in range(0,0x10610000-BASE,2):
    h1,h2=struct.unpack_from('<2H',blob,pos)
    if h1&0xfbf0!=0xf240:continue
    imm=((h1&15)<<12)|((h1&0x400)<<1)|((h2&0x7000)>>4)|(h2&0xff)
    if imm not in (0x1c14,0x1024,0x1224):continue
    ins=next(md.disasm(blob[pos:pos+4],BASE+pos,count=1),None)
    if ins and ins.mnemonic=='movw':
        immediates.append(dict(pc=hex(ins.address),bytes=ins.bytes.hex(),mnemonic=ins.mnemonic,operands=ins.op_str))
strings=[dict(address=hex(BASE+m.start()),text=m.group().decode('ascii'))
         for m in re.finditer(rb'[\x20-\x7e]{5,}',blob)
         if re.search(rb'(lens|optic|aberrat|chromatic|diffract)',m.group(),re.I) and len(m.group())<180]
result=dict(scope=__doc__,firmware_sha256=SHA,property=prop,property_arrays=arrays,
            input_property_routes=routes,buffer_descriptors=buffers,ascii_clues=strings,movw_candidates=immediates,
            limitations=['A property ID or name alone does not identify a correction algorithm.',
                         'Linear case snippets must be checked against their actual dispatch control flow.'])
a.output.write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(dict(property=prop,arrays=arrays,routes=routes,buffers=buffers,strings=strings),indent=2))

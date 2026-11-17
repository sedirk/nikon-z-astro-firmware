"""Read immutable firmware tables related to the candidate RAW pixel stages."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x10020000
SHA = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert not a.output.exists()
blob = (ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
assert hashlib.sha256(blob).hexdigest() == SHA

def area(addr, size):
    data = blob[addr-BASE:addr-BASE+size]
    assert len(data) == size
    return dict(address=hex(addr), size=size, bytes=data.hex(),
                sha256=hashlib.sha256(data).hexdigest())

descriptors=[]
for address in range(0x11536d68, 0x11536dd8, 16):
    tag, kind, count, offset, callback = struct.unpack_from('<HHIII', blob, address-BASE)
    if callback in (0x102899a1, 0x10289943, 0x102898e5):
        descriptors.append(dict(**area(address,16), tag=hex(tag), kind=kind,
                                count=count, callback=hex(callback)))
assert [d['tag'] for d in descriptors] == ['0x5','0x6','0x7']
regions=[struct.unpack_from('<4I',blob,off) for off in range(0x14000,0x14120,16)]
def initialized(addr,size):
    for src,dst,count,handler in regions:
        if handler==0x1002006c and dst<=addr and addr+size<=dst+count:
            row=area(src+addr-dst,size)
            row['destination']=hex(addr)
            return row
    raise ValueError(hex(addr))
root=struct.unpack('<I',bytes.fromhex(initialized(0xc18d38a0,4)['bytes']))[0]
profile=initialized(root,64)
taglist=struct.unpack_from('<I',bytes.fromhex(profile['bytes']),15*4)[0]
tags=[]
for index in range(100):
    tag=struct.unpack_from('<H',blob,taglist-BASE+index*2)[0]
    if tag==0xffff: break
    tags.append(tag)
else: raise ValueError('unterminated list')
assert 7 in tags
md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
immediates=[]
for pos in range(0,0x10610000-BASE,2):
    h1,h2=struct.unpack_from('<HH',blob,pos)
    if h1&0xfbf0 != 0xf240: continue
    imm=((h1&15)<<12)|((h1&0x400)<<1)|((h2&0x7000)>>4)|(h2&0xff)
    if imm not in (0x227c,0x22fc): continue
    ins=next(md.disasm(blob[pos:pos+4],BASE+pos,count=1),None)
    if ins and ins.mnemonic=='movw':
        immediates.append(dict(pc=hex(ins.address),bytes=ins.bytes.hex(),mnemonic=ins.mnemonic,operands=ins.op_str))
strings=[]
pattern=re.compile(r'(shading|vignett|distort|black.?level|white.?bal|ob.?clamp|raw.?out|raw.?correct)',re.I)
for match in re.finditer(rb'[\x20-\x7e]{6,}', blob):
    value=match.group().decode('ascii')
    if pattern.search(value) and len(value)<300:
        strings.append(dict(address=hex(BASE+match.start()), text=value))
report=dict(scope=__doc__, firmware_sha256=SHA, descriptors=descriptors,
            nef_profile=profile, nefinfo_vtable=initialized(0xc18d3690,16),
            nefinfo_tags=tags, nefinfo_tag_list=area(taglist,2*(len(tags)+1)),
            coefficient_source_immediates=immediates,
            coefficient_metadata_template=area(0x11529e7c,0x60),
            spatial_sample_positions=area(0x115cd690,34), strings=strings,
            limitation='Tables and strings are data. A name or adjacent constant is not proof of hardware pixel semantics.')
a.output.write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(dict(descriptors=descriptors,strings=len(strings)),indent=2))

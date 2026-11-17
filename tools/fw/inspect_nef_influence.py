"""Read-only immediate-consumer inventory and native NEF tag data tables.

The immediate search covers only the literal MOVW r0,#0x3e1 encoding, not
indirect/computed config consumers. RAM table resolution uses original startup
copy records; this is initial ROM-backed data, not a runtime camera snapshot.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x10020000
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
blob = (ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
digest = hashlib.sha256(blob).hexdigest()
assert digest == '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
regions = [struct.unpack_from('<4I', blob, off) for off in range(0x14000,0x14120,16)]

def resolve(addr, size):
    if BASE <= addr and addr+size <= BASE+len(blob):
        return addr, None
    for src, dst, count, handler in regions:
        if handler == 0x1002006c and dst <= addr and addr+size <= dst+count:
            return src+addr-dst, dict(source=hex(src),destination=hex(dst),size=count)
    raise ValueError(hex(addr))

def data(addr, size):
    rom, region = resolve(addr, size)
    value = blob[rom-BASE:rom-BASE+size]
    return dict(address=hex(addr),rom=hex(rom),copy_region=region,bytes=value.hex())

def word(addr):
    return struct.unpack('<I',bytes.fromhex(data(addr,4)['bytes']))[0]

md = capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
consumers = []
for off in range(0,len(blob)-4,2):
    if blob[off:off+4] != bytes.fromhex('40f2e130'):
        continue
    insns = [dict(pc=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)
             for i in md.disasm(blob[off:off+24],BASE+off)]
    assert any(i['mnemonic']=='bl' and i['operands']=='#0x101cb734' for i in insns)
    consumers.append(dict(address=hex(BASE+off),instructions=insns))
assert len(consumers)==7

# Native profile zero (NEF context byte 1) selects group 5 for Nikon MakerNotes.
root = word(0xc18d38a0)
vtable = word(0x11537588+5*4)
selected_list = word(root+5*4)
tags = []
for i in range(200):
    value = struct.unpack('<H',bytes.fromhex(data(selected_list+2*i,2)['bytes']))[0]
    if value == 0xffff:
        break
    tags.append(value)
else:
    raise ValueError('unterminated tag list')
assert 0x3d in tags
descriptor = data(0x11537028,16)
tag, kind, count, default, callback = struct.unpack('<HHIII',bytes.fromhex(descriptor['bytes']))
assert (tag,kind,count,default,callback)==(0x3d,3,4,0,0x1028a9d9)
report = dict(scope=__doc__,firmware_sha256=digest,config_immediate_consumers=consumers,
    metadata=dict(profile_pointer=data(0xc18d38a0,4),profile_root=data(root,64),
        group5_vtable_pointer=data(0x11537588+5*4,4),group5_vtable=data(vtable,16),
        group5_filter=hex(word(0x115375c8+5*4)),
        selected_tag_list=data(selected_list,(len(tags)+1)*2),selected_tags=tags,
        blacklevel_descriptor=descriptor,tag_id=hex(tag),type=kind,count=count,callback=hex(callback)))
assert not a.output.exists()
a.output.write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(dict(config_reads=[c['address'] for c in consumers],metadata=report['metadata']),indent=2))

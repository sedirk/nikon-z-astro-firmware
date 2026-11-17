"""Read-only Thumb immediate candidates for fixed calibration operators.

Decode every aligned MOVW/ADD.W candidate in the first 5 MiB. These hits need
control-flow confirmation; data and second halfwords are not executable proof.
"""
from pathlib import Path
import argparse, hashlib, json, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM

ROOT=Path(__file__).resolve().parents[2]; BASE=0x10020000

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();assert not a.output.exists()
    b=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    digest=hashlib.sha256(b).hexdigest()
    assert digest=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
    values={0xa6e90,0xacdf0,0x6e90,0xcdf0,0xb2d50,0x2d50,0xb8cb0,0x8cb0,
            0xbcad0,0xcad0,0xc2a30,0x2a30,0xc4a10,0x4a10,0xc8830,0x8830,
            0x5f60,0x3e20,0x1fe0,0x17d8,0xf88,0x7f8,0x47180,0x7180,0xd8000}
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True;rows=[]
    for off in range(0,0x500000,2):
        h=struct.unpack_from('<H',b,off)[0]
        if h & 0xf800 != 0xf000:continue
        i=next(md.disasm(b[off:off+4],BASE+off,count=1),None)
        if not i or i.mnemonic not in ('movw','mov.w','add.w','addw','sub.w','subw','cmp.w','cmp'):continue
        if not any(o.type==ARM_OP_IMM and o.imm in values for o in i.operands):continue
        lo=i.address-16;hi=i.address+20
        rows.append(dict(pc=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str,
                         window=[dict(pc=hex(x.address),bytes=x.bytes.hex(),mnemonic=x.mnemonic,operands=x.op_str)
                                 for x in md.disasm(b[lo-BASE:hi-BASE],lo)]))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(dict(scope=__doc__,sha256=digest,candidates=rows),indent=2),encoding='utf8')
    a.output.with_suffix('.txt').write_text('\n'.join(f"{x['pc']} {x['mnemonic']} {x['operands']}" for x in rows)+'\n',encoding='utf8')
    print(json.dumps(dict(candidates=len(rows),output=str(a.output))))

if __name__=='__main__':main()

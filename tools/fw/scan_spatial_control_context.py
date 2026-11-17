"""Search stock printable labels and bounded ARM immediate candidates; hits are not code proof."""
from pathlib import Path
import argparse,json,re,struct
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM
from probe_raw_candidates import ROOT,BASE,sha
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert not a.output.exists()
    b=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    assert sha(b)=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
    labels=[]
    pattern=re.compile(r'shading|defect|pixel|gain|calib|correction|\bBLC\b|\bLSC\b|DSNU|PRNU|front',re.I)
    for m in re.finditer(rb'[\x20-\x7e]{5,}',b):
        text=m.group().decode('ascii')
        if len(text)<=300 and pattern.search(text):labels.append(dict(address=hex(BASE+m.start()),text=text))
    values={0x47180,0x47198,0x4719a,0x471a4,0x472ac,0x7180,0x7198,0x719a,0x71a4,
            0x20068700,0x20068704,0x8700,0x8704,0x68f00,0x686e4}
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True;hits=[]
    for off in range(0,0x500000,2):
        h=struct.unpack_from('<H',b,off)[0]
        if h&0xf800!=0xf000:continue
        i=next(md.disasm(b[off:off+4],BASE+off,count=1),None)
        if i and i.mnemonic in ('movw','mov.w','add.w','addw','sub.w','subw') and any(o.type==ARM_OP_IMM and o.imm in values for o in i.operands):
            hits.append(dict(pc=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str))
    result=dict(scope=__doc__,firmware_sha256=sha(b),labels=labels,immediate_candidates=hits)
    a.output.write_text(json.dumps(result,indent=2),encoding='utf8')
    a.output.with_suffix('.txt').write_text('\n'.join(f"{r['address']} {r['text']}" for r in labels)+'\n',encoding='utf8')
    print(json.dumps(dict(labels=len(labels),immediate_candidates=hits)))
if __name__=='__main__':main()

"""Bounded inventory of direct gate callers and temporary-flag stores.

Every-halfword scans are candidates, not a whole-program absence proof. Small
windows and exact original bytes are retained for manual control-flow review.
"""
from pathlib import Path
import argparse,hashlib,json,struct
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
from capstone.arm import ARM_OP_MEM
ROOT=Path(__file__).resolve().parents[2];BASE=0x10020000

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    b=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True
    def window(pc,before=28,after=16):
        return [dict(pc=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)
                for i in md.disasm(b[pc-before-BASE:pc+after-BASE],pc-before)]
    stores=[]
    for pc in range(0x10178000,0x10180000,2):
        h1,h2=struct.unpack_from('<HH',b,pc-BASE)
        if h1&0xfe00!=0xf800 or h2&0xfff!=0x84:continue
        i=next(md.disasm(b[pc-BASE:pc-BASE+4],pc,count=1),None)
        if i and i.mnemonic.startswith('str') and any(o.type==ARM_OP_MEM and o.mem.disp==0x84 for o in i.operands):
            stores.append(dict(pc=hex(pc),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str,window=window(pc)))
    calls=json.loads((ROOT/'analysis/raw-fixed-operators-2026-11-09/id35-scope-callers.json').read_text())['branches']
    calls=[dict(**c,window=window(int(c['pc'],16))) for c in calls]
    # Code addresses potentially targeted within the replacement block.
    lo,hi=0x1011c78a,0x1011c7bc;branches=[];pointers=[]
    targets=set(range(lo,hi,2))
    for off in range(0,0x500000,2):
        h1,h2=struct.unpack_from('<HH',b,off);pc=BASE+off
        if h1&0xf800==0xf000 and h2&0x9000==0x9000:
            s=(h1>>10)&1;j1=(h2>>13)&1;j2=(h2>>11)&1
            imm=(s<<24)|((1^(j1^s))<<23)|((1^(j2^s))<<22)|((h1&0x3ff)<<12)|((h2&0x7ff)<<1)
            if s:imm-=1<<25
            dest=pc+4+imm
            if dest in targets:branches.append(dict(pc=hex(pc),target=hex(dest),kind='Thumb2 direct candidate'))
    # Short branches can reach the block only from a bounded surrounding span.
    for pc in range(lo-2048,hi+2048,2):
        i=next(md.disasm(b[pc-BASE:pc-BASE+4],pc,count=1),None)
        if not i or not i.mnemonic.startswith(('b','cb')):continue
        if any(getattr(o,'imm',None) in targets for o in i.operands if o.type==2):
            branches.append(dict(pc=hex(pc),instruction=f'{i.mnemonic} {i.op_str}',window=window(pc,8,8)))
    for dest in targets:
        start=0;needle=struct.pack('<I',dest|1)
        while True:
            off=b.find(needle,start)
            if off<0:break
            pointers.append(dict(address=hex(BASE+off),value=hex(dest|1)));start=off+1
    report=dict(scope=__doc__,sha256=hashlib.sha256(b).hexdigest(),stores=stores,callers=calls,
                replacement_entries=branches,odd_pointer_candidates=pointers)
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    lines=[]
    for kind,rows in (('store',stores),('call',calls)):
        for row in rows:
            lines.append(f'\n; {kind} {row["pc"]}')
            lines.extend(f"{i['pc']} {i['mnemonic']:9s} {i['operands']}" for i in row['window'])
    (a.output/'windows.txt').write_text('\n'.join(lines),encoding='utf8')
    print(json.dumps(dict(stores=[r['pc'] for r in stores],calls=len(calls),entries=branches,pointers=pointers),indent=2))

if __name__=='__main__':main()

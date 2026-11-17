"""Find candidate Thumb field stores; halfword scans are not a code map."""
from pathlib import Path
import argparse, hashlib, json
import capstone
from capstone.arm import ARM_OP_MEM, ARM_OP_IMM

ROOT=Path(__file__).resolve().parents[2];BASE=0x10020000
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
p.add_argument('--coefficients',action='store_true',help='Find direct loads from context coefficient offsets instead.')
a=p.parse_args();blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
digest=hashlib.sha256(blob).hexdigest()
assert digest=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB);md.detail=True
ranges=((0x1011b000,0x10123000),(0x10179000,0x1017e800))
hits=[]
for lo,hi in ranges:
    for pc in range(lo,hi,2):
        ins=next(md.disasm(blob[pc-BASE:pc-BASE+4],pc,count=1),None)
        if not ins:continue
        field=ins.mnemonic.startswith('str') and any(o.type==ARM_OP_MEM and 0xa8<=o.mem.disp<=0xc0 for o in ins.operands)
        resource=ins.mnemonic.startswith(('add','sub')) and any(o.type==ARM_OP_IMM and o.imm==0xbe000 for o in ins.operands)
        if a.coefficients:
            field=ins.mnemonic.startswith('ldr') and any(o.type==ARM_OP_MEM and 0xc4<=o.mem.disp<=0xd4 for o in ins.operands)
            resource=False
        if field or resource:hits.append(dict(pc=hex(pc),bytes=ins.bytes.hex(),mnemonic=ins.mnemonic,operands=ins.op_str,reason=('coefficient-offset load' if a.coefficients else 'field-offset store') if field else 'resource-page arithmetic'))
report=dict(firmware_sha256=digest,scope=__doc__,coefficient_scan=a.coefficients,ranges=[[hex(x) for x in pair] for pair in ranges],candidates=hits)
a.output.parent.mkdir(parents=True,exist_ok=True)
a.output.write_text(json.dumps(report,indent=2),encoding='utf-8')
a.output.with_suffix('.txt').write_text('\n'.join(f"{r['pc']} {r['mnemonic']} {r['operands']} ; {r['reason']}" for r in hits)+'\n',encoding='utf-8')
print(json.dumps(dict(candidates=len(hits),output=str(a.output))))

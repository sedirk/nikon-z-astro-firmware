"""Bounded Thumb candidate scan for exposure and RAW-neighborhood investigation.

Every hit needs control-flow/object validation. Halfword scans include data and
second halves of wide instructions; this is deliberately not a symbol map.
"""
from pathlib import Path
import argparse, hashlib, json, struct
import capstone
from capstone.arm import ARM_OP_MEM, ARM_OP_IMM

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x10020000
EXPECTED = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--range', action='append', dest='ranges', required=True)
    p.add_argument('--offset', action='append', type=lambda x:int(x,0), default=[])
    p.add_argument('--immediate', action='append', type=lambda x:int(x,0), default=[])
    p.add_argument('--stores-only', action='store_true')
    p.add_argument('--arithmetic', action='store_true', help='Exploratory three-bit or 8-DN step instructions.')
    a=p.parse_args(); assert not a.output.exists()
    data=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    assert hashlib.sha256(data).hexdigest()==EXPECTED
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB); md.detail=True
    hits=[]
    for span in a.ranges:
        lo,hi=(int(x,16) for x in span.split(':'))
        assert BASE<=lo<hi<=BASE+len(data)
        for pc in range(lo,hi,2):
            h=struct.unpack_from('<H',data,pc-BASE)[0]
            # Thumb memory or wide instruction; no branches/ALU16 needed.
            if not a.immediate and not a.arithmetic and not (0x5000<=h<0xa000 or h>=0xe800): continue
            ins=next(md.disasm(data[pc-BASE:pc-BASE+4],pc,count=1),None)
            if ins is None: continue
            mem=ins.mnemonic.startswith(('str',) if a.stores_only else ('str','ldr')) and any(o.type==ARM_OP_MEM and o.mem.disp in a.offset for o in ins.operands)
            imm=ins.mnemonic.startswith(('add','sub','mov','cmp')) and any(o.type==ARM_OP_IMM and o.imm in a.immediate for o in ins.operands)
            arithmetic=a.arithmetic and ((ins.mnemonic.startswith(('and','bic')) and any(o.type==ARM_OP_IMM and o.imm in (7,56,0xfffffff8) for o in ins.operands)) or (ins.mnemonic.startswith(('lsl','lsr','ubfx','sbfx')) and any(o.type==ARM_OP_IMM and o.imm in (3,29) for o in ins.operands)))
            if mem or imm or arithmetic: hits.append(dict(pc=hex(pc),bytes=ins.bytes.hex(),mnemonic=ins.mnemonic,operands=ins.op_str,reason='arithmetic' if arithmetic else ('offset' if mem else 'immediate')))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(dict(scope=__doc__,firmware_sha256=EXPECTED,ranges=a.ranges,offsets=a.offset,immediates=a.immediate,candidates=hits),indent=2))
    a.output.with_suffix('.txt').write_text('\n'.join(f"{r['pc']} {r['mnemonic']} {r['operands']}" for r in hits)+'\n')
    print(json.dumps(dict(output=str(a.output),candidates=len(hits))))

if __name__=='__main__': main()

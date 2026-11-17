"""Read original scatter-loaded Thumb update backend without executing hardware."""
from pathlib import Path
import argparse,hashlib,json,struct
import capstone
from capstone.arm import ARM_OP_MEM,ARM_REG_PC
ROOT=Path(__file__).resolve().parents[2];BASE=0x10020000
EXPECTED='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--range',action='append',dest='ranges',required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    data=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    if hashlib.sha256(data).hexdigest()!=EXPECTED:raise ValueError('Original changed')
    regions=[(BASE,data)];scatter=[]
    for off in range(0x14000,0x14120,16):
        src,dst,n,handler=struct.unpack_from('<4I',data,off)
        scatter.append(dict(source=hex(src),dest=hex(dst),size=n,handler=hex(handler)))
        if handler==0x1002006c:regions.append((dst,data[src-BASE:src-BASE+n]))
    def read(addr,n):
        for start,blob in regions:
            if start<=addr and addr+n<=start+len(blob):return blob[addr-start:addr-start+n]
        raise ValueError(f'No source mapping for {addr:x}+{n:x}')
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB);md.detail=True
    spans=[];lines=[]
    for span in a.ranges:
        lo,hi=(int(x,16) for x in span.split(':'));rows=[]
        lines.append('; '+span)
        for ins in md.disasm(read(lo,hi-lo),lo):
            row=dict(pc=hex(ins.address),bytes=ins.bytes.hex(),mnemonic=ins.mnemonic,operands=ins.op_str)
            for operand in ins.operands:
                if ins.mnemonic.startswith('ldr') and operand.type==ARM_OP_MEM and operand.mem.base==ARM_REG_PC:
                    addr=((ins.address+4)&~3)+operand.mem.disp
                    try:row.update(literal_address=hex(addr),literal_value=hex(struct.unpack('<I',read(addr,4))[0]))
                    except ValueError:pass
            rows.append(row)
            lines.append(f"{ins.address:08x} {ins.mnemonic:9s} {ins.op_str}"+
                (f" ; [{row['literal_address']}]={row['literal_value']}" if 'literal_value' in row else ''))
        spans.append(dict(start=hex(lo),end=hex(hi),instructions=rows))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x',encoding='utf8') as f:json.dump(dict(scatter=scatter,ranges=spans,
        scope='Read-only disassembly. Linear ranges may contain literal pools; instruction reachability must be checked.'),f,indent=2)
    with a.output.with_suffix('.txt').open('x',encoding='utf8') as f:f.write('\n'.join(lines)+'\n')
    print(json.dumps(dict(output=str(a.output),ranges=len(spans))))
if __name__=='__main__':main()

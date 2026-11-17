"""Curated original instruction ranges for no-lens curve state research."""
from pathlib import Path
import argparse, hashlib, json
import capstone

ROOT=Path(__file__).resolve().parents[2]
BASE=0x10020000
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args(); assert not a.output.exists()
blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
sha=hashlib.sha256(blob).hexdigest()
assert sha=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
ranges=[(0x100c22e0,0x100c234e,'numeric-mode-selector'),
 (0x100c24f2,0x100c2610,'main-property-builder-before-literals'),
 (0x100c2628,0x100c2824,'main-property-builder-after-literals'),
 (0x100c289e,0x100c29e4,'still-curve-builder'),
 (0x100c1e22,0x100c1ef2,'source-property-projection'),
 (0x1013c392,0x1013c422,'neutral-selector'),
 (0x1014962c,0x101496a8,'neutral-helper-2c'),
 (0x101496a8,0x101496e8,'neutral-helper-a8-before-table1'),
 (0x101496ec,0x10149702,'neutral-helper-a8-before-table2'),
 (0x1014970a,0x10149710,'neutral-helper-a8-return'),
 (0x1013fa50,0x1013fa68,'still-neutral-producer'),
 (0x1013c5ae,0x1013c5be,'other-neutral-producer'),
 (0x100ab4f4,0x100ab51e,'cached-input-predicate'),
 (0x100ac74a,0x100ac76e,'stage-cached-input-predicate'),
 (0x10164bd2,0x10164c1c,'property-wrapper'),
 (0x10170dea,0x10170e18,'system-lock-wrappers')]
report=dict(firmware_sha256=sha,ranges=[],data=[],scope='Curated instruction evidence; no physical pixel interpretation.')
lines=[]
for lo,hi,label in ranges+[(0x100361e8,0x10036208,'ARM-system-service-failure-site')]:
    isa='ARM' if lo==0x100361e8 else 'Thumb'
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_ARM if isa=='ARM' else capstone.CS_MODE_THUMB)
    ins=[dict(pc=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)
         for i in md.disasm(blob[lo-BASE:hi-BASE],lo)]
    assert ins and int(ins[-1]['pc'],16)+len(bytes.fromhex(ins[-1]['bytes']))==hi,label
    report['ranges'].append(dict(start=hex(lo),end=hex(hi),label=label,instruction_set=isa,instructions=ins))
    lines.append(f'\n; {isa} {label}')
    lines.extend(f"{i['pc']} {i['mnemonic']:9s} {i['operands']}" for i in ins)
for lo,size in ((0x101496e8,4),(0x10149702,8)):
    data=blob[lo-BASE:lo-BASE+size]
    report['data'].append(dict(address=hex(lo),size=size,bytes=data.hex(),purpose='TBB offsets, not instructions'))
a.output.write_text(json.dumps(report,indent=2),encoding='utf-8')
a.output.with_suffix('.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print(json.dumps(dict(ranges=len(report['ranges']),instructions=sum(len(x['instructions']) for x in report['ranges']),data_tables=len(report['data']))))

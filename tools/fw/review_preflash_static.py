"""Independent, read-only final inspection of the pinned Z6 EG candidate."""
from pathlib import Path
import argparse, binascii, hashlib, json, struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x10020000
ORIGINAL = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
CANDIDATE = 'eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875'
EDITS = ((0x100c2654, '00f065fa', '4ff00000'),
         (0x100c267c, '00f045fa', '4ff00200'),
         (0x100c2690, '90f81a18', '4ff00201'))

def require(value, message):
    if not value: raise ValueError(message)

def sha(data): return hashlib.sha256(data).hexdigest()

def disasm(data, lo, hi, arm=False):
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM if arm else capstone.CS_MODE_THUMB)
    return [dict(pc=hex(i.address), bytes=i.bytes.hex(), mnemonic=i.mnemonic, operands=i.op_str)
            for i in md.disasm(data[lo-BASE:hi-BASE], lo)]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    original=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    candidate=(ROOT/'outputs/Z6-C380-neighborhood-candidate-2026-11-09/candidate/EG162080.BIN').read_bytes()
    require(sha(original)==ORIGINAL and sha(candidate)==CANDIDATE, 'Pinned input hash mismatch')
    require(len(original)==len(candidate)==33502842, 'Size mismatch')
    expected=bytearray(original);patches=[]
    for pc,old,new in EDITS:
        off=pc-BASE;require(original[off:off+4]==bytes.fromhex(old), 'Old instruction mismatch')
        expected[off:off+4]=bytes.fromhex(new)
        old_ins=disasm(original,pc,pc+4);new_ins=disasm(candidate,pc,pc+4)
        require(len(old_ins)==len(new_ins)==1 and new_ins[0]['mnemonic']=='mov.w', 'Instruction boundary mismatch')
        patches.append(dict(pc=hex(pc),original=old_ins,candidate=new_ins))
    expected[-2:]=binascii.crc_hqx(expected[:-2],0).to_bytes(2,'big')
    require(bytes(expected)==candidate,'Unexpected candidate content')
    require(binascii.crc_hqx(original,0)==binascii.crc_hqx(candidate,0)==0,'CRC mismatch')
    offsets=[hex(i) for i,(x,y) in enumerate(zip(original,candidate)) if x!=y]
    require(len(offsets)==12, 'Unexpected diff count')
    spans=[('startup_header',BASE,BASE+0x15000,False),
           ('patch_context',0x100c2648,0x100c26c6,False),
           ('pure_converter_leaves',0x100c2b0a,0x100c2b3a,False),
           ('flash_arm_veneers',0x1014a674,0x1014a6a4,True)]
    ranges=[]
    for label,lo,hi,arm in spans:
        ranges.append(dict(label=label,start=hex(lo),end=hex(hi),mode='ARM' if arm else 'Thumb',
            unchanged=original[lo-BASE:hi-BASE]==candidate[lo-BASE:hi-BASE],
            instructions=[] if label=='startup_header' else disasm(original,lo,hi,arm)))
    # The code and data outside the three 4-byte slots plus trailing CRC must be
    # identical, including all updater code. This is stronger than selected hashes.
    # ARM LDR-PC veneers contain a data word after each instruction, not code.
    veneers=[]
    for pc in (0x1014a674,0x1014a67c,0x1014a684):
        veneers.append(dict(pc=hex(pc),instruction=disasm(original,pc,pc+4,True),
                            target_pointer=hex(struct.unpack_from('<I',original,pc+4-BASE)[0])))
    ranges[-1]['instructions']=[i for v in veneers for i in v['instruction']]
    report=dict(ok=True,original_sha256=ORIGINAL,candidate_sha256=CANDIDATE,
        changed_byte_offsets=offsets,patches=patches,ranges=ranges,
        startup_first_0x15000_unchanged=ranges[0]['unchanged'],
        all_other_bytes_identical=True,physical_boot_test=False,arm_veneers=veneers,
        caveat='Static inspection and prior bounded calls are not a physical boot, power-failure, or recovery guarantee.')
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    (a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    lines=[]
    for r in ranges:
        lines.append(f"; {r['label']} {r['mode']} {r['start']}..{r['end']}")
        lines.extend(f"{i['pc']} {i['bytes']} {i['mnemonic']} {i['operands']}" for i in r['instructions'])
    (a.output/'disassembly.txt').write_text('\n'.join(lines)+'\n',encoding='utf8')
    print(json.dumps(dict(ok=True,diff_bytes=len(offsets),candidate_sha256=CANDIDATE)))

if __name__=='__main__': main()

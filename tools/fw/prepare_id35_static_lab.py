"""Assemble a same-size ID35 temporary-stage LAB candidate, not an install kit.

Repack the existing kind0 block to make room for a context+84 guard. No code
cave, added image area, new address, calibration edit or extra processing bit.
The hardware pixel operation remains unidentified; this is a causal-test input.
"""
from pathlib import Path
import argparse,binascii,hashlib,json
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
from keystone import Ks,KS_ARCH_ARM,KS_MODE_THUMB

ROOT=Path(__file__).resolve().parents[2];BASE=0x10020000
M4='outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN'
HASH='bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b'
START,END=0x1011c78a,0x1011c7bc
ASM='''
    ldr r2, [r2, #0x14]
    movs r3, #80
    muls r0, r3
    adds r2, r2, r0
    add.w r2, r2, #0x540
    ldr r0, [pc, #0x11c]
    subs r0, #0x84
    ldrb r3, [r2]
    ldr.w r1, [r6, #0x84]
    cbz r1, original_gate
    mov r3, r4
original_gate:
    str r3, [r0, #0x1c]
    ldrb r3, [r2, #1]
    strb.w r3, [r0, #0x20]
    ldrb r3, [r2, #2]
    strb.w r3, [r0, #0x26]
    ldrb r3, [r2, #3]
    str r3, [r0, #0x7c]
    bl #0x10110c08
    b #0x1011c81c
'''

def sha(b):return hashlib.sha256(b).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    src=ROOT/M4;b=src.read_bytes();assert sha(b)==HASH and binascii.crc_hqx(b,0)==0
    stock=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    before=b[START-BASE:END-BASE];assert before==stock[START-BASE:END-BASE]
    assembled,count=Ks(KS_ARCH_ARM,KS_MODE_THUMB).asm(ASM,addr=START)
    code=bytes(assembled)
    (a.output/'replacement.s').write_text(ASM,encoding='utf8')
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    instructions=[dict(pc=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)
                  for i in md.disasm(code,START)]
    report=dict(status='LAB_ONLY_NOT_PREFLASH_REVIEWED',scope=__doc__,parent=M4,parent_sha256=HASH,
                address=hex(START),end=hex(END),before=before.hex(),after=code.hex(),instructions=instructions,
                allowed_semantic_change='kind0: context+84 nonzero forces ID35 gate to 0; otherwise all fields retain native values.',
                static_scope_limit='Guard is the native temporary-stage flag; call-site and lifecycle audit required before installation.',
                pixel_operation='Unknown hardware; no claim of ring removal or full dark-current recovery.')
    (a.output/'assembly.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    assert len(code)==END-START,(len(code),END-START)
    # Literal must still load the existing PROC base, then subtract 0x84.
    literal=next(i for i in instructions if i['operands'].startswith('r0, [pc,'))
    pc=int(literal['pc'],16);addr=((pc+4)&~3)+0x11c
    assert addr==0x1011c8b4,(literal,hex(addr))
    changed=bytearray(b);changed[START-BASE:END-BASE]=code
    changed[-2:]=binascii.crc_hqx(changed[:-2],0).to_bytes(2,'big')
    assert len(changed)==len(b) and binascii.crc_hqx(changed,0)==0
    differences=[i for i,(x,y) in enumerate(zip(b,changed)) if x!=y]
    assert all(START-BASE<=i<END-BASE or i>=len(b)-2 for i in differences)
    dest=a.output/'modified4-id35-temporary-off-lab.bi';dest.write_bytes(changed)
    report.update(module=dest.name,sha256=sha(changed),bytes=len(changed),crc16_hex=changed[-2:].hex(),
                  changed_code_bytes=sum(i<len(b)-2 for i in differences),total_changed_bytes=len(differences),
                  firmware_original_unchanged=sha(src.read_bytes())==HASH)
    (a.output/'manifest.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    (a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps({k:report[k] for k in ('status','sha256','bytes','changed_code_bytes','total_changed_bytes')}))

if __name__=='__main__':main()

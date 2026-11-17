"""Build an exact-static-call ID35 gate-off LAB module on modified4.

Use private kind4 at 10179d54 only; the dispatcher removes bit2 for record
selection and retains the original argument in r7. Kind0 sees r7=0 normally or
4 at that static call. Only the latter clears the ID35 gate. Public kinds0..2
are the validated domain; other private/undefined kinds require separate review.
No image growth, caves, new literals, calibration edits or hardware formula.
"""
from pathlib import Path
import argparse,binascii,json
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
from keystone import Ks,KS_ARCH_ARM,KS_MODE_THUMB
from prepare_id35_static_lab import ROOT,BASE,M4,HASH,START,END,sha

BLOCK='''
    ldr r2, [r2, #0x14]
    movs r3, #80
    muls r0, r3
    adds r2, r2, r0
    add.w r2, r2, #0x540
    ldr r0, [pc, #0x11c]
    subs r0, #0x84
    ldrb r3, [r2]
    cbz r7, original_gate
    mov r3, r4
original_gate:
    nop
    nop
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

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    src=ROOT/M4;original=src.read_bytes();assert sha(original)==HASH and binascii.crc_hqx(original,0)==0
    ks=Ks(KS_ARCH_ARM,KS_MODE_THUMB);md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    specs=[(0x10179d54,2,'movs r0, #4','Private tag at the one observed static kind0 call.'),
           (0x1011c756,8,'mov r7, r0; bic r5, r0, #4; mov r6, r1','Keep raw kind in r7, use ordinary kind for native record lookup.'),
           (0x1011c764,4,'cmp r0, #28; bhs #0x1011c786','Selector returns 0..27 or 0xffff; equivalent rejection on that domain.'),
           (START,END-START,BLOCK,'Original four-field construction with only the tagged ID35 gate zeroed.')]
    b=bytearray(original);edits=[]
    for address,size,assembly,why in specs:
        code=bytes(ks.asm(assembly,addr=address)[0]);assert len(code)==size,(hex(address),len(code),size)
        old=original[address-BASE:address-BASE+size]
        edits.append(dict(address=hex(address),before=old.hex(),after=code.hex(),reason=why,assembly=assembly,
            instructions=[dict(pc=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str) for i in md.disasm(code,address)]))
        b[address-BASE:address-BASE+size]=code
    b[-2:]=binascii.crc_hqx(b[:-2],0).to_bytes(2,'big')
    assert len(b)==len(original) and binascii.crc_hqx(b,0)==0
    # Same native call/return site and existing literal; no relocation.
    for lo,hi in ((0x1011c7b6,0x1011c7bc),(0x1011c8b4,0x1011c8b8)):
        assert b[lo-BASE:hi-BASE]==original[lo-BASE:hi-BASE]
    diff=[i for i,(x,y) in enumerate(zip(b,original)) if x!=y]
    dest=a.output/'modified4-id35-static-call-off-lab.bi';dest.write_bytes(b)
    report=dict(status='LAB_ONLY_NOT_PREFLASH_REVIEWED',scope=__doc__,parent=M4,parent_sha256=HASH,
        module=dest.name,sha256=sha(b),bytes=len(b),changed_code_bytes=sum(i<len(b)-2 for i in diff),
        total_changed_bytes=len(diff),crc16_hex=b[-2:].hex(),edits=edits,
        semantic_variable='ID35 global gate = 0 at static call 10179d56; other validated public calls preserve calibration values.',
        table33x4='Unchanged; unity and physical operation not assumed.',hardware_pixels_verified=False,
        ordinary_api_kinds=[0,1,2],new_private_kind=4,source_unchanged=sha(src.read_bytes())==HASH)
    (a.output/'manifest.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    (a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps({k:report[k] for k in ('status','sha256','bytes','changed_code_bytes','total_changed_bytes')}))

if __name__=='__main__':main()

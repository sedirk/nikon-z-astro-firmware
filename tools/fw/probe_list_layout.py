"""Execute unmodified Thumb list logic on explicitly synthetic tagged inputs.

Verifies packing and pointer selection, not the interpretation of list words
by silicon. No memory-write hooks (see check_unicorn_memhook.py).
"""
from pathlib import Path
import hashlib
import json
import struct
import unicorn
from unicorn.arm_const import *

ROOT=Path(__file__).resolve().parents[2]
BASE=0x10020000
SOURCE=0x50000000
DEST=0x51000000
STACK=0x52000000
STOP=0x53000000
CONFIG=0xc20aa7c8
STATE=0xc18fa954
GROUP=0x39000
SIZE=7*GROUP
EXPECTED='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'

def main():
    image=ROOT/'firmware/decoded/eg1620_038000.bi'
    data=image.read_bytes()
    assert hashlib.sha256(data).hexdigest()==EXPECTED
    uc=unicorn.Uc(unicorn.UC_ARCH_ARM,unicorn.UC_MODE_THUMB)
    uc.mem_map(BASE,(len(data)+4095)&~4095)
    uc.mem_write(BASE,data)
    uc.mem_protect(BASE,(len(data)+4095)&~4095,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
    uc.mem_map(SOURCE,0x100000)
    uc.mem_map(DEST,0x190000)
    uc.mem_map(STACK,0x10000)
    uc.mem_map(STOP,0x1000)
    for address in (CONFIG,0xc18812b4,STATE,0xc18d20dc):
        uc.mem_map(address&~4095,4096)
    uc.mem_write(0xc18812b4,struct.pack('<I',1))
    descriptor=data[0x11f66eb0-BASE:0x11f66eb0-BASE+84]
    uc.mem_write(0xc18d20dc,descriptor)
    source=bytearray(0x100000)
    expected=bytearray(SIZE)
    groups=[]
    for group in range(7):
        mode,blocks,_,_,length,offset=struct.unpack_from('<4B2I',descriptor,12*group)
        rows=8*blocks
        assert mode in (0,1) and rows==104
        for stream in range(3):
            for row in range(rows):
                # Deliberately artificial identifiers, not pixel coordinates.
                tag=0x11000000|(group<<20)|(stream<<16)|(row<<1)
                values=(tag|1,tag|0x8000,0xffffffff)
                src=(offset+stream*length+row*3)*4
                struct.pack_into('<3I',source,src,*values)
                packed_row=(row//8)*24+stream*8+row%8 if mode==0 else stream*152+row
                struct.pack_into('<3I',expected,group*GROUP+packed_row*512,*values)
        groups.append(dict(index=group,packing_mode=mode,input_rows_per_stream=rows,
                           stream_stride_words=length,source_offset_words=offset,
                           populated_output_rows=3*rows))
    uc.mem_write(SOURCE,bytes(source))
    def prepare():
        uc.reg_write(UC_ARM_REG_SP,STACK+0xf000)
        uc.reg_write(UC_ARM_REG_LR,STOP|1)
    cases=[]
    for flag in (0,1):
        uc.mem_write(CONFIG+0x29e,bytes([flag]))
        uc.mem_write(DEST,b'Z'*(SIZE+32))
        prepare()
        for reg,val in ((UC_ARM_REG_R4,0),(UC_ARM_REG_R6,DEST),(UC_ARM_REG_R9,1),(UC_ARM_REG_R10,SOURCE)):
            uc.reg_write(reg,val)
        uc.mem_write(STACK+0xf000,struct.pack('<3I',0,0x9800,0x4c00))
        uc.emu_start(0x100bc151,0x100bc204,count=3_000_000)
        assert uc.reg_read(UC_ARM_REG_PC)==0x100bc204
        actual=bytes(uc.mem_read(DEST,SIZE))
        if flag==0:
            target=bytes(expected)
        else:
            target=(b'\xff'*4+bytes(508))*456+b'Z'*(SIZE-GROUP)
        assert actual==target, f'Unexpected list packing flag={flag}'
        assert bytes(uc.mem_read(DEST+SIZE,32))==b'Z'*32
        cases.append(dict(flag=flag,bytes=len(actual),sha256=hashlib.sha256(actual).hexdigest(),
                          matches_independent_expected=True,tail_guard_unchanged=True,
                          all_other_groups_untouched=actual[GROUP:]==b'Z'*(SIZE-GROUP)))
    pointer_cases=[]
    mode_map=[0,0,0,0,0,1,2,3,4,2,5,5,0]
    for pointer in (0,0x80400000):
        uc.mem_write(STATE+0x1c,struct.pack('<I',pointer))
        for mode in range(14):
            prepare();uc.reg_write(UC_ARM_REG_R0,mode)
            uc.emu_start(0x1011d55f,STOP,count=100)
            assert uc.reg_read(UC_ARM_REG_PC)==STOP
            value=uc.reg_read(UC_ARM_REG_R0)
            expected_value=pointer+0x1f8000+mode_map[mode]*0xd0 if pointer and mode<13 else 0
            assert value==expected_value
            pointer_cases.append(dict(pointer=hex(pointer),mode=mode,returned=hex(value)))
    report=dict(firmware_sha256=EXPECTED,unicorn_version=unicorn.__version__,
                native_code_changed=False,memory_write_hooks=False,
                scope='Synthetic RAM, original list body and pointer getter; no allocation/locking prologue, RTOS, ISP, pixels, NEF or real calibration.',
                list_cases=cases,group_descriptors=groups,resource_b_pointer_cases=pointer_cases,
                firmware_unchanged=hashlib.sha256(image.read_bytes()).hexdigest()==EXPECTED)
    out=ROOT/'analysis/list-path-2026-11-02/synthetic-layout.json'
    out.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(output=str(out),list_cases=cases,pointer_cases=len(pointer_cases)),indent=2))

if __name__=='__main__':
    main()

"""Diagnose an observed skipped original MOVW using fresh isolated CPU instances."""
from pathlib import Path
import argparse,hashlib,json
import unicorn as un
from unicorn.arm_const import *
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
assert not a.output.exists()
root=Path(__file__).resolve().parents[2]
b=(root/'firmware/decoded/eg1620_038000.bi').read_bytes()
assert hashlib.sha256(b).hexdigest()=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
rows=[]
for entry in (0x1015e0dc,0x1015e0e2):
    for hooks in (False,True):
        u=un.Uc(un.UC_ARCH_ARM,un.UC_MODE_THUMB)
        u.mem_map(0x10020000,(len(b)+4095)&~4095);u.mem_write(0x10020000,b)
        u.mem_map(0x50000000,0x10000);u.mem_write(0x50000006,b'\x01')
        u.reg_write(UC_ARM_REG_R6,0x50000000);u.reg_write(UC_ARM_REG_R1,0xffffffc0)
        u.reg_write(UC_ARM_REG_SP,0x50008000)
        instructions=[]
        if hooks:
            def observe(_u,pc,size,_):
                instructions.append(dict(pc=hex(pc),bytes=bytes(u.mem_read(pc,size)).hex(),r1=hex(u.reg_read(UC_ARM_REG_R1))))
            u.hook_add(un.UC_HOOK_CODE,observe)
        u.emu_start(entry|1,0x1015e0f0,count=20)
        rows.append(dict(entry=hex(entry),hooks=hooks,r1=hex(u.reg_read(UC_ARM_REG_R1)),pc=hex(u.reg_read(UC_ARM_REG_PC)),
                         stored=bytes(u.mem_read(0x50008000,8)).hex(),instructions=instructions))
a.output.write_text(json.dumps(dict(unicorn=un.__version__,rows=rows),indent=2),encoding='utf-8')
print(json.dumps(rows,indent=2))

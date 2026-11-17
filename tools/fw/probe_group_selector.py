"""Enumerate the original pure list-group branch; mode enum meanings unknown."""
from pathlib import Path
import hashlib,json
import unicorn
from unicorn.arm_const import *

ROOT=Path(__file__).resolve().parents[2]
data=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
assert hashlib.sha256(data).hexdigest()=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
uc=unicorn.Uc(unicorn.UC_ARCH_ARM,unicorn.UC_MODE_THUMB)
uc.mem_map(0x10020000,(len(data)+4095)&~4095);uc.mem_write(0x10020000,data)
uc.mem_map(0x50000000,4096);uc.reg_write(UC_ARM_REG_R8,0x50000000)
rows=[]
for mode in range(14):
    values=[]
    for submode in range(8):
        uc.mem_write(0x5000000c,bytes([mode,submode]))
        uc.emu_start(0x100bc469,0x100bc4a6,count=100)
        assert uc.reg_read(UC_ARM_REG_PC)==0x100bc4a6
        values.append(uc.reg_read(UC_ARM_REG_R0))
    rows.append(dict(mode=mode,submodes_0_to_7=values))
report=dict(scope='Native branch 100bc468..100bc4a6 only; request+8==0 path. Numeric mode meanings not inferred.',cases=112,rows=rows)
(ROOT/'analysis/list-generator-2026-11-02/group-selection.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2))

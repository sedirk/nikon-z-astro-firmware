"""Reproduce a local instrumentation discrepancy; never alters firmware bytes."""
from pathlib import Path
import hashlib
import json
import unicorn
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_BLOCK, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP, UC_ARM_REG_LR

root = Path(__file__).resolve().parents[2]
data = (root / 'firmware/decoded/eg1620_038000.bi').read_bytes()
assert hashlib.sha256(data).hexdigest() == '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
results = []
for hooks in (0, UC_HOOK_BLOCK, UC_HOOK_MEM_WRITE, UC_HOOK_BLOCK | UC_HOOK_MEM_WRITE):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.mem_map(0x10020000, (len(data) + 4095) & ~4095)
    uc.mem_write(0x10020000, data)
    uc.mem_map(0x50000000, 0x10000)
    uc.mem_write(0x50000000, b'Z' * 0x1000)
    uc.mem_map(0x60000000, 0x10000)
    for register, value in ((UC_ARM_REG_R0, 0x50000000), (UC_ARM_REG_R1, 64),
                            (UC_ARM_REG_SP, 0x60008000), (UC_ARM_REG_LR, 0x60000001)):
        uc.reg_write(register, value)
    if hooks & UC_HOOK_BLOCK:
        uc.hook_add(UC_HOOK_BLOCK, lambda *_: None)
    if hooks & UC_HOOK_MEM_WRITE:
        uc.hook_add(UC_HOOK_MEM_WRITE, lambda *_: None)
    uc.emu_start(0x10170F2D, 0x60000000, count=10000)
    result = bytes(uc.mem_read(0x50000000, 128))
    row = dict(block_hook=bool(hooks & UC_HOOK_BLOCK), memory_write_hook=bool(hooks & UC_HOOK_MEM_WRITE),
               requested_clear_bytes=64, observed_zero_bytes_in_128=result.count(0),
               trailing_guard_intact=result[64:] == b'Z' * 64)
    if not row['memory_write_hook']:
        assert row['trailing_guard_intact'] and row['observed_zero_bytes_in_128'] == 64
    results.append(row)
report = dict(unicorn_version=unicorn.__version__, scope='local isolated native Thumb helper, not a physical firmware defect',
              native_helper='0x10170f2c', results=results)
out = root / 'analysis/local-2026-11-02/unicorn_memhook_check.json'
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report, indent=2))

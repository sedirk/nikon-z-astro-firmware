from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

for func_start in [0x104c2770, 0x104c3550, 0x103c2990]:
    off = func_start - BASE
    print(f"\nDisassembling around 0x{func_start:08x}:")
    for ins in md.disasm(buf[off:off+0x70], func_start):
        print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")

from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

addr = 0x10408e00
off = addr - BASE
print(f"Disassembling 0x{addr:08x}..0x10408f00:")
for ins in md.disasm(buf[off:off+0x100], addr):
    print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")

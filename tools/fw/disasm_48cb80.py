from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

addr = 0x1048cb80
off = addr - BASE
code = buf[off : off + 0x40]
print(f"0x{addr:08x}:")
for ins in md.disasm(code, addr):
    print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")

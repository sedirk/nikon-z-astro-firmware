from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

addr = 0x103ff230
off = addr - BASE
code = buf[off : off + 0x60]

print(f"Disassembly around 0x103ff256 (0x{addr:08x}):")
for ins in md.disasm(code, addr):
    mark = " <--" if ins.address == 0x103ff256 else ""
    print(f"0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{mark}")

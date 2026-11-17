from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

addr = 0x10408e7c
off = addr - BASE
code = buf[off : off + 0x30]
print("0x10408e7c:")
for ins in md.disasm(code, addr):
    print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")

addr2 = 0x102e70d4
off2 = addr2 - BASE
code2 = buf[off2 : off2 + 0x30]
print("\n0x102e70d4:")
for ins in md.disasm(code2, addr2):
    print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")

import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

print("Fast scanning for 0x1ba2 patterns...")

# 1. 32-bit literal 0x00001ba2
lit_bytes = struct.pack("<I", 0x1ba2)
idx = 0
while True:
    idx = buf.find(lit_bytes, idx)
    if idx == -1: break
    addr = BASE + idx
    print(f"32-bit literal 0x1ba2 at 0x{addr:08x}")
    idx += 4

# 2. movw Rd, #0x1ba2: bytes: 41 f2 a2 3X (X is Rd from 0 to 15)
for r in range(16):
    pat = bytes([0x41, 0xf2, 0xa2, 0x30 | r])
    idx = 0
    while True:
        idx = buf.find(pat, idx)
        if idx == -1: break
        addr = BASE + idx
        # disasm context
        off = idx - 8
        code = buf[off : off + 24]
        print(f"\nmovw r{r}, #0x1ba2 at 0x{addr:08x}:")
        for ins in md.disasm(code, addr - 8):
            mark = " <--" if ins.address == addr else ""
            print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{mark}")
        idx += 2

import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

print("Exact search for movw Rd, #0x1ba2 (41 f6 a2 3X)...")
for r in range(16):
    pat = bytes([0x41, 0xf6, 0xa2, 0x30 | r])
    idx = 0
    while True:
        idx = buf.find(pat, idx)
        if idx == -1: break
        addr = BASE + idx
        off = idx - 12
        code = buf[off : off + 32]
        print(f"\n=== movw r{r}, #0x1ba2 at 0x{addr:08x} ===")
        for ins in md.disasm(code, addr - 12):
            mark = " <--" if ins.address == addr else ""
            print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{mark}")
        idx += 2

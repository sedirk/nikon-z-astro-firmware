from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

target = 0x1026afdc
b = struct.pack("<I", target)
idx = 0
found = []
while True:
    idx = buf.find(b, idx)
    if idx == -1: break
    found.append(BASE + idx)
    idx += 4

print(f"0x{target:08x} referenced at: {[hex(a) for a in found]}")

for c_addr in found:
    off = c_addr - BASE - 32
    code = buf[off : off + 96]
    print(f"\nDisassembly around reference at 0x{c_addr:08x}:")
    for ins in md.disasm(code, c_addr - 32):
        mark = " <--" if ins.address == c_addr else ""
        print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{mark}")

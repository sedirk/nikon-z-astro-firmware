from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
import struct

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

# Let's inspect references to 0x104c4ca8 or 0x106703bc or 0x11ecca2c
# We know 0x106703cc is at 0x106703bc + 0x10
# What class has this vtable?
# Let's look at the constructor that sets this vtable!
# Usually: ldr r1, =0x106703bc; str r1, [r0]
target = struct.pack("<I", 0x106703bc)
idx = 0
while True:
    idx = buf.find(target, idx)
    if idx == -1: break
    addr = BASE + idx
    print(f"0x106703bc referenced at 0x{addr:08x}")
    # disasm surrounding
    off = idx - 20
    for ins in md.disasm(buf[off:off+40], addr - 20):
        print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")
    idx += 4

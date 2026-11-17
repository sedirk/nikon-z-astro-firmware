from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

targets = [
    (0x11c28984, "CAM_ENTERSLEEPMODE_ACCEPT"),
    (0x11c289a0, "CAM_LEAVESLEEPMODE_ACCEPT"),
]

for addr, name in targets:
    b = struct.pack("<I", addr)
    idx = 0
    while True:
        idx = buf.find(b, idx)
        if idx == -1: break
        c_addr = BASE + idx
        print(f"{name} referenced at 0x{c_addr:08x}")
        # disasm caller function
        off = idx - 32
        for ins in md.disasm(buf[off:off+64], c_addr - 32):
            mark = " <--" if ins.address == c_addr else ""
            print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{mark}")
        idx += 4

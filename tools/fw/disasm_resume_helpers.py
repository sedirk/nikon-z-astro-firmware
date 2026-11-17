from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

for addr in [0x101d9e86, 0x101d9ec2, 0x1026a1d2, 0x1026abf0, 0x1026b26a, 0x1026a264]:
    off = addr - BASE
    print(f"\nDisassembling 0x{addr:08x}:")
    for ins in md.disasm(buf[off:off+0x30], addr):
        print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")

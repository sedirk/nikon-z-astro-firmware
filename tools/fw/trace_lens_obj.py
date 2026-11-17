from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

sites = [
    0x1035bb04,
    0x103c2a1a,
    0x103c4b08,
    0x104446dc,
    0x10444b62,
    0x104a8b98,
    0x104c280e,
    0x104c361a,
]

for s in sites:
    start = s - 32
    off = start - BASE
    print(f"\n=== Call site at 0x{s:08x} ===")
    for ins in md.disasm(buf[off:off+64], start):
        mark = " <---" if ins.address == s else ""
        print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{mark}")

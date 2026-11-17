from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

phases = [
    (0x1025de4a, "Phase 0"),
    (0x1025dfbc, "Phase 1"),
    (0x1025e0a6, "Phase 2"),
    (0x1025e17a, "Phase 3"),
    (0x1025e24c, "Phase 4"),
    (0x1025e362, "Phase 5"),
    (0x1025e4c6, "Phase 6"),
    (0x1025e5e6, "Phase 7"),
    (0x1025e71e, "Phase 8"),
    (0x1025e79c, "Phase 9"),
    (0x1025e7d8, "Phase 10"),
]

for addr, name in phases:
    print(f"\n=== {name} at 0x{addr:08x} ===")
    off = addr - BASE
    code = buf[off : off + 0x40]
    for ins in md.disasm(code, addr):
        print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")
        if ins.mnemonic == "bl":
            pass

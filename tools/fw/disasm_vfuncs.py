from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

vtable = [
    (0x104c4c6a, "vfunc_c6a"),
    (0x104c4c88, "vfunc_c88"),
    (0x104c4c8c, "vfunc_c8c"),
    (0x104c4ca8, "vfunc_ca8_restore"),
    (0x104c513e, "vfunc_13e"),
    (0x104c516a, "vfunc_16a"),
    (0x104c516e, "vfunc_16e"),
    (0x104c518e, "vfunc_18e"),
]

for addr, name in vtable:
    print(f"\n=== {name} at 0x{addr:08x} ===")
    off = addr - BASE
    code = buf[off : off + 0x60]
    for ins in md.disasm(code, addr):
        print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")
        if ins.mnemonic in ["bx", "pop"] and ("pc" in ins.op_str or "lr" in ins.op_str):
            break

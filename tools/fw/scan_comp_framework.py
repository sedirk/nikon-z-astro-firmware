from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

# Let's search for functions that call slot +0x10 across component table
# Or functions calling 0x104c4c6a, 0x104c4c8c, 0x104c4ca8
# In C++, a loop doing:
# for (comp in components) {
#    vptr = comp->vtable;
#    vptr->RestoreSettings(comp);
# }

# Let's find callers of slot 0 (+0x00): ldr rX, [rY]; blx rX
# slot 3 (+0x0c): ldr rX, [rY, #0xc]; blx rX
# slot 4 (+0x10): ldr rX, [rY, #0x10]; blx rX

print("Scanning for loops calling vtable methods...")
# Search around 0x10407000..0x10408500 (component framework functions)
for addr in [0x10407ef0, 0x10407af2, 0x1040a734, 0x10407cf4]:
    print(f"Disassembling helper 0x{addr:08x}:")
    off = addr - BASE
    for ins in md.disasm(buf[off:off+32], addr):
        print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")

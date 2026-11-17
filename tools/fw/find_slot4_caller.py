from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

# Let's search for ldr rX, [..., #0x10]; blx rX or blx ...
# In Thumb2:
# ldr r3, [rX, #0x10]; blx r3:
# ldr r3, [rX, #0x10] -> 5b 69 (if r3, r3) or 1b 69 (if r3, r0) etc.
# Or ldr.w r3, [rX, #0x10]
# Let's search all code for calling slot 4 (+0x10) of a vtable!
print("Searching for calls to vtable slot +0x10...")
for off in range(0x10400000 - BASE, 0x10420000 - BASE, 2):
    code = buf[off:off+16]
    for ins in md.disasm(code, BASE + off):
        if "blx" in ins.mnemonic:
            # check previous instructions in disasm
            prev = list(md.disasm(buf[off-12:off], BASE + off - 12))
            for p in prev:
                if "#0x10" in p.op_str and ("ldr" in p.mnemonic):
                    print(f"Call site at 0x{ins.address:08x}:")
                    for x in prev:
                        print(f"   0x{x.address:08x}: {x.mnemonic:8s} {x.op_str}")
                    print(f"-> 0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")

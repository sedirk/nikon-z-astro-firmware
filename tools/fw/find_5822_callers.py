from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

# Let's find callers of 0x10405822
target = 0x10405822
print(f"Searching callers of 0x{target:08x}...")
callers = []
for off in range(0, len(buf) - 4, 2):
    b0, b1 = buf[off], buf[off+1]
    if (b1 & 0xf8) == 0xf0:
        b2, b3 = buf[off+2], buf[off+3]
        if (b3 & 0xd0) == 0xd0:
            pc = BASE + off + 4
            s = (b1 >> 2) & 1
            imm10 = ((b1 & 3) << 8) | b0
            j1 = (b3 >> 5) & 1
            j2 = (b3 >> 3) & 1
            imm11 = ((b3 & 7) << 8) | b2
            i1 = ~(j1 ^ s) & 1
            i2 = ~(j2 ^ s) & 1
            offset = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
            if s: offset -= (1 << 25)
            if pc + offset == target:
                callers.append(BASE + off)

print(f"Found {len(callers)} callers of 0x10405822:")
for c in callers:
    # print context of caller
    off_c = c - BASE - 12
    code = buf[off_c : off_c + 20]
    insns = list(md.disasm(code, c - 12))
    context = "; ".join(f"{i.mnemonic} {i.op_str}" for i in insns[-3:])
    print(f"  0x{c:08x}: {context}")

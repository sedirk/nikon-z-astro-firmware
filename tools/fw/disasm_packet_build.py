from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

start = 0x104c4e48
off = start - BASE
print("Disassembling 0x104c4e48..0x104c4e90:")
for ins in md.disasm(buf[off:off+0x50], start):
    print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")

# Inspect literal pool around 0x104c4ef8
import struct
for a in [0x104c4e5c, 0x104c4e64]:
    off_ins = a - BASE
    # ldr r0, [pc, #imm]
    # In Thumb2: PC is a + 4
    # let's read the words at PC relative
    pass

off_pool = 0x104c4ef0 - BASE
words = struct.unpack_from("<16I", buf, off_pool)
print("\nLiteral pool around 0x104c4ef0:")
for i, w in enumerate(words):
    print(f"  0x{BASE + off_pool + i*4:08x}: 0x{w:08x}")

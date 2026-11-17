from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

# Let's inspect each candidate of `ldr rX, [rY, #0x10]; blx rX`
# that we found earlier!
candidates = [
    0x10054412,
    0x10054434,
    0x100591b6,
    0x100599d0,
    0x10062622,
    0x100b15ae,
    0x100d8d12,
    0x101f8d2a,
    0x101f8d88,
    0x101f8e6a,
    0x101f8ec8,
    0x101f99a4,
    0x101f9c02,
    0x102391a0,
    0x102391b4,
    0x1026724e,
    0x1027b60e,
    0x1027d22a,
    0x10348150,
]

for addr in candidates:
    off = addr - BASE - 16
    code = buf[off : off + 32]
    print(f"\n=== Candidate at 0x{addr:08x} ===")
    for ins in md.disasm(code, addr - 16):
        mark = " <--" if ins.address == addr else ""
        print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{mark}")

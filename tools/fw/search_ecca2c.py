from pathlib import Path
import struct
from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()

target = 0x11ecca2c
# 1. 32-bit literal
b = struct.pack("<I", target)
idx = 0
while True:
    idx = buf.find(b, idx)
    if idx == -1: break
    print(f"Literal 0x{target:08x} at 0x{BASE + idx:08x}")
    idx += 4

# 2. movw / movt to target
# movw Rd, #0xca2c
# movt Rd, #0x11ec
ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
for r in range(12):
    code_w = bytes(ks.asm(f"movw r{r}, #0xca2c")[0])
    code_t = bytes(ks.asm(f"movt r{r}, #0x11ec")[0])
    idx = 0
    while True:
        idx = buf.find(code_w, idx)
        if idx == -1: break
        print(f"movw r{r}, #0xca2c found at 0x{BASE + idx:08x}")
        idx += 2

# 3. Base address 0x11ecc000 or 0x11ecc800
for base_addr in [0x11ecc000, 0x11ecc8d0, 0x11ecc900, 0x11ecca00]:
    b = struct.pack("<I", base_addr)
    idx = 0
    while True:
        idx = buf.find(b, idx)
        if idx == -1: break
        print(f"Base 0x{base_addr:08x} literal at 0x{BASE + idx:08x}")
        idx += 4

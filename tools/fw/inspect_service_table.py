from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

# Where is 0x11ecca00 / 0x11ecca2c used?
# Let's search for references to 0x11ecca00
for target in [0x11ecca00, 0x11ecca2c]:
    b = struct.pack("<I", target)
    idx = 0
    while True:
        idx = buf.find(b, idx)
        if idx == -1: break
        print(f"0x{target:08x} literal found at 0x{BASE + idx:08x}")
        idx += 4

# Or maybe the start of that array? What is the start of the array around 0x11ecc000?
# Let's inspect the entire table around 0x11ecc900..0x11ecca80
print("\nInspecting table entries around 0x11ecc900..0x11ecca80:")
for addr in range(0x11ecc9a0, 0x11eccab0, 0x2c):
    off = addr - BASE
    w = struct.unpack("<11I", buf[off:off+44])
    print(f"0x{addr:08x}: vptr=0x{w[0]:08x} id=0x{w[6]:08x} flag=0x{w[7]:08x} parent=0x{w[8]:08x}")

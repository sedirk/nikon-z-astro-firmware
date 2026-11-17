from pathlib import Path
import struct

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()

# Find the start of the table around 0x11ecc000
# Look backwards from 0x11ecc900
for addr in range(0x11ecc900, 0x11ec8000, -0x2c):
    off = addr - BASE
    w0 = struct.unpack_from("<I", buf, off)[0]
    if not (0x10000000 <= w0 <= 0x12000000):
        print(f"Table might start near 0x{addr:08x} (first non-ROM word: 0x{w0:08x})")
        break

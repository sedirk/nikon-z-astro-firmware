from pathlib import Path
import struct

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()

for addr in range(0x11ecc8d0, 0x11eccab0, 0x10):
    off = addr - BASE
    w = struct.unpack_from("<4I", buf, off)
    print(f"0x{addr:08x}: " + " ".join(f"0x{x:08x}" for x in w))

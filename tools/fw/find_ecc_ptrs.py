from pathlib import Path
import struct

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()

# Search for any references to addresses in 0x11ecc000..0x11eccb00
print("Searching for pointers into 0x11ecc800..0x11ecca80:")
for off in range(0, len(buf)-4, 4):
    w = struct.unpack_from("<I", buf, off)[0]
    if 0x11ecc800 <= w <= 0x11ecca80:
        print(f"Pointer 0x{w:08x} at 0x{BASE + off:08x}")

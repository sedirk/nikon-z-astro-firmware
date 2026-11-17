from pathlib import Path
import struct

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()

addr = 0x106681b8
off = addr - BASE
print(f"Table at 0x{addr:08x}:")
for i in range(20):
    w1, w2 = struct.unpack_from("<II", buf, off + i*8)
    print(f"  entry {i:2d}: prop_val=0x{w1:08x} ({w1:4d}), data=0x{w2:08x} (0x{w2 & 0xffff:04x})")

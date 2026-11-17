from pathlib import Path
import struct

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()

target = 0xc1874740
b = struct.pack("<I", target)
idx = 0
found = []
while True:
    idx = buf.find(b, idx)
    if idx == -1: break
    found.append(f"0x{BASE + idx:08x}")
    idx += 4
print(f"0x{target:08x} found at: {found}")

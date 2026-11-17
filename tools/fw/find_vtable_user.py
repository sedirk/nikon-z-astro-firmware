from pathlib import Path
import struct

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()

# search for references to 0x106703bc (the sub-vtable where 0x104c4ca8 is at +0x10)
# vtable layout:
# 0x106703bc: vtable start for this interface?
# 0x106703cc: 0x104c4ca9 (offset +0x10 from 0x106703bc!)

for target in [0x106703bc, 0x106703ac, 0x106703a8]:
    pat = struct.pack("<I", target)
    idx = 0
    while True:
        idx = buf.find(pat, idx)
        if idx == -1: break
        print(f"vtable 0x{target:08x} referenced at 0x{BASE + idx:08x}")
        idx += 4

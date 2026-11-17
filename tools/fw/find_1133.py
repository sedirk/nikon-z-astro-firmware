from pathlib import Path
import struct

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()

# search for 0x1133 in menu descriptors
# menu descriptor: 32 bytes, first word is prop_id
target = struct.pack("<I", 0x1133)
idx = 0
while True:
    idx = buf.find(target, idx)
    if idx == -1: break
    addr = BASE + idx
    print(f"0x1133 found at 0x{addr:08x}")
    # check if this looks like a menu descriptor
    words = struct.unpack("<8I", buf[idx:idx+32])
    print(f"  words: " + " ".join(f"0x{w:08x}" for w in words))
    idx += 4

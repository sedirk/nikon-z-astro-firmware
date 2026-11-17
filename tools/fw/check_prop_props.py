from pathlib import Path
import struct

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()

# Let's inspect the menu descriptor for 0x1ba2 at 0x113a6390
# Descriptor format (32 bytes):
# +0x00: Property ID
# +0x04: Label string ID
# +0x08: Help string ID
# +0x0c: Label2 string ID
# +0x10: Default value
# +0x14: Flags / Type
# +0x18: Max value
# +0x1c: Step / Extra

print("Menu descriptor at 0x113a6390 (0x1ba2):")
words = struct.unpack("<8I", buf[0x113a6390 - BASE : 0x113a6390 - BASE + 32])
for i, w in enumerate(words):
    print(f"  +0x{i*4:02x}: 0x{w:08x} ({w})")

# Let's inspect where 0x1133 is defined in menu or property tables
print("\nSearching for 0x1133 in tables:")
# Search in bank default offsets
banks = [0x11144dc4, 0x111b4868, 0x111cbc48, 0x111e3028, 0x111fa408]
# check if 0x1133 or 0x1ba2 is in banks
for b in banks:
    # scan whole bank of ~4KB
    bank_data = buf[b - BASE : b - BASE + 0x2000]
    cnt_1ba2 = bank_data.count(struct.pack("<I", 0x1ba2))
    cnt_1133 = bank_data.count(struct.pack("<I", 0x1133))
    print(f"  Bank 0x{b:08x}: count(0x1ba2)={cnt_1ba2}, count(0x1133)={cnt_1133}")

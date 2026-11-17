from pathlib import Path
import struct

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()

off = 0x10409100 - BASE
val = struct.unpack_from("<I", buf, off)[0]
print(f"Base address of component table: 0x{val:08x}")

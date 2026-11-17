from pathlib import Path
import struct

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()

# Print strings around 0x11c28984
off = 0x11c28984 - BASE
print("Strings around 0x11c28984:")
print(buf[off-64:off+128])

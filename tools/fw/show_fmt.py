from pathlib import Path

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()

off = 0x104c4f00 - BASE
print(f"Bytes at 0x104c4f00: {buf[off:off+32]}")

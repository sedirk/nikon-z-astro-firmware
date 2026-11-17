import struct
from pathlib import Path

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()

targets = [
    (0x11bb0fd4, "MlLensDisconnectShutdownComplete"),
    (0x11bb1004, "MlLensConnectStartupComplete"),
    (0x11bb109c, "MlLensConnectComplete"),
    (0x11bb113c, "MlLensDisconnectComplete"),
    (0x11bb1518, "MlLensConnect"),
    (0x11bb1578, "MlLensDisconnect"),
]

for addr, name in targets:
    b = struct.pack("<I", addr)
    idx = 0
    found = []
    while True:
        idx = buf.find(b, idx)
        if idx == -1: break
        found.append(f"0x{BASE + idx:08x}")
        idx += 4
    print(f"{name} (0x{addr:08x}) referenced at: {found}")

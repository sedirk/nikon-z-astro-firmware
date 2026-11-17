import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
BIN_PATH = Path("firmware/decoded/eg1620_038000.bi")

def main():
    buf = BIN_PATH.read_bytes()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    sites = [0x10512b50, 0x10338eaa, 0x1012fcb4, 0x103d836a]
    for s in sites:
        print(f"=== Site at 0x{s:08x} ===")
        off = s - BASE - 16
        for i in md.disasm(buf[off:off+48], s - 16):
            mark = " <-- 0x1ba2" if i.address == s else ""
            print(f"0x{i.address:08x}: {i.mnemonic:8s} {i.op_str}{mark}")

if __name__ == "__main__":
    main()

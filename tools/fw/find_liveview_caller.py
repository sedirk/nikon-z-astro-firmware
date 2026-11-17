import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
BIN_PATH = Path("firmware/decoded/eg1620_038000.bi")

def main():
    buf = BIN_PATH.read_bytes()
    target = 0x10525a70
    print(f"Searching callers and pointers of 0x{target:08x}...")
    
    # 1. Pointers (target | 1)
    ptr_bytes = struct.pack("<I", target | 1)
    idx = 0
    while True:
        idx = buf.find(ptr_bytes, idx)
        if idx == -1: break
        print(f"Pointer found at 0x{BASE + idx:08x}")
        idx += 4

    # 2. BL calls
    for off in range(0, len(buf) - 4, 2):
        b0, b1 = buf[off], buf[off+1]
        if (b1 & 0xf8) == 0xf0:
            b2, b3 = buf[off+2], buf[off+3]
            if (b3 & 0xd0) == 0xd0:
                pc = BASE + off + 4
                s = (b1 >> 2) & 1
                imm10 = ((b1 & 3) << 8) | b0
                j1 = (b3 >> 5) & 1
                j2 = (b3 >> 3) & 1
                imm11 = ((b3 & 7) << 8) | b2
                i1 = ~(j1 ^ s) & 1
                i2 = ~(j2 ^ s) & 1
                offset = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
                if s: offset -= (1 << 25)
                if pc + offset == target:
                    print(f"BL caller found at 0x{BASE + off:08x}")

if __name__ == "__main__":
    main()

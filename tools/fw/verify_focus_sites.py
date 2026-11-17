import struct
import sys
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
BIN_PATH = Path("firmware/decoded/eg1620_038000.bi")

def main():
    buf = BIN_PATH.read_bytes()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    def disasm_range(start_addr, end_addr):
        off = start_addr - BASE
        length = end_addr - start_addr
        code = buf[off : off + length]
        lines = []
        for i in md.disasm(code, start_addr):
            lines.append(f"0x{i.address:08x}: {i.mnemonic:8s} {i.op_str}")
        return lines

    print("=== 1. Cold boot restore (0x104c4e10..0x104c4e60) ===")
    lines1 = disasm_range(0x104c4e10, 0x104c4e70)
    for l in lines1:
        print(l)

    print("\n=== 2. StartCameraLiveView (0x10525aa0..0x10525ae0) ===")
    lines2 = disasm_range(0x10525aa0, 0x10525ae0)
    for l in lines2:
        print(l)

    print("\n=== 3. Menu descriptor at 0x113a6390 ===")
    off_menu = 0x113a6390 - BASE
    words = struct.unpack("<8I", buf[off_menu : off_menu + 32])
    for idx, w in enumerate(words):
        print(f"  +0x{idx*4:02x} (0x{0x113a6390 + idx*4:08x}): 0x{w:08x}")

    print("\n=== 4. Bank 0x1ba2 offsets (+0xb70) ===")
    banks = [
        ("Factory", 0x11144dc4),
        ("Bank 0", 0x111b4868),
        ("Bank 1", 0x111cbc48),
        ("Bank 2", 0x111e3028),
        ("Bank 3", 0x111fa408),
    ]
    for name, b in banks:
        off = b - BASE + 0xb70
        val = struct.unpack("<I", buf[off : off + 4])[0]
        print(f"  {name:8s} @ 0x{b+0xb70:08x}: {val}")

if __name__ == "__main__":
    main()

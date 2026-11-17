import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM

BASE = 0x10000000
BIN_PATH = Path("firmware/decoded/eg1620_038000.bi")

def main():
    buf = BIN_PATH.read_bytes()
    
    # 1. Search for 0x1ba2 in 16-bit little endian: b'\xa2\x1b'
    # In Thumb-2, movw rX, #0x1ba2 is:
    # 0xf241 0xbX 0xa2 (where X is dest register)
    # Let's search for any bytes containing 0xa2, 0x1b or pattern
    print("Searching for 0x1ba2...")
    matches_literal = []
    for off in range(0, len(buf) - 4, 2):
        val16 = struct.unpack_from("<H", buf, off)[0]
        if val16 == 0x1ba2:
            matches_literal.append(BASE + off)
            
    print(f"Found {len(matches_literal)} literal 16-bit 0x1ba2 occurrences:")
    for a in matches_literal:
        print(f"  0x{a:08x}")

    # Search for thumb-2 movw: f2 4x yz a2
    # movw r0, #0x1ba2 -> f241 30a2
    # movw r1, #0x1ba2 -> f241 31a2
    # movw r2, #0x1ba2 -> f241 32a2
    print("Searching for movw rX, #0x1ba2 ...")
    for r in range(16):
        # movw Rd, #imm16: 1111 0 i 10 0 1 0 0 imm4 0 imm3 Rd imm8
        # for 0x1ba2: imm16 = 0001 1011 1010 0010
        # i = 0, imm4 = 0001 (1), imm3 = 011 (3), imm8 = 1010 0010 (a2)
        # first halfword: 1111 0010 0100 0001 = 0xf241
        # second halfword: 0 011 Rd a2 = (0x30 | r) << 8 | 0xa2
        pat = bytes([0x41, 0xf2, 0xa2, (0x30 | r)])
        idx = 0
        while True:
            idx = buf.find(pat, idx)
            if idx == -1:
                break
            print(f"  movw r{r}, #0x1ba2 found at 0x{BASE + idx:08x}")
            idx += 2

if __name__ == "__main__":
    main()

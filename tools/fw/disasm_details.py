import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
BIN_PATH = Path("firmware/decoded/eg1620_038000.bi")

def main():
    buf = BIN_PATH.read_bytes()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    def disasm_range(start_addr, end_addr):
        off = start_addr - BASE
        code = buf[off : off + (end_addr - start_addr)]
        for i in md.disasm(code, start_addr):
            print(f"0x{i.address:08x}: {i.mnemonic:8s} {i.op_str}")

    print("=== StartCameraLiveView exit ===")
    disasm_range(0x10525ad0, 0x10525af4)

    print("\n=== 0x104c4ca8 prologue and body ===")
    disasm_range(0x104c4ca8, 0x104c4d00)

    print("\n=== 0x104c4e1a to 0x104c4e8c ===")
    disasm_range(0x104c4e1a, 0x104c4ea0)

if __name__ == "__main__":
    main()

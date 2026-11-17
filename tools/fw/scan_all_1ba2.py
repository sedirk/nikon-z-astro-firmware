from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

print("Scanning for all instructions loading or referencing 0x1ba2...")
# 0x1ba2 = 7074
for off in range(0, len(buf) - 4, 2):
    # check 4-byte Thumb instructions
    code = buf[off:off+4]
    for ins in md.disasm(code, BASE + off):
        if "1ba2" in ins.op_str.lower() or "7074" in ins.op_str:
            print(f"0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")

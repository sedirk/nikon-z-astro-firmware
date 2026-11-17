from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

start_addr = 0x1025e800
end_addr = 0x1025ea50
off = start_addr - BASE
code = buf[off : off + (end_addr - start_addr)]

print(f"Disassembly of Resume dispatcher (0x{start_addr:08x}..0x{end_addr:08x}):")
for ins in md.disasm(code, start_addr):
    mark = " <--" if ins.address == 0x1025e894 else ""
    print(f"0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{mark}")

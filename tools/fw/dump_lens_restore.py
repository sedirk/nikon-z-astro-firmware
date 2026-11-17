from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

start_addr = 0x104c4ca8
end_addr = 0x104c4f30
off = start_addr - BASE
code = buf[off : off + (end_addr - start_addr)]

print(f"Full dump of 0x{start_addr:08x}..0x{end_addr:08x}:")
lines = []
for ins in md.disasm(code, start_addr):
    lines.append(f"0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")

Path("analysis/lens_restore_func.txt").write_text("\n".join(lines), encoding="utf-8")
print(f"Dumped {len(lines)} instructions to analysis/lens_restore_func.txt")

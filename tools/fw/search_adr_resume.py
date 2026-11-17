from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

target = 0x1026afdc
target_off = target - BASE

print(f"Searching for instructions referencing 0x{target:08x} within +/- 4KB...")
# Search in [target_off - 4096, target_off + 4096]
start_search = max(0, target_off - 4096)
end_search = min(len(buf), target_off + 4096)

for off in range(start_search, end_search, 2):
    code = buf[off:off+4]
    for ins in md.disasm(code, BASE + off):
        if ins.mnemonic.startswith("adr") or ins.mnemonic.startswith("ldr"):
            # check target address
            if hex(target) in ins.op_str.lower() or str(target) in ins.op_str:
                print(f"Match: 0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")

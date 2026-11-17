from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

target = 0x1026afdc
target_off = target - BASE

print(f"Finding adr to 0x{target:08x}...")
# 16-bit ADR: 1010 0 rrr imm8 (adds imm8 * 4 to PC)
# Range is PC + 0..1020
for off in range(max(0, target_off - 1024), target_off, 2):
    b0, b1 = buf[off], buf[off+1]
    if (b1 & 0xf8) == 0xa0: # 16-bit ADR Rd, [PC, #imm8]
        rd = (b1 & 7)
        imm8 = b0
        addr = BASE + off
        pc = (addr + 4) & ~3
        dest = pc + (imm8 * 4)
        if dest == target:
            print(f"16-bit ADR at 0x{addr:08x}: adr r{rd}, 0x{dest:08x}")

# 32-bit ADR: 1111 0 i 10 0 0 0 0 1111 0 imm3 Rd imm8
for off in range(max(0, target_off - 4096), target_off + 4096, 2):
    b0, b1 = buf[off], buf[off+1]
    if (b1 & 0xfb) == 0xf2 and b0 == 0x0f: # ADR (subtract) or ADR (add)
        addr = BASE + off
        # disassemble with capstone
        for ins in md.disasm(buf[off:off+4], addr):
            if ins.mnemonic.startswith("adr"):
                print(f"32-bit ADR at 0x{addr:08x}: {ins.mnemonic} {ins.op_str}")

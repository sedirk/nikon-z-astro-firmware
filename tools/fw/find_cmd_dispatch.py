import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

# Let's search for references to 0x2b (MlLensConnectStartupComplete)
# and 0x2c (MlLensConnectComplete)
# and 0x2e (MlLensDisconnectShutdownComplete)
# In Thumb, movs rX, #0x2b / #0x2c / #0x2e
# movs r0, #0x2b -> 0x202b
# movs r1, #0x2b -> 0x212b
# movs r2, #0x2b -> 0x222b
# movs r3, #0x2b -> 0x232b

for cmd_id, name in [
    (0x2b, "MlLensConnectStartupComplete"),
    (0x2c, "MlLensConnectComplete"),
    (0x2d, "MlLensDisconnectComplete"),
    (0x2e, "MlLensDisconnectShutdownComplete"),
]:
    print(f"\n=== References for {name} (0x{cmd_id:02x}) ===")
    for r in range(4):
        # 16-bit movs rX, #imm: 0010 0 rrr imm8 -> (0x20 | r) << 8 | imm8
        pat = bytes([cmd_id, 0x20 | r])
        idx = 0
        while True:
            idx = buf.find(pat, idx)
            if idx == -1: break
            addr = BASE + idx
            # disasm surrounding instructions
            off = idx - 4
            code = buf[off:off+16]
            ins = list(md.disasm(code, addr - 4))
            ins_str = "; ".join(f"0x{i.address:08x}: {i.mnemonic} {i.op_str}" for i in ins)
            print(f"  r{r} at 0x{addr:08x} -> {ins_str}")
            idx += 2

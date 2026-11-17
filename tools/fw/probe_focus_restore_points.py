import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10000000
BIN_PATH = Path("firmware/decoded/eg1620_038000.bi")

def main():
    buf = BIN_PATH.read_bytes()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    def disasm(addr, length):
        off = addr - BASE
        code = buf[off : off + length]
        insns = []
        for i in md.disasm(code, addr):
            insns.append(f"0x{i.address:08x}: {i.mnemonic:8s} {i.op_str}")
        return insns

    # 1. 0x104c4e00..0x104c4e70
    cold_insns = disasm(0x104c4e00, 0x80)
    
    # 2. 0x10525ab0..0x10525af0
    liveview_insns = disasm(0x10525aa0, 0x50)

    # 3. 0x113a6390 menu descriptor
    off_menu = 0x113a6390 - BASE
    menu_words = [f"0x{w:08x}" for w in struct.unpack("<8I", buf[off_menu : off_menu + 32])]

    # 4. Bank default offsets
    banks = [0x11144dc4, 0x111b4868, 0x111cbc48, 0x111e3028, 0x111fa408]
    bank_vals = []
    for b in banks:
        off = b - BASE + 0xb70
        val = struct.unpack("<I", buf[off : off + 4])[0]
        bank_vals.append((hex(b), hex(off + BASE), val))

    # Save details to analysis file
    out = {
        "cold_insns": cold_insns,
        "liveview_insns": liveview_insns,
        "menu_words": menu_words,
        "bank_vals": bank_vals,
    }
    import json
    Path("analysis/focus_points.json").parent.mkdir(parents=True, exist_ok=True)
    Path("analysis/focus_points.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"Analysis saved successfully. Menu words: {menu_words[:4]}, Bank vals: {bank_vals}")

if __name__ == "__main__":
    main()

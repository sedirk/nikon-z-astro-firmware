"""Independent byte, protected-region, and branch-target audit for Modified10."""
from pathlib import Path
import argparse, binascii, json, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
from probe_raw_candidates import ROOT, BASE, sha

STOCK_SHA = "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c"
M9_SHA = "70ecc8d583b5207761fbad1b51411906900ba8fb82886dce0fe241595f7d182c"
M10_SHA = "85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4"
SIZE = 33502842

# Independently hardcoded expected edits (addr, stock_hex, m10_hex, in_m9)
EXPECTED_EDITS = [
    (0x1002d884, "00" * 68, "0f4900223c2341f82320013bfbd144f200028a620a65c1f8a020c1f8c82042f22002c2f22002c1f8f4202022a1f8f8200022c1f8fc20a1f8fa200120eff042be54379ac2", True),
    (0x100ae3a4, "0cf166f8", "0cf187f8", False),
    (0x100c2654, "00f065fa", "4ff00000", True),
    (0x100c267c, "00f045fa", "4ff00200", True),
    (0x100c2690, "90f81a18", "4ff00201", True),
    (0x100c28b2, "84f86200", "84f86290", False),
    (0x100c28c8, "84f86390", "84f86300", False),
    (0x100c2964, "90f85f02", "4ff00100", False),
    (0x1017d834, "01209ff787fe", "b0f626f8c046", True),
    (0x1019741a, "59b1", "0ee0", False),
    (0x10197868, "4e77", "4a77", False),
    (0x10197876, "4078", "0020", False),
]


def is_embedded_png_idat(stock: bytes, off: int) -> bool:
    png = stock.rfind(b"\x89PNG\r\n\x1a\n", 0, off)
    if png < 0 or off - png > 0x200000:
        return False
    cursor = png + 8
    while cursor + 12 <= len(stock):
        length = struct.unpack_from(">I", stock, cursor)[0]
        kind = stock[cursor + 4 : cursor + 8]
        if length >= 0x1000000 or cursor + 12 + length > len(stock):
            return False
        data = stock[cursor + 4 : cursor + 8 + length]
        if (binascii.crc32(data) & 0xFFFFFFFF) != struct.unpack_from(">I", stock, cursor + 8 + length)[0]:
            return False
        if cursor + 8 <= off < cursor + 8 + length:
            return kind == b"IDAT"
        cursor += length + 12
        if kind == b"IEND":
            break
    return False


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)

    stock = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()
    m9 = (ROOT / "outputs/Z6-C380-production-modified9-2026-11-12/01_TEST_MODIFIED9/EG162080.BIN").read_bytes()
    m10 = (ROOT / "analysis/modified10-preflash-2026-11-13/lab-build/modified10-candidate.bi").read_bytes()

    assert len(stock) == len(m9) == len(m10) == SIZE
    assert sha(stock) == STOCK_SHA and sha(m9) == M9_SHA and sha(m10) == M10_SHA
    assert all(binascii.crc_hqx(b, 0) == 0 for b in (stock, m9, m10))

    allowed_stock = set(range(SIZE - 2, SIZE))
    allowed_m9 = set(range(SIZE - 2, SIZE))
    for addr, old_h, new_h, in_m9 in EXPECTED_EDITS:
        old_b, new_b = bytes.fromhex(old_h), bytes.fromhex(new_h)
        off = addr - BASE
        n = len(old_b)
        assert stock[off : off + n] == old_b, f"Stock mismatch at {addr:#x}"
        assert m10[off : off + n] == new_b, f"M10 mismatch at {addr:#x}"
        assert m9[off : off + n] == (new_b if in_m9 else old_b), f"M9 mismatch at {addr:#x}"
        allowed_stock.update(range(off, off + n))
        if not in_m9:
            allowed_m9.update(range(off, off + n))

    diff_stock = [i for i, (x, y) in enumerate(zip(stock, m10)) if x != y]
    diff_m9 = [i for i, (x, y) in enumerate(zip(m9, m10)) if x != y]
    assert set(diff_stock).issubset(allowed_stock), "Unexpected byte modified vs Stock!"
    assert set(diff_m9).issubset(allowed_m9), "Unexpected byte modified vs Modified9!"
    assert len(diff_stock) == 95 and sum(i < SIZE - 2 for i in diff_stock) == 93
    assert len(diff_m9) == 14 and sum(i < SIZE - 2 for i in diff_m9) == 12

    protected = []
    for name, lo, hi in [
        ("startup_vectors_and_scatter", BASE, 0x1002d884),
        ("alignment_hole_remainder", 0x1002d8c8, 0x10035000),
        ("updater", 0x101b4000, 0x101ba000),
        ("fullsize_predicate_helpers", 0x101ba474, 0x101ba4ce),
        ("flash_veneers", 0x1014a674, 0x1014a6a4),
        ("resource_directory", 0x11f15000, 0x11f17000),
        ("id35_dispatch_and_selectors", 0x1011c2a0, 0x1011c820),
        ("id35_driver", 0x100cd64a, 0x100cda40),
        ("cal33_selector", 0x1011e23e, 0x1011e36a),
        ("frontend_upload", 0x1010b1c0, 0x1010b45e),
        ("static_start_wait_error", 0x10179d0c, 0x10179e00),
        ("irq_callback", 0x10178de8, 0x10178f38),
        ("lossless_encoder_wrapper", 0x100af648, 0x100af780),
    ]:
        c_s, c_9, c_10 = (b[lo - BASE : hi - BASE] for b in (stock, m9, m10))
        assert c_s == c_9 == c_10, f"Protected region {name} changed!"
        protected.append(dict(name=name, start=hex(lo), end=hex(hi), sha256=sha(c_s)))

    # Verify zero interior branch/pointer targets into modified instruction spans or helper hole in Stock
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    hole_lo, hole_hi = 0x1002d884, 0x1002d8c8
    interior_addrs = set(range(hole_lo, hole_hi))
    for addr, old_h, _, _ in EXPECTED_EDITS:
        if addr != hole_lo:
            n = len(bytes.fromhex(old_h))
            # Interior halfwords of 4-byte/6-byte replacement spans must not be external branch targets
            interior_addrs.update(range(addr + 2, addr + n, 2))

    external_thumb2_hits = []
    png_hits = []
    for off in range(0, SIZE - 4, 2):
        h1, h2 = struct.unpack_from("<HH", stock, off)
        if h1 & 0xF800 != 0xF000 or h2 & 0x9000 != 0x9000:
            continue
        s = (h1 >> 10) & 1
        j1 = (h2 >> 13) & 1
        j2 = (h2 >> 11) & 1
        delta = (s << 24) | ((1 ^ (j1 ^ s)) << 23) | ((1 ^ (j2 ^ s)) << 22) | ((h1 & 0x3FF) << 12) | ((h2 & 0x7FF) << 1)
        if s:
            delta -= 1 << 25
        pc = BASE + off
        target = pc + 4 + delta
        if target in interior_addrs:
            if is_embedded_png_idat(stock, off):
                png_hits.append(dict(pc=hex(pc), target=hex(target)))
            else:
                ins = next(md.disasm(stock[off : off + 4], pc, count=1), None)
                if ins and ins.mnemonic in ("bl", "b.w"):
                    external_thumb2_hits.append(dict(pc=hex(pc), target=hex(target), mnemonic=ins.mnemonic))

    assert external_thumb2_hits == [], f"Unexpected Thumb2 branch into interior/hole: {external_thumb2_hits}"

    # 0x10020000..0x1002d884 is 32-bit ARM startup code; scan it in ARM32 mode for branches into the helper hole
    md_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md_arm.detail = True
    arm32_hole_hits = []
    for pc in range(BASE, hole_lo, 4):
        ins = next(md_arm.disasm(stock[pc - BASE : pc - BASE + 4], pc, count=1), None)
        if ins and ins.mnemonic.startswith("b"):
            for op in ins.operands:
                if op.type == ARM_OP_IMM and hole_lo <= op.imm < hole_hi:
                    arm32_hole_hits.append(dict(pc=hex(pc), target=hex(op.imm), ins=f"{ins.mnemonic} {ins.op_str}"))
    assert arm32_hole_hits == [], f"Unexpected ARM32 branch into helper hole: {arm32_hole_hits}"

    # Scan Thumb short branches around all Thumb code edit sites (>= 0x10030000)
    short_branch_hits = []
    for addr, old_h, _, _ in EXPECTED_EDITS:
        if addr < 0x10030000:
            continue
        span_end = addr + len(bytes.fromhex(old_h))
        lo_scan = max(0x10030000, addr - 2052)
        hi_scan = min(BASE + SIZE - 2, span_end + 2052)
        for pc in range(lo_scan, hi_scan, 2):
            if addr <= pc < span_end:
                continue
            ins = next(md.disasm(stock[pc - BASE : pc - BASE + 2], pc, count=1), None)
            if ins and ins.size == 2 and ins.mnemonic.startswith("b"):
                for op in ins.operands:
                    if op.type == ARM_OP_IMM and op.imm in interior_addrs:
                        short_branch_hits.append(dict(pc=hex(pc), target=hex(op.imm), ins=f"{ins.mnemonic} {ins.op_str}"))
    assert short_branch_hits == [], f"Unexpected short branch into interior: {short_branch_hits}"

    aligned_ptr_hits = []
    for off in range(0, SIZE - 4, 4):
        v = struct.unpack_from("<I", stock, off)[0]
        if (v & ~1) in interior_addrs:
            aligned_ptr_hits.append(dict(address=hex(BASE + off), value=hex(v)))
    assert aligned_ptr_hits == [], f"Unexpected aligned pointer into interior/hole: {aligned_ptr_hits}"

    # Verify static builder 0x1017d7b6..0x1017d83e preserves all 15 initial BLs + final hook -> 0x1002d884 -> 0x1011d548
    m10_builder = list(md.disasm(m10[0x1017d7b6 - BASE : 0x1017d83e - BASE], 0x1017d7b6))
    stock_builder = list(md.disasm(stock[0x1017d7b6 - BASE : 0x1017d83e - BASE], 0x1017d7b6))
    m10_bls = [i.op_str for i in m10_builder if i.mnemonic == "bl"]
    stock_bls = [i.op_str for i in stock_builder if i.mnemonic == "bl"]
    assert len(m10_bls) == len(stock_bls) == 16
    assert m10_bls[:-1] == stock_bls[:-1] and m10_bls[-1] == "#0x1002d884"
    for i in m10_builder:
        for op in i.operands:
            if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                lit_addr = ((i.address + 4) & ~3) + op.mem.disp
                assert lit_addr == 0x1017dbb8
                assert struct.unpack_from("<I", m10, lit_addr - BASE)[0] == 0xc18fa844

    res = dict(
        ok=True,
        sha256=M10_SHA,
        parent_modified9_sha256=M9_SHA,
        stock_sha256=STOCK_SHA,
        bytes=SIZE,
        changed_code_bytes_vs_stock=93,
        changed_total_bytes_vs_stock=95,
        changed_code_bytes_vs_modified9=12,
        changed_total_bytes_vs_modified9=14,
        protected_regions_verified=len(protected),
        protected=protected,
        external_thumb2_interior_hits=external_thumb2_hits,
        png_idat_false_positives_filtered=png_hits,
        short_branch_interior_hits=short_branch_hits,
        aligned_pointer_interior_hits=aligned_ptr_hits,
    )
    (args.output / "result.json").write_text(json.dumps(res, indent=2), encoding="utf8")
    (args.output / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps({
        "ok": True,
        "protected_regions": len(protected),
        "changed_vs_stock": 95,
        "changed_vs_m9": 14,
        "interior_hits": 0,
    }))


if __name__ == "__main__":
    main()

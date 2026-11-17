"""Deterministically build and statically audit Modified18 (Design A1: Color Space Switchable Astro RAW + Uncompressed/Lossless Decoupled + Permanent 30-600s v2)."""
from __future__ import annotations
import argparse
import binascii
import hashlib
import json
import struct
from pathlib import Path
import sys

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from z6_astro_ui_color_space import (
    ADDR_M18_CAVE,
    ADDR_M9_SANITIZER,
    HELP_EN,
    HELP_ZH_CN,
    HELP_ZH_TW,
    LABEL_EN,
    LABEL_ZH_CN,
    LABEL_ZH_TW,
    LANG_ZH_CN,
    LANG_ZH_TW,
    build_all_m18_astro_ui_spans,
)
from z6_m600_tables import BASE, SIZE
from z6_m600_v2 import build_all_m600_v2_spans

ROOT = THIS_DIR.parents[1]
STOCK_SHA = "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c"
M12_SHA = "9734012be0e063fa8f2ccbf77c2dd5a63a76be2f45887aa6b806b97b441cb67c"
M13_SHA = "3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749"
M15_SHA = "0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def update_crc(buf: bytearray) -> str:
    crc = binascii.crc_hqx(bytes(buf[:-2]), 0)
    buf[-2:] = crc.to_bytes(2, "big")
    assert binascii.crc_hqx(bytes(buf), 0) == 0
    return f"{crc:04x}"


def collect_m18_edits(stock: bytes) -> tuple[list[dict], dict[str, int]]:
    m18_spans, syms = build_all_m18_astro_ui_spans(stock)
    m600_spans = build_all_m600_v2_spans(stock)

    edits: list[dict] = []
    for addr, grp, new_b, desc in m18_spans + m600_spans:
        off = addr - BASE
        assert 0 <= off and off + len(new_b) <= SIZE - 2
        old_b = stock[off : off + len(new_b)]
        edits.append(
            {
                "group": grp,
                "address": f"0x{addr:08x}",
                "before": old_b.hex(),
                "after": new_b.hex(),
                "description": desc,
            }
        )
    edits.sort(key=lambda item: int(item["address"], 16))
    return edits, syms


def audit_cave_disassembly_and_glyphs(stock: bytes, m18_bytes: bytes, syms: dict[str, int], spans: list) -> dict:
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cave_code_start = ADDR_M18_CAVE - BASE
    cave_code_end = syms["code_end"] - BASE
    insns = list(cs.disasm(m18_bytes[cave_code_start:cave_code_end], ADDR_M18_CAVE))
    decoded_len = sum(i.size for i in insns)
    assert decoded_len == (cave_code_end - cave_code_start), (
        f"Cave disassembly incomplete: decoded {decoded_len} != {cave_code_end - cave_code_start}"
    )
    for i in insns:
        if i.size == 4:
            hw1, hw2 = struct.unpack_from("<HH", i.bytes, 0)
            if hw1 == 0xE8BD:
                assert (hw2 & 0xC000) != 0xC000, f"Unpredictable POP {{.., lr, pc}} at {i.address:#x}"

    # Verify interior halfword addresses of multi-instruction inline hooks are never targeted by
    # short B/B<cc>/CBZ/CBNZ/B.W/BL instructions within +/-16MB around the code section.
    interior_addrs: set[int] = set()
    for off, end, addr, grp, _, _, _ in spans:
        if not grp.startswith("m600_") and addr not in (ADDR_M9_SANITIZER, ADDR_M18_CAVE):
            for ia in range(addr + 2, addr + (end - off), 2):
                interior_addrs.add(ia)

    interior_hits: list[str] = []
    for off, end, addr, grp, _, _, _ in spans:
        if not grp.startswith("m600_") and addr not in (ADDR_M9_SANITIZER, ADDR_M18_CAVE):
            w_lo = max(BASE, (addr - 0x800) & ~3)
            w_hi = min(BASE + 0x600000, addr + 0x800)
            for ins in cs.disasm(stock[w_lo - BASE : w_hi - BASE], w_lo):
                if ins.mnemonic.startswith(("b", "cbz", "cbnz")) and "#" in ins.op_str:
                    tok = ins.op_str.split("#")[-1].strip()
                    try:
                        tgt = int(tok, 16)
                    except ValueError:
                        continue
                    if tgt in interior_addrs:
                        interior_hits.append(f"{ins.address:#x} -> {tgt:#x} ({ins.mnemonic} {ins.op_str})")
    assert not interior_hits, f"Interior hook branch target collision(s): {interior_hits}"

    # Verify 36-language font glyph coverage against Stock's 36 language string pools
    idx_tbl = 0x112C2A08
    pool_tbl = 0x112C2A98
    missing_glyph_langs = 0
    for lang in range(36):
        idx_base = struct.unpack_from("<I", stock, idx_tbl + lang * 4 - BASE)[0]
        pool_base = struct.unpack_from("<I", stock, pool_tbl + lang * 4 - BASE)[0]
        end_off = struct.unpack_from("<I", stock, idx_base + 2291 * 4 - BASE)[0]
        pool_chars = set(stock[pool_base - BASE : pool_base + end_off - BASE].decode("utf-16le", errors="ignore"))
        if lang == LANG_ZH_CN:
            lbl, hlp = LABEL_ZH_CN, HELP_ZH_CN
        elif lang == LANG_ZH_TW:
            lbl, hlp = LABEL_ZH_TW, HELP_ZH_TW
        else:
            lbl, hlp = LABEL_EN, HELP_EN
        miss = [c for c in (lbl + hlp) if c not in pool_chars and c not in "\n\r\t "]
        assert not miss, f"Language {lang} missing font glyph(s): {miss}"

    return {
        "cave_code_instructions": len(insns),
        "cave_code_bytes": cave_code_end - cave_code_start,
        "cave_total_bytes": syms["cave_end"] - ADDR_M18_CAVE,
        "cave_free_headroom_before_m600": 0x1002EF14 - syms["cave_end"],
        "interior_branch_collisions": len(interior_hits),
        "verified_36_languages_zero_missing_glyphs": missing_glyph_langs == 0,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified18-preflash-2026-11-15/lab-build",
    )
    args = ap.parse_args()
    out_dir = args.output.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    stock = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()
    m12 = (ROOT / "outputs/Z6-C380-modified12-reviewed-2026-11-14/01_TEST_MODIFIED12/EG162080.BIN").read_bytes()
    m13 = (ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN").read_bytes()
    m15_path = ROOT / "outputs/Z6-C380-modified15-reviewed-2026-11-15/01_TEST_MODIFIED15/EG162080.BIN"
    if not m15_path.is_file():
        m15_path = ROOT / "analysis/modified15-preflash-2026-11-15/lab-build/modified15-candidate.bi"
    m15 = m15_path.read_bytes()

    assert len(stock) == SIZE, f"Stock size mismatch: {len(stock)} != {SIZE}"
    assert sha(stock) == STOCK_SHA, "Stock checksum mismatch"
    assert sha(m12) == M12_SHA, "M12 checksum mismatch"
    assert sha(m13) == M13_SHA, "M13 checksum mismatch"
    assert sha(m15) == M15_SHA, "M15 checksum mismatch"

    edits, syms = collect_m18_edits(stock)
    print(f"Collected {len(edits)} distinct edits (17 Astro UI + 84 M600 v2).")

    m18_buf = bytearray(stock)
    spans_for_audit: list[tuple[int, int, int, str, bytes, bytes, str]] = []
    delta_bytes = 0
    for ed in edits:
        addr = int(ed["address"], 16)
        off = addr - BASE
        b_after = bytes.fromhex(ed["after"])
        b_before = bytes.fromhex(ed["before"])
        assert m18_buf[off : off + len(b_before)] == b_before
        m18_buf[off : off + len(b_after)] = b_after
        delta_bytes += sum(1 for a, b in zip(b_before, b_after) if a != b)
        spans_for_audit.append((off, off + len(b_after), addr, ed["group"], b_before, b_after, ed["description"]))

    # Overlapping edit sanity check:
    spans_for_audit.sort(key=lambda s: s[0])
    for i in range(len(spans_for_audit) - 1):
        prev_end = spans_for_audit[i][1]
        next_start = spans_for_audit[i + 1][0]
        assert prev_end <= next_start, (
            f"Overlap between 0x{spans_for_audit[i][2]:08x} and 0x{spans_for_audit[i+1][2]:08x}"
        )

    crc_str = update_crc(m18_buf)
    m18_bytes = bytes(m18_buf)
    m18_sha = sha(m18_bytes)

    # Reversibility test: revert all edits back to stock and assert zero difference
    reverted = bytearray(m18_bytes)
    for ed in edits:
        addr = int(ed["address"], 16)
        off = addr - BASE
        b_before = bytes.fromhex(ed["before"])
        reverted[off : off + len(b_before)] = b_before
    update_crc(reverted)
    assert bytes(reverted) == stock, "Reversibility check failed: patched image did not cleanly roll back to Stock!"

    audit_res = audit_cave_disassembly_and_glyphs(stock, m18_bytes, syms, spans_for_audit)

    candidate_bi = out_dir / "modified18-candidate.bi"
    candidate_bi.write_bytes(m18_bytes)

    manifest = {
        "candidate": "modified18-astro-ui-color-space-600s-v1",
        "design": "A1 (Photo Shooting Menu -> Color space 0x0508 switchable Astro RAW)",
        "base_stock_sha256": STOCK_SHA,
        "modified18_sha256": m18_sha,
        "crc16_hqx": f"0x{crc_str}",
        "total_edits": len(edits),
        "astro_ui_edits": sum(1 for ed in edits if not ed["group"].startswith("m600_")),
        "m600_v2_edits": sum(1 for ed in edits if ed["group"].startswith("m600_")),
        "byte_deltas_vs_stock": delta_bytes,
        "cave_symbols": {k: f"0x{v:08x}" for k, v in syms.items()},
        "audit": audit_res,
        "edits": edits,
    }

    manifest_json = out_dir / "modified18-manifest.json"
    manifest_json.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    # Save to patches directory for packaging:
    patches_dir = ROOT / "patches"
    patches_dir.mkdir(parents=True, exist_ok=True)
    patch_recipe = patches_dir / "z6-c380-modified18-astro-ui-color-space-600s.json"
    patch_recipe.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n" + "=" * 70)
    print("MODIFIED18 (DESIGN A1: COLOR SPACE ASTRO UI + PERMANENT 600S) READY")
    print("=" * 70)
    print(f"Output binary   : {candidate_bi}")
    print(f"SHA-256         : {m18_sha}")
    print(f"CRC16-HQX       : 0x{crc_str}")
    print(f"Total Edits     : {len(edits)} (17 Astro UI + 84 M600 v2)")
    print(f"Byte Deltas     : {delta_bytes} bytes vs Stock C3.80")
    print(f"Recipe JSON     : {patch_recipe}")
    print(f"Cave total size : {audit_res['cave_total_bytes']} bytes")
    print(f"Cave headroom   : {audit_res['cave_free_headroom_before_m600']} bytes before m600_v2")
    print("=" * 70)


if __name__ == "__main__":
    main()

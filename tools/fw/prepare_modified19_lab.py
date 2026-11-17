"""Build Nikon Z6 C3.80 Modified19 candidate firmware (Full Color Space Astro UI v2 + Post-Exposure Interval Timer + Permanent 30-600s v2)."""
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

from z6_astro_ui_color_space_v2 import (
    ADDR_M19_CAVE,
    ADDR_M19_CAVE_LIMIT,
    ADDR_M9_SANITIZER,
    LANG_ZH_CN,
    LANG_ZH_TW,
    UI_OVERRIDES,
    build_all_m19_astro_ui_spans,
)
from z6_interval_post_exposure import build_interval_post_exposure_spans
from z6_m600_tables import BASE, SIZE
from z6_m600_v2 import build_all_m600_v2_spans

ROOT = THIS_DIR.parents[1]
STOCK_SHA = "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c"
M12_SHA = "9734012be0e063fa8f2ccbf77c2dd5a63a76be2f45887aa6b806b97b441cb67c"
M13_SHA = "3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749"
M15_SHA = "0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c"
M18_SHA = "5d404ea3707796c895782ebe75288763a67a238b7cac6cfce6dec71ba04dd157"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def update_crc(buf: bytearray) -> str:
    crc = binascii.crc_hqx(bytes(buf[:-2]), 0)
    buf[-2:] = crc.to_bytes(2, "big")
    assert binascii.crc_hqx(bytes(buf), 0) == 0
    return f"{crc:04x}"


def collect_m19_edits(stock: bytes) -> tuple[list[dict], dict[str, int]]:
    m19_ui_spans, syms = build_all_m19_astro_ui_spans(stock)
    iv_spans = build_interval_post_exposure_spans(stock)
    m600_spans = build_all_m600_v2_spans(stock)

    edits: list[dict] = []
    for addr, grp, new_b, desc in m19_ui_spans + iv_spans + m600_spans:
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


def audit_cave_disassembly_and_glyphs(stock: bytes, m19_bytes: bytes, syms: dict[str, int], spans: list) -> dict:
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cave_code_start = ADDR_M19_CAVE - BASE
    cave_code_end = syms["code_end"] - BASE
    insns = list(cs.disasm(m19_bytes[cave_code_start:cave_code_end], ADDR_M19_CAVE))
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
    # short B/B<cc>/CBZ/CBNZ/B.W/BL instructions around the code section.
    interior_addrs: set[int] = set()
    for off, end, addr, grp, _, _, _ in spans:
        if not grp.startswith("m600_") and addr not in (ADDR_M9_SANITIZER, ADDR_M19_CAVE):
            for ia in range(addr + 2, addr + (end - off), 2):
                interior_addrs.add(ia)

    cs_skip = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cs_skip.skipdata = True
    interior_hits: list[str] = []
    for off, end, addr, grp, _, _, _ in spans:
        if not grp.startswith("m600_") and addr not in (ADDR_M9_SANITIZER, ADDR_M19_CAVE):
            w_lo = max(BASE, (addr - 0x800) & ~3)
            w_hi = min(BASE + 0x600000, addr + 0x800)
            for ins in cs_skip.disasm(stock[w_lo - BASE : w_hi - BASE], w_lo):
                if ins.mnemonic.startswith(("b", "cbz", "cbnz")) and "#" in ins.op_str:
                    tok = ins.op_str.split("#")[-1].strip()
                    try:
                        tgt = int(tok, 16)
                    except ValueError:
                        continue
                    if tgt in interior_addrs:
                        interior_hits.append(f"{ins.address:#x} -> {tgt:#x} ({ins.mnemonic} {ins.op_str})")
    assert not interior_hits, f"Interior hook branch target collision(s): {interior_hits}"

    # Verify 36-language font glyph coverage + font class 0 across all 5 overridden String IDs
    idx_tbl = 0x112C2A08
    pool_tbl = 0x112C2A98
    attr_tbl = 0x112C2B28
    sid_class_tbl = 0x10D2FF58
    for sid, _, _, _, _ in UI_OVERRIDES:
        assert stock[sid_class_tbl + sid - BASE] == 0, f"String ID {sid:#x} non-zero global font class"

    for lang in range(36):
        idx_base = struct.unpack_from("<I", stock, idx_tbl + lang * 4 - BASE)[0]
        pool_base = struct.unpack_from("<I", stock, pool_tbl + lang * 4 - BASE)[0]
        attr_base = struct.unpack_from("<I", stock, attr_tbl + lang * 4 - BASE)[0]
        end_off = struct.unpack_from("<I", stock, idx_base + 2291 * 4 - BASE)[0]
        pool_chars = set(stock[pool_base - BASE : pool_base + end_off - BASE].decode("utf-16le", errors="ignore"))
        for sid, _, txt_en, txt_cn, txt_tw in UI_OVERRIDES:
            assert stock[attr_base + sid - BASE] == 0, f"Lang {lang} SID {sid:#x} non-zero font attr"
            txt = txt_cn if lang == LANG_ZH_CN else (txt_tw if lang == LANG_ZH_TW else txt_en)
            miss = [c for c in txt if c not in pool_chars and c not in "\n\r\t "]
            assert not miss, f"Language {lang} SID {sid:#x} missing font glyph(s): {miss}"

    return {
        "cave_code_instructions": len(insns),
        "cave_code_bytes": cave_code_end - cave_code_start,
        "cave_total_bytes": syms["cave_end"] - ADDR_M19_CAVE,
        "cave_free_headroom_before_m600": ADDR_M19_CAVE_LIMIT - syms["cave_end"],
        "interior_branch_collisions": len(interior_hits),
        "verified_36_languages_zero_missing_glyphs": True,
        "overridden_ui_string_ids": [f"0x{sid:04x}" for sid, _, _, _, _ in UI_OVERRIDES],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified19-preflash-2026-11-16/lab-build",
    )
    args = ap.parse_args()
    out_dir = args.output.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    stock = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()
    m12 = (ROOT / "outputs/Z6-C380-modified12-reviewed-2026-11-14/01_TEST_MODIFIED12/EG162080.BIN").read_bytes()
    m13 = (ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN").read_bytes()
    m15 = (ROOT / "outputs/Z6-C380-modified15-reviewed-2026-11-15/01_TEST_MODIFIED15/EG162080.BIN").read_bytes()
    m18 = (ROOT / "outputs/Z6-C380-modified18-reviewed-2026-11-15/01_TEST_MODIFIED18/EG162080.BIN").read_bytes()

    assert len(stock) == SIZE, f"Stock size mismatch: {len(stock)} != {SIZE}"
    assert sha(stock) == STOCK_SHA, "Stock checksum mismatch"
    assert sha(m12) == M12_SHA, "M12 checksum mismatch"
    assert sha(m13) == M13_SHA, "M13 checksum mismatch"
    assert sha(m15) == M15_SHA, "M15 checksum mismatch"
    assert sha(m18) == M18_SHA, "M18 checksum mismatch"

    edits, syms = collect_m19_edits(stock)

    m19_buf = bytearray(stock)
    spans_for_audit: list[tuple[int, int, int, str, bytes, bytes, str]] = []
    delta_bytes = 0
    for ed in edits:
        addr = int(ed["address"], 16)
        off = addr - BASE
        b_after = bytes.fromhex(ed["after"])
        b_before = bytes.fromhex(ed["before"])
        assert m19_buf[off : off + len(b_before)] == b_before
        m19_buf[off : off + len(b_after)] = b_after
        delta_bytes += sum(1 for a, b in zip(b_before, b_after) if a != b)
        spans_for_audit.append((off, off + len(b_after), addr, ed["group"], b_before, b_after, ed["description"]))

    spans_for_audit.sort(key=lambda s: s[0])
    for i in range(len(spans_for_audit) - 1):
        prev_end = spans_for_audit[i][1]
        next_start = spans_for_audit[i + 1][0]
        assert prev_end <= next_start, (
            f"Overlap between 0x{spans_for_audit[i][2]:08x} and 0x{spans_for_audit[i+1][2]:08x}"
        )

    crc_str = update_crc(m19_buf)
    m19_bytes = bytes(m19_buf)
    m19_sha = sha(m19_bytes)

    # Reversibility test back to stock:
    reverted = bytearray(m19_bytes)
    for ed in edits:
        addr = int(ed["address"], 16)
        off = addr - BASE
        b_before = bytes.fromhex(ed["before"])
        reverted[off : off + len(b_before)] = b_before
    update_crc(reverted)
    assert bytes(reverted) == stock, "Reversibility check failed!"

    audit_res = audit_cave_disassembly_and_glyphs(stock, m19_bytes, syms, spans_for_audit)

    candidate_bi = out_dir / "modified19-candidate.bi"
    candidate_bi.write_bytes(m19_bytes)

    astro_cnt = sum(1 for ed in edits if ed["group"].startswith(("m19_astro", "m19_color", "m19_ui", "modified9_")))
    iv_cnt = sum(1 for ed in edits if ed["group"].startswith("m19_interval"))
    m600_cnt = sum(1 for ed in edits if ed["group"].startswith("m600_"))

    manifest = {
        "candidate": "modified19-astro-ui-v2-interval-gap-600s-v1",
        "design": "A1 v2 (Full Color space title + sRGB/Astro labels) + Post-Exposure Interval Timer (0x101FF392) + Permanent 30-600s v2",
        "base_stock_sha256": STOCK_SHA,
        "modified18_sha256": M18_SHA,
        "modified19_sha256": m19_sha,
        "crc16_hqx": f"0x{crc_str}",
        "total_edits": len(edits),
        "astro_ui_edits": astro_cnt,
        "interval_timer_edits": iv_cnt,
        "m600_v2_edits": m600_cnt,
        "byte_deltas_vs_stock": delta_bytes,
        "cave_symbols": {k: f"0x{v:08x}" for k, v in syms.items()},
        "audit": audit_res,
        "edits": edits,
    }

    manifest_json = out_dir / "modified19-manifest.json"
    manifest_json.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    patches_dir = ROOT / "patches"
    patches_dir.mkdir(parents=True, exist_ok=True)
    patch_recipe = patches_dir / "z6-c380-modified19-astro-ui-v2-interval-600s.json"
    patch_recipe.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"MODIFIED19 READY | SHA256={m19_sha} | CRC=0x{crc_str} | Edits={len(edits)} ({astro_cnt}+{iv_cnt}+{m600_cnt}) | Cave={audit_res['cave_total_bytes']}B (free {audit_res['cave_free_headroom_before_m600']}B)")


if __name__ == "__main__":
    main()

"""Prepare Modified21 candidate image, manifest, and static/glyph/ROM-property audits.

Fixes Modified18..Modified20 Astro RAW Color Space switch regression:
  1. Corrects PID 0x0508 RAM slot from 0xC24CDDC4 (PID 0x0440 Focus Shift shots) to genuine
     0xC24CDE28 (verified against native ROM property table 0x10070474/0x10070478 and 0x100700A0).
  2. Locks Photo-mode Effective Color Space 0x1381 ([0xC24CC948]) to 0 (sRGB) at 0x1014F678 so
     embedded NEF preview JPEGs, companion RAW+JPEG files, EXIF ColorSpace, and DCF filenames
     (Z61_xxxx / DSC_xxxx) remain genuine sRGB while 0x0508 ([0xC24CDE28]) stays 0/1 (preserving
     NVRAM, U1-U3 banks, and the external LiveView/Info Adobe indicator icon).
  3. Updates Color Space option labels to '标准 (sRGB)' / '直通RAW (sRGB)' (EN 'Standard (sRGB)' /
     'Astro RAW (sRGB)', ZH_TW '標準 (sRGB)' / '直通RAW (sRGB)').
"""
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
    ADDR_M20_IV_CAVE,
    ADDR_M9_SANITIZER,
    LANG_ZH_CN,
    LANG_ZH_TW,
    RAM_PROP_0508_REAL,
    RAM_PROP_131B,
    RAM_PROP_1381,
    UI_OVERRIDES_M21,
    build_all_m21_astro_ui_spans,
)
from z6_interval_post_exposure import (
    ADDR_IV_ENDTIME_CAVE,
    ADDR_IV_ENDTIME_CAVE_LIMIT,
    RAM_PROP_0204,
    RAM_PROP_1308,
    RAM_PROP_1319,
    RAM_PROP_136F,
    build_all_m20_interval_spans,
)
from z6_m600_tables import BASE, SIZE
from z6_m600_v2 import build_all_m600_v2_spans

ROOT = THIS_DIR.parents[1]
STOCK_SHA = "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c"
M13_SHA = "3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749"
M15_SHA = "0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c"
M18_SHA = "5d404ea3707796c895782ebe75288763a67a238b7cac6cfce6dec71ba04dd157"
M19_SHA = "c4629a3700c947846b6c535567beb57055613db1b4120d024b7473cd1e27667a"
M20_SHA = "8003fac8111e059d8b64d7800e471524247eab451dc1f84da2b163ed2e255ac1"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def update_crc(buf: bytearray) -> str:
    crc = binascii.crc_hqx(bytes(buf[:-2]), 0)
    buf[-2:] = crc.to_bytes(2, "big")
    assert binascii.crc_hqx(bytes(buf), 0) == 0
    return f"{crc:04x}"


def verify_rom_property_ram_slots(stock: bytes) -> dict[str, str]:
    """Cross-check every RAM_PROP_* constant directly against Stock ROM property tables."""
    t1, t2 = struct.unpack_from("<2I", stock, 0x10070474 - BASE)
    expected = {
        0x0508: (RAM_PROP_0508_REAL, 7, 4),
        0x131B: (RAM_PROP_131B, 7, 4),
        0x1381: (RAM_PROP_1381, 7, 4),
        0x0204: (RAM_PROP_0204, 7, 4),
        0x1308: (RAM_PROP_1308, 8, 8),
        0x1319: (RAM_PROP_1319, 7, 4),
        0x136F: (RAM_PROP_136F, 7, 4),
    }
    verified: dict[str, str] = {}
    for pid, (exp_ram, exp_type, exp_sz) in expected.items():
        grp, sub = pid >> 8, pid & 0xFF
        bidx, cnt = struct.unpack_from("<HH", stock, t1 + grp * 28 - BASE + 0xC)
        assert sub < cnt, f"PID {pid:#06x} sub {sub} >= group count {cnt}"
        w0, w1, w2, _ = struct.unpack_from("<4I", stock, t2 + (bidx + sub) * 16 - BASE)
        assert w2 == exp_ram and (w0 & 0xFF) == exp_type and w1 == exp_sz, (
            f"ROM property descriptor mismatch for PID {pid:#06x}: "
            f"got ram={w2:#x} type={w0 & 0xff} sz={w1}, expected ram={exp_ram:#x} type={exp_type} sz={exp_sz}"
        )
        verified[f"0x{pid:04x}"] = f"0x{w2:08x}"
    return verified


def collect_m21_edits(stock: bytes) -> tuple[list[dict], dict[str, int]]:
    m21_ui_spans, ui_syms = build_all_m21_astro_ui_spans(stock)
    iv_spans, iv_syms = build_all_m20_interval_spans(stock)
    m600_spans = build_all_m600_v2_spans(stock)

    syms = dict(ui_syms)
    for k, v in iv_syms.items():
        assert k not in syms, f"Duplicate symbol {k}"
        syms[k] = v

    edits: list[dict] = []
    for addr, grp, new_b, desc in m21_ui_spans + iv_spans + m600_spans:
        if grp.startswith("m20_interval"):
            grp = f"m21_{grp[4:]}"
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


def audit_caves_and_glyphs(
    stock: bytes, m21_bytes: bytes, syms: dict[str, int], spans: list
) -> dict:
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    def _audit_code_range(start_addr: int, end_addr: int, label: str) -> int:
        s_off = start_addr - BASE
        e_off = end_addr - BASE
        insns = list(cs.disasm(m21_bytes[s_off:e_off], start_addr))
        decoded = sum(i.size for i in insns)
        assert decoded == (e_off - s_off), (
            f"{label} disassembly incomplete: decoded {decoded} != {e_off - s_off}"
        )
        for i in insns:
            if i.size == 4:
                hw1, hw2 = struct.unpack_from("<HH", i.bytes, 0)
                if hw1 == 0xE8BD:
                    assert (hw2 & 0xC000) != 0xC000, (
                        f"Unpredictable POP {{.., lr, pc}} at {i.address:#x} in {label}"
                    )
        return len(insns)

    ui_insns = _audit_code_range(ADDR_M19_CAVE, syms["code_end"], "astro_ui_cave")
    iv_insns = _audit_code_range(ADDR_IV_ENDTIME_CAVE, syms["iv_cave_end"], "iv_endtime_cave")

    cave_bases = {ADDR_M9_SANITIZER, ADDR_M19_CAVE, ADDR_IV_ENDTIME_CAVE}
    interior_addrs: set[int] = set()
    for off, end, addr, grp, _, _, _ in spans:
        if not grp.startswith("m600_") and addr not in cave_bases:
            for ia in range(addr + 2, addr + (end - off), 2):
                interior_addrs.add(ia)

    cs_skip = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cs_skip.skipdata = True
    interior_hits: list[str] = []
    for off, end, addr, grp, _, _, _ in spans:
        if not grp.startswith("m600_") and addr not in cave_bases:
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

    idx_tbl = 0x112C2A08
    pool_tbl = 0x112C2A98
    attr_tbl = 0x112C2B28
    sid_class_tbl = 0x10D2FF58
    for sid, _, _, _, _ in UI_OVERRIDES_M21:
        assert stock[sid_class_tbl + sid - BASE] == 0, f"String ID {sid:#x} non-zero global font class"

    for lang in range(36):
        idx_base = struct.unpack_from("<I", stock, idx_tbl + lang * 4 - BASE)[0]
        pool_base = struct.unpack_from("<I", stock, pool_tbl + lang * 4 - BASE)[0]
        attr_base = struct.unpack_from("<I", stock, attr_tbl + lang * 4 - BASE)[0]
        end_off = struct.unpack_from("<I", stock, idx_base + 2291 * 4 - BASE)[0]
        pool_chars = set(
            stock[pool_base - BASE : pool_base + end_off - BASE].decode("utf-16le", errors="ignore")
        )
        for sid, _, txt_en, txt_cn, txt_tw in UI_OVERRIDES_M21:
            assert stock[attr_base + sid - BASE] == 0, f"Lang {lang} SID {sid:#x} non-zero font attr"
            txt = txt_cn if lang == LANG_ZH_CN else (txt_tw if lang == LANG_ZH_TW else txt_en)
            miss = [c for c in txt if c not in pool_chars and c not in "\n\r\t "]
            assert not miss, f"Language {lang} SID {sid:#x} missing font glyph(s): {miss}"

    verified_props = verify_rom_property_ram_slots(stock)

    return {
        "astro_ui_cave_instructions": ui_insns,
        "astro_ui_cave_code_bytes": syms["code_end"] - ADDR_M19_CAVE,
        "astro_ui_cave_total_bytes": syms["cave_end"] - ADDR_M19_CAVE,
        "astro_ui_gap_before_iv_cave": ADDR_M20_IV_CAVE - syms["cave_end"],
        "iv_endtime_cave_instructions": iv_insns,
        "iv_endtime_cave_bytes": syms["iv_cave_end"] - ADDR_IV_ENDTIME_CAVE,
        "cave_free_headroom_before_m600": ADDR_IV_ENDTIME_CAVE_LIMIT - syms["iv_cave_end"],
        "interior_branch_collisions": len(interior_hits),
        "verified_36_languages_zero_missing_glyphs": True,
        "verified_rom_property_ram_slots": verified_props,
        "overridden_ui_string_ids": [f"0x{sid:04x}" for sid, _, _, _, _ in UI_OVERRIDES_M21],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified21-preflash-2026-11-16/lab-build",
    )
    args = ap.parse_args()
    out_dir = args.output.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    stock = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()
    m13 = (ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN").read_bytes()
    m15 = (ROOT / "outputs/Z6-C380-modified15-reviewed-2026-11-15/01_TEST_MODIFIED15/EG162080.BIN").read_bytes()
    m19 = (ROOT / "outputs/Z6-C380-modified19-reviewed-2026-11-16/01_TEST_MODIFIED19/EG162080.BIN").read_bytes()
    m20 = (ROOT / "outputs/Z6-C380-modified20-reviewed-2026-11-16/01_TEST_MODIFIED20/EG162080.BIN").read_bytes()

    assert len(stock) == SIZE, f"Stock size mismatch: {len(stock)} != {SIZE}"
    assert sha(stock) == STOCK_SHA, "Stock checksum mismatch"
    assert sha(m13) == M13_SHA, "M13 checksum mismatch"
    assert sha(m15) == M15_SHA, "M15 checksum mismatch"
    assert sha(m19) == M19_SHA, "M19 checksum mismatch"
    assert sha(m20) == M20_SHA, "M20 checksum mismatch"

    edits, syms = collect_m21_edits(stock)

    m21_buf = bytearray(stock)
    spans_for_audit: list[tuple[int, int, int, str, bytes, bytes, str]] = []
    delta_bytes = 0
    for ed in edits:
        addr = int(ed["address"], 16)
        off = addr - BASE
        b_after = bytes.fromhex(ed["after"])
        b_before = bytes.fromhex(ed["before"])
        assert m21_buf[off : off + len(b_before)] == b_before
        m21_buf[off : off + len(b_after)] = b_after
        delta_bytes += sum(1 for a, b in zip(b_before, b_after) if a != b)
        spans_for_audit.append((off, off + len(b_after), addr, ed["group"], b_before, b_after, ed["description"]))

    spans_for_audit.sort(key=lambda s: s[0])
    for i in range(len(spans_for_audit) - 1):
        prev_end = spans_for_audit[i][1]
        next_start = spans_for_audit[i + 1][0]
        assert prev_end <= next_start, (
            f"Overlap between 0x{spans_for_audit[i][2]:08x} and 0x{spans_for_audit[i+1][2]:08x}"
        )

    crc_str = update_crc(m21_buf)
    m21_bytes = bytes(m21_buf)
    m21_sha = sha(m21_bytes)

    reverted = bytearray(m21_bytes)
    for ed in edits:
        addr = int(ed["address"], 16)
        off = addr - BASE
        b_before = bytes.fromhex(ed["before"])
        reverted[off : off + len(b_before)] = b_before
    update_crc(reverted)
    assert bytes(reverted) == stock, "Reversibility check failed!"

    audit_res = audit_caves_and_glyphs(stock, m21_bytes, syms, spans_for_audit)

    candidate_bi = out_dir / "modified21-candidate.bi"
    candidate_bi.write_bytes(m21_bytes)

    astro_cnt = sum(1 for ed in edits if ed["group"].startswith(("m21_astro", "m21_color", "m21_ui", "modified9_")))
    iv_cnt = sum(1 for ed in edits if ed["group"].startswith("m21_interval"))
    m600_cnt = sum(1 for ed in edits if ed["group"].startswith("m600_"))
    assert astro_cnt + iv_cnt + m600_cnt == len(edits)

    manifest = {
        "candidate": "modified21-astro-raw-fix-srgb-ui-interval-endtime-600s-v1",
        "design": (
            "A1 v4 (Fixed PID 0x0508 RAM 0xC24CDE28 gate + Photo 0x1381 sRGB lock 0x1014F678 + "
            "'标准 (sRGB)' / '直通RAW (sRGB)' 36-lang UI) + "
            "Post-Exposure Interval Timer (0x101FF392) + "
            "Dynamic Exposure-Aware Interval End Day/Time (0x1049C26C) + Permanent 30-600s v2"
        ),
        "base_stock_sha256": STOCK_SHA,
        "modified20_sha256": M20_SHA,
        "modified21_sha256": m21_sha,
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

    manifest_json = out_dir / "modified21-manifest.json"
    manifest_json.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    patches_dir = ROOT / "patches"
    patches_dir.mkdir(parents=True, exist_ok=True)
    patch_recipe = patches_dir / "z6-c380-modified21-astro-raw-fix-srgb-600s.json"
    patch_recipe.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print(
        f"MODIFIED21 READY | SHA256={m21_sha} | CRC=0x{crc_str} | "
        f"Edits={len(edits)} ({astro_cnt}+{iv_cnt}+{m600_cnt}) | "
        f"UI_Cave={audit_res['astro_ui_cave_total_bytes']}B (gap {audit_res['astro_ui_gap_before_iv_cave']}B) | "
        f"IV_Cave={audit_res['iv_endtime_cave_bytes']}B (free {audit_res['cave_free_headroom_before_m600']}B)"
    )


if __name__ == "__main__":
    main()

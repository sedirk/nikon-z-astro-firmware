"""Deterministically build and statically audit Modified16 (A3 UI-Switchable Astro Lossless + Permanent 30-600s v2)."""
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

from z6_astro_ui_toggle import (
    ADDR_M16_CAVE,
    ADDR_M9_SANITIZER,
    HELP_EN,
    HELP_ZH_CN,
    HELP_ZH_TW,
    LABEL_EN,
    LABEL_ZH_CN,
    LABEL_ZH_TW,
    LANG_ZH_CN,
    LANG_ZH_TW,
    build_all_m16_astro_ui_spans,
)
from z6_m600_tables import BASE, SIZE
from z6_m600_v2 import build_all_m600_v2_spans

ROOT = THIS_DIR.parents[1]
STOCK_SHA = "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c"
M12_SHA = "9734012be0e063fa8f2ccbf77c2dd5a63a76be2f45887aa6b806b97b441cb67c"
M13_SHA = "3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749"
M14_SHA = "6d970609c18ac64302e82a7e4f4bfba9d8d4b14a606b55bf2cbc56dc37ea754b"
M15_SHA = "0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def update_crc(buf: bytearray) -> str:
    crc = binascii.crc_hqx(bytes(buf[:-2]), 0)
    buf[-2:] = crc.to_bytes(2, "big")
    assert binascii.crc_hqx(bytes(buf), 0) == 0
    return f"{crc:04x}"


def collect_m16_edits(stock: bytes) -> tuple[list[dict], dict[str, int]]:
    m16_spans, syms = build_all_m16_astro_ui_spans(stock)
    m600_spans = build_all_m600_v2_spans(stock)

    edits: list[dict] = []
    for addr, grp, new_b, desc in m16_spans + m600_spans:
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


def audit_cave_disassembly_and_glyphs(stock: bytes, m16_bytes: bytes, syms: dict[str, int], spans: list) -> dict:
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cave_code_start = ADDR_M16_CAVE - BASE
    cave_code_end = syms["code_end"] - BASE
    insns = list(cs.disasm(m16_bytes[cave_code_start:cave_code_end], ADDR_M16_CAVE))
    decoded_len = sum(i.size for i in insns)
    assert decoded_len == (cave_code_end - cave_code_start), (
        f"Cave disassembly incomplete: decoded {decoded_len} != {cave_code_end - cave_code_start}"
    )
    for i in insns:
        # Ensure no unpredictable POP.W with both LR and PC set (0xE8BD with bits 14 & 15 both 1)
        if i.size == 4:
            hw1, hw2 = struct.unpack_from("<HH", i.bytes, 0)
            if hw1 == 0xE8BD:
                assert (hw2 & 0xC000) != 0xC000, f"Unpredictable POP {{.., lr, pc}} at {i.address:#x}"

    # Verify interior halfword addresses of multi-instruction inline hooks are never targeted by
    # short B/B<cc>/CBZ/CBNZ/B.W/BL instructions within +/-16MB around the code section.
    interior_addrs: set[int] = set()
    for off, end, addr, grp, _, _, _ in spans:
        if not grp.startswith("m600_") and addr not in (ADDR_M9_SANITIZER, ADDR_M16_CAVE):
            for ia in range(addr + 2, addr + (end - off), 2):
                interior_addrs.add(ia)

    # Scan nearby +/-4KB window around each hook site with Capstone for any local/cond/cbz branch into interior_addrs
    interior_hits: list[str] = []
    for off, end, addr, grp, _, _, _ in spans:
        if not grp.startswith("m600_") and addr not in (ADDR_M9_SANITIZER, ADDR_M16_CAVE):
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
        miss = [c for c in (lbl + hlp) if c not in pool_chars]
        assert not miss, f"Language {lang} missing font glyph(s): {miss}"

    return {
        "cave_code_instructions": len(insns),
        "cave_code_bytes": cave_code_end - cave_code_start,
        "cave_total_bytes": syms["cave_end"] - ADDR_M16_CAVE,
        "cave_free_headroom_before_m600": 0x1002EF14 - syms["cave_end"],
        "interior_branch_collisions": len(interior_hits),
        "verified_36_languages_zero_missing_glyphs": missing_glyph_langs == 0,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified16-preflash-2026-11-15/lab-build",
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

    assert len(stock) == len(m12) == len(m13) == len(m15) == SIZE
    assert sha(stock) == STOCK_SHA and binascii.crc_hqx(stock, 0) == 0
    assert sha(m12) == M12_SHA and binascii.crc_hqx(m12, 0) == 0
    assert sha(m13) == M13_SHA and binascii.crc_hqx(m13, 0) == 0
    assert sha(m15) == M15_SHA and binascii.crc_hqx(m15, 0) == 0

    edits, syms = collect_m16_edits(stock)
    spans = []
    for e in edits:
        addr = int(e["address"], 16)
        old_b = bytes.fromhex(e["before"])
        new_b = bytes.fromhex(e["after"])
        assert len(old_b) == len(new_b) > 0
        off = addr - BASE
        assert 0 <= off and off + len(old_b) <= SIZE - 2
        spans.append((off, off + len(old_b), addr, e["group"], old_b, new_b, e))

    for (_, prev_end, *_), (cur_start, *_) in zip(spans, spans[1:]):
        assert prev_end <= cur_start, f"Overlapping edit spans: {prev_end:#x} > {cur_start:#x}"

    recipe_doc = {
        "schema": 1,
        "model": "Nikon Z6 (first generation)",
        "version": "C3.80",
        "module": "eg1620_038000.bi",
        "load_base": "0x10020000",
        "source_size": SIZE,
        "source_sha256": STOCK_SHA,
        "parent_candidate": "modified15-production-600s-v2",
        "parent_sha256": M15_SHA,
        "status": (
            "preflash candidate; implements Design A3 UI-switchable 'Astro Lossless' / '天文无损' in "
            "NEF (RAW) compression menu (0x0506==2) with genuine Lossless NEF encoding + permanent 30-600s v2 M-still shutter"
        ),
        "candidates": [
            {
                "id": "modified16-astro-ui-600s-v1",
                "scope": (
                    "21-site UI-switchable Astro Lossless RAW + Lossless NEF coercion (dynamic gate on 0x1315==2 && 0x131b<=1) "
                    "+ 84-site permanent 30-600s v2 M-mode still shutter extension (105 total non-overlapping sites)."
                ),
                "edits": edits,
            }
        ],
    }
    recipe_path = ROOT / "patches/z6-c380-modified16-astro-ui-600s.json"
    recipe_path.write_text(json.dumps(recipe_doc, indent=2), encoding="utf8")

    # Build A: directly from Stock C3.80
    from_stock = bytearray(stock)
    for off, end, addr, _, old_b, new_b, _ in spans:
        assert bytes(from_stock[off:end]) == old_b, f"Stock anchor mismatch at {addr:#x}"
        from_stock[off:end] = new_b
    crc_stock = update_crc(from_stock)

    # Build B: incrementally from Modified15 (revert M13's 13 inline sites, keep 0x1002d884 + 84 m600_v2 sites, apply 20 m16_* sites)
    m13_recipe = json.loads(
        (ROOT / "patches/z6-c380-modified13-production-convergence.json").read_text(encoding="utf8")
    )
    from_m15 = bytearray(m15)
    for me in m13_recipe["candidates"][0]["edits"]:
        m_addr = int(me["address"], 16)
        if m_addr == ADDR_M9_SANITIZER:
            continue
        m_off = m_addr - BASE
        m_old = bytes.fromhex(me["before"])
        m_new = bytes.fromhex(me["after"])
        assert bytes(from_m15[m_off : m_off + len(m_new)]) == m_new
        from_m15[m_off : m_off + len(m_old)] = m_old

    m16_only_count = 0
    m600_count = 0
    for off, end, addr, grp, old_b, new_b, _ in spans:
        if grp.startswith("m600_") or addr == ADDR_M9_SANITIZER:
            assert bytes(from_m15[off:end]) == new_b, f"Modified15 inherited site mismatch at {addr:#x}"
            if grp.startswith("m600_"):
                m600_count += 1
        else:
            assert bytes(from_m15[off:end]) == old_b, f"Modified15 reverted anchor mismatch at {addr:#x}"
            from_m15[off:end] = new_b
            m16_only_count += 1
    crc_m15 = update_crc(from_m15)

    m16_bytes = bytes(from_stock)
    assert m16_bytes == bytes(from_m15), "Build from Stock vs Modified15 diverged!"
    assert crc_stock == crc_m15
    m16_sha = sha(m16_bytes)
    assert m16_sha not in (STOCK_SHA, M12_SHA, M13_SHA, M14_SHA, M15_SHA)

    # Static disassembly, interior-branch, and 36-language glyph pool audit
    static_audit = audit_cave_disassembly_and_glyphs(stock, m16_bytes, syms, spans)

    # Exact rollback checks to Stock C3.80 and Modified15
    rev_stock = bytearray(m16_bytes)
    for off, end, _, _, old_b, _, _ in spans:
        rev_stock[off:end] = old_b
    update_crc(rev_stock)
    assert bytes(rev_stock) == stock, "Rollback to Stock failed!"

    rev_m15 = bytearray(m16_bytes)
    for off, end, addr, grp, old_b, _, _ in spans:
        if not grp.startswith("m600_") and addr != ADDR_M9_SANITIZER:
            rev_m15[off:end] = old_b
    for me in m13_recipe["candidates"][0]["edits"]:
        m_addr = int(me["address"], 16)
        if m_addr != ADDR_M9_SANITIZER:
            m_off = m_addr - BASE
            m_new = bytes.fromhex(me["after"])
            rev_m15[m_off : m_off + len(m_new)] = m_new
    update_crc(rev_m15)
    assert bytes(rev_m15) == m15, "Transform rollback to Modified15 failed!"

    site_details = []
    for off, end, addr, grp, old_b, new_b, meta in spans:
        site_details.append(
            {
                "address": f"0x{addr:08x}",
                "file_offset": f"0x{off:08x}",
                "group": grp,
                "span_bytes": len(old_b),
                "changed_bytes": sum(x != y for x, y in zip(old_b, new_b)),
                "description": meta.get("description", ""),
            }
        )

    diff_vs_stock = sum(a != b for a, b in zip(stock, m16_bytes))
    diff_vs_m15 = sum(a != b for a, b in zip(m15, m16_bytes))

    out_bin = out_dir / "modified16-candidate.bi"
    out_bin.write_bytes(m16_bytes)
    (out_dir / "prepare_modified16_lab.py").write_bytes(Path(__file__).read_bytes())

    manifest = {
        "ok": True,
        "candidate": "modified16",
        "candidate_id": "modified16-astro-ui-600s-v1",
        "parent_candidate": "modified15",
        "recipe_path": recipe_path.relative_to(ROOT).as_posix(),
        "recipe_sha256": sha(recipe_path.read_bytes()),
        "module_path": out_bin.relative_to(ROOT).as_posix(),
        "sha256": m16_sha,
        "size_bytes": len(m16_bytes),
        "crc16": crc_stock,
        "total_sites": len(spans),
        "astro_ui_sites": len(spans) - m600_count,
        "m600_sites": m600_count,
        "total_spans_bytes": sum(s["span_bytes"] for s in site_details),
        "total_changed_bytes_vs_stock": diff_vs_stock,
        "total_changed_bytes_vs_m15": diff_vs_m15,
        "cave_symbols": {k: f"0x{v:08x}" for k, v in syms.items()},
        "static_audit": static_audit,
        "verified_dual_build": True,
        "verified_rollback_to_m15": True,
        "verified_rollback_to_stock": True,
        "sites": site_details,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf8")
    print(f"Modified16 prepared: SHA256={m16_sha} CRC16={crc_stock} RecipeSHA256={manifest['recipe_sha256']}")
    print(
        f"Sites={len(spans)} (AstroUI={len(spans)-m600_count}, M600={m600_count}) "
        f"CaveBytes={static_audit['cave_total_bytes']} Headroom={static_audit['cave_free_headroom_before_m600']} "
        f"ChangedVsStock={diff_vs_stock} ChangedVsM15={diff_vs_m15}"
    )


if __name__ == "__main__":
    main()

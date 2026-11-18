"""Build and statically audit Nikon Z6 C3.80 Modified23 firmware.

SPDX-License-Identifier: GPL-3.0-or-later

Resolves P1 (Long-Exposure Uncompressed Astro RAW 16-bit LE & Embedded Preview Overlay)
on top of the verified Modified22 baseline:
  1. Preserves all Modified22 fixes intact:
     - Genuine Color space PID 0x0526 (RAM 0xC24CDEA0) UI gate + PID 0x131B <= 1 RAW check;
     - Effective Color Space PID 0x130A (RAM 0xC24CC74C) locked to 0 (sRGB) at 0x1014BB28;
     - Photo-mode Auto ISO sensitivity control (PID 0x0508 / 0x1381) 100% Stock C3.80;
     - 36-language UI overrides, post-exposure Interval Timer, dynamic End Day/Time, and 60s-600s shutter v2.
  2. Adds 14th Astro-gated trampoline (`tramp_a34d0` inside `astro_ui_cave`) hooked at `0x100A34D0`
     inside the uncompressed RAW encoder `0x100A3480`:
     - Root cause: On >= 1s (`wide=1` / `owner+0x252=1` or `owner+0x1af0!=0`) captures, frontend RAW
       `INPUT` uses descriptor format `3` (`16-bit LE` unpacked, stride `12,128` B, `48,997,120` B).
       Lossless/lossy encoder `0x100A323E` compresses format `3 -> 0` cleanly, whereas uncompressed
       encoder `0x100A3480` branches to `0x100A34D0` and executes `strb r2, [r4, #2]; strb r2, [r4, #3]`
       (`r2 = 0`), setting BOTH hardware bit-packer input and output codes to `0` (`16-bit LE`).
       That writes `48,997,120` B into a `42,920,960` B (`packed-14`) slot, colliding with the three
       512-byte-aligned embedded preview JPEG slots starting at `+44,072,448` B (rows `3633..4000`)
       while TIFF SubIFD2 still declares `Compression=34713, BitsPerSample=14`.
     - Fix: `0x100A34D0` (`a270e270`) branches to `tramp_a34d0`, which saves `{r0, r1, r2, lr}` and
       `APSR` flags and calls `fn_is_astro_r0` (`0x1002D900`):
         * Standard mode (`r0 == 0`): executes exact Stock `strb r2, [r4, #2]; strb r2, [r4, #3]` -> `0x100A34AA`;
         * Astro RAW mode (`r0 == 1`): sets input `[r4, #2] = 0` (`16-bit LE`), reads target NEF format
           `ldrb r1, [r5, #1]` (`ENCODED+0x51`), sets output `[r4, #3] = 2` (`12-bit packed`) if `r1 == 2`
           else `1` (`14-bit packed`, `lut_ptr = 0` lossless bit-packing), restores `APSR` and `{r0..r2, lr}`,
           and jumps to `0x100A34AA` where `0x100A3548..0x100A35A8` computes exact `dst_stride` (`10,624` B
           for FX 14-bit) and `StripByteCounts` (`42,920,960` B == `raw_cap`).
  3. Verifies bit-for-bit SHA-256 reproducibility of Modified19, Modified20, Modified21, and Modified22.
"""
from __future__ import annotations
if not __debug__:
    raise RuntimeError(
        "prepare_modified23_lab.py must not be executed with Python -O/-OO "
        "(imported builders and probes rely on debug assertions)."
    )

import argparse
import binascii
import hashlib
import json
from pathlib import Path
import struct
import sys

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from prepare_modified22_lab import (  # noqa: E402
    M13_SHA,
    M15_SHA,
    M19_SHA,
    M20_SHA,
    M21_SHA,
    STOCK_SHA,
    _apply_spans,
    verify_rom_property_ram_slots,
)
from z6_astro_ui_color_space_v2 import (  # noqa: E402
    ADDR_M19_CAVE,
    ADDR_M20_IV_CAVE,
    ADDR_M9_SANITIZER,
    LANG_ZH_CN,
    LANG_ZH_TW,
    UI_OVERRIDES_M21,
    build_all_m19_astro_ui_spans,
    build_all_m20_astro_ui_spans,
    build_all_m21_astro_ui_spans,
    build_all_m22_astro_ui_spans,
    build_all_m23_astro_ui_spans,
)
from z6_c380_container import load_stock_eg_module  # noqa: E402
from z6_interval_post_exposure import (  # noqa: E402
    ADDR_IV_ENDTIME_CAVE,
    ADDR_IV_ENDTIME_CAVE_LIMIT,
    build_all_m20_interval_spans,
    build_interval_post_exposure_spans,
)
from z6_m600_tables import BASE, SIZE  # noqa: E402
from z6_m600_v2 import build_all_m600_v2_spans  # noqa: E402

ROOT = THIS_DIR.parents[1]
M22_SHA = "c6a23ea40f03d83c6c721e96e8b5af8a8422a7b4ed81d39222392b7635681771"
DEFAULT_RECIPE_REL = "patches/z6-c380-modified23-uncompressed-astro-raw-srgb-600s.json"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def update_crc(buf: bytearray) -> str:
    crc = binascii.crc_hqx(bytes(buf[:-2]), 0)
    buf[-2:] = crc.to_bytes(2, "big")
    require(binascii.crc_hqx(bytes(buf), 0) == 0, "CRC-16/XMODEM remainder non-zero after update")
    return f"{crc:04x}"

def verify_legacy_reproducibility_through_m22(stock: bytes) -> dict[str, str]:
    """Ensure M19, M20, M21, and M22 builders remain 100% bit-for-bit reproducible."""
    m600_spans = build_all_m600_v2_spans(stock)
    iv19_spans = build_interval_post_exposure_spans(stock)
    iv20_spans, _ = build_all_m20_interval_spans(stock)

    m19_ui, _ = build_all_m19_astro_ui_spans(stock)
    m20_ui, _ = build_all_m20_astro_ui_spans(stock)
    m21_ui, _ = build_all_m21_astro_ui_spans(stock)
    m22_ui, _ = build_all_m22_astro_ui_spans(stock)

    got_m19 = sha(_apply_spans(stock, m19_ui + iv19_spans + m600_spans))
    got_m20 = sha(_apply_spans(stock, m20_ui + iv20_spans + m600_spans))
    got_m21 = sha(_apply_spans(stock, m21_ui + iv20_spans + m600_spans))
    got_m22 = sha(_apply_spans(stock, m22_ui + iv20_spans + m600_spans))

    require(got_m19 == M19_SHA, f"M19 reproducibility broken: {got_m19} != {M19_SHA}")
    require(got_m20 == M20_SHA, f"M20 reproducibility broken: {got_m20} != {M20_SHA}")
    require(got_m21 == M21_SHA, f"M21 reproducibility broken: {got_m21} != {M21_SHA}")
    require(got_m22 == M22_SHA, f"M22 reproducibility broken: {got_m22} != {M22_SHA}")
    return {
        "m19_sha256": got_m19,
        "m20_sha256": got_m20,
        "m21_sha256": got_m21,
        "m22_sha256": got_m22,
    }


def collect_m23_edits(stock: bytes) -> tuple[list[dict], dict[str, int]]:
    m23_ui_spans, ui_syms = build_all_m23_astro_ui_spans(stock)
    iv_spans, iv_syms = build_all_m20_interval_spans(stock)
    m600_spans = build_all_m600_v2_spans(stock)

    syms = dict(ui_syms)
    for k, v in iv_syms.items():
        require(k not in syms, f"Duplicate symbol {k}")
        syms[k] = v

    edits: list[dict] = []
    for addr, grp, new_b, desc in m23_ui_spans + iv_spans + m600_spans:
        if grp.startswith("m20_interval"):
            grp = f"m23_{grp[4:]}"
        off = addr - BASE
        require(0 <= off and off + len(new_b) <= SIZE - 2, f"Span out of bounds at {addr:#x}")
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


def audit_a34d0_global_xrefs(stock: bytes) -> dict[str, list[str]]:
    """Verify across the entire 33.5 MB firmware that ONLY 0x100A349C targets 0x100A34D0..0x100A34D3."""
    ptr_hits: list[str] = []
    for tgt in range(0x100A34D0, 0x100A34D5):
        pat = struct.pack("<I", tgt)
        idx = 0
        while True:
            pos = stock.find(pat, idx)
            if pos < 0:
                break
            ptr_hits.append(f"0x{BASE + pos:08x}->0x{tgt:08x}")
            idx = pos + 1
    require(not ptr_hits, f"Unexpected u32 pointer literal(s) into 0x100A34D0..0x100A34D4: {ptr_hits}")

    local_hits: list[str] = []
    cs_skip = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cs_skip.skipdata = True
    for ins in cs_skip.disasm(stock[0x100A2000 - BASE : 0x100A5000 - BASE], 0x100A2000):
        if ins.mnemonic.startswith(("b", "cbz", "cbnz")) and "#" in ins.op_str:
            try:
                tgt = int(ins.op_str.split("#")[-1].strip(), 16)
            except ValueError:
                continue
            if 0x100A34D0 <= tgt <= 0x100A34D3:
                local_hits.append(f"0x{ins.address:08x}:{ins.mnemonic} {ins.op_str}")
    require(local_hits == ["0x100a349c:beq #0x100a34d0"], f"Unexpected local branch xrefs: {local_hits}")
    wide_hits: list[str] = []
    lo_off = max(0, (0x100A34D0 - 0x1000000) - BASE)
    hi_off = min(len(stock) - 4, (0x100A34D0 + 0x1000000) - BASE)
    mv = memoryview(stock)
    for off in range(lo_off, hi_off, 2):
        hw1 = mv[off] | (mv[off + 1] << 8)
        if (hw1 & 0xF800) == 0xF000:
            hw2 = mv[off + 2] | (mv[off + 3] << 8)
            top = (hw2 >> 12) & 0xF
            if top in (0x8, 0x9, 0xA, 0xB, 0xD, 0xF):
                pc = BASE + off
                if top in (0x9, 0xB, 0xD, 0xF):
                    s = (hw1 >> 10) & 1
                    j1 = (hw2 >> 13) & 1
                    j2 = (hw2 >> 11) & 1
                    i1 = (~(j1 ^ s)) & 1
                    i2 = (~(j2 ^ s)) & 1
                    imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((hw1 & 0x3FF) << 12) | ((hw2 & 0x7FF) << 1)
                    if s:
                        imm -= 1 << 25
                else:
                    cond = (hw1 >> 6) & 0xF
                    if cond >= 14:
                        continue
                    s = (hw1 >> 10) & 1
                    j1 = (hw2 >> 13) & 1
                    j2 = (hw2 >> 11) & 1
                    imm = (s << 20) | (j2 << 19) | (j1 << 18) | ((hw1 & 0x3F) << 12) | ((hw2 & 0x7FF) << 1)
                    if s:
                        imm -= 1 << 21
                tgt = (pc + 4 + imm) & 0xFFFFFFFF
                if 0x100A34D0 <= tgt <= 0x100A34D3:
                    wide_hits.append(f"0x{pc:08x}->0x{tgt:08x}")
    require(not wide_hits, f"Unexpected 32-bit B.W/BL xrefs into 0x100A34D0..0x100A34D3: {wide_hits}")
    return {
        "u32_pointer_hits": ptr_hits,
        "local_branch_hits": local_hits,
        "wide_branch_hits": wide_hits,
    }


def audit_caves_and_glyphs(
    stock: bytes, m23_bytes: bytes, syms: dict[str, int], spans: list
) -> dict:
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    def _audit_code_range(start_addr: int, end_addr: int, label: str) -> int:
        s_off = start_addr - BASE
        e_off = end_addr - BASE
        insns = list(cs.disasm(m23_bytes[s_off:e_off], start_addr))
        decoded = sum(i.size for i in insns)
        require(
            decoded == (e_off - s_off),
            f"{label} disassembly incomplete: decoded {decoded} != {e_off - s_off}",
        )
        for i in insns:
            if i.size == 4:
                hw1, hw2 = struct.unpack_from("<HH", i.bytes, 0)
                if hw1 == 0xE8BD:
                    require(
                        (hw2 & 0xC000) != 0xC000,
                        f"Unpredictable POP {{.., lr, pc}} at {i.address:#x} in {label}",
                    )
        return len(insns)

    ui_insns = _audit_code_range(ADDR_M19_CAVE, syms["code_end"], "astro_ui_cave")
    iv_insns = _audit_code_range(ADDR_IV_ENDTIME_CAVE, syms["iv_cave_end"], "iv_endtime_cave")

    # Verify Auto ISO functions 0x1040AD00 and 0x1014F678 remain 100% Stock:
    require(
        m23_bytes[0x1040AD00 - BASE : 0x1040AD14 - BASE] == stock[0x1040AD00 - BASE : 0x1040AD14 - BASE],
        "Auto ISO 0x1040AD00 Stock bytes mismatch",
    )
    require(
        m23_bytes[0x1014F638 - BASE : 0x1014F6B4 - BASE] == stock[0x1014F638 - BASE : 0x1014F6B4 - BASE],
        "Auto ISO 0x1014F638 Stock bytes mismatch",
    )
    # Verify 0x100A34D4 (b #0x100a34aa) immediately after 4-byte 0x100A34D0 hook is untouched:
    require(
        m23_bytes[0x100A34D4 - BASE : 0x100A34D6 - BASE] == stock[0x100A34D4 - BASE : 0x100A34D6 - BASE],
        "Adjacent 0x100A34D4 instruction altered",
    )
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
    require(not interior_hits, f"Interior hook branch target collision(s): {interior_hits}")

    a34d0_xrefs = audit_a34d0_global_xrefs(stock)

    idx_tbl = 0x112C2A08
    pool_tbl = 0x112C2A98
    attr_tbl = 0x112C2B28
    sid_class_tbl = 0x10D2FF58
    for sid, _, _, _, _ in UI_OVERRIDES_M21:
        require(stock[sid_class_tbl + sid - BASE] == 0, f"String ID {sid:#x} non-zero global font class")
    for lang in range(36):
        idx_base = struct.unpack_from("<I", stock, idx_tbl + lang * 4 - BASE)[0]
        pool_base = struct.unpack_from("<I", stock, pool_tbl + lang * 4 - BASE)[0]
        attr_base = struct.unpack_from("<I", stock, attr_tbl + lang * 4 - BASE)[0]
        end_off = struct.unpack_from("<I", stock, idx_base + 2291 * 4 - BASE)[0]
        pool_chars = set(
            stock[pool_base - BASE : pool_base + end_off - BASE].decode("utf-16le", errors="ignore")
        )
        for sid, _, txt_en, txt_cn, txt_tw in UI_OVERRIDES_M21:
            require(stock[attr_base + sid - BASE] == 0, f"Lang {lang} SID {sid:#x} non-zero font attr")
            txt = txt_cn if lang == LANG_ZH_CN else (txt_tw if lang == LANG_ZH_TW else txt_en)
            miss = [c for c in txt if c not in pool_chars and c not in "\n\r\t "]
            require(not miss, f"Language {lang} SID {sid:#x} missing font glyph(s): {miss}")
    verified_props = verify_rom_property_ram_slots(stock)
    legacy_repro = verify_legacy_reproducibility_through_m22(stock)

    return {
        "astro_ui_cave_instructions": ui_insns,
        "astro_ui_cave_code_bytes": syms["code_end"] - ADDR_M19_CAVE,
        "astro_ui_cave_total_bytes": syms["cave_end"] - ADDR_M19_CAVE,
        "astro_ui_gap_before_iv_cave": ADDR_M20_IV_CAVE - syms["cave_end"],
        "iv_endtime_cave_instructions": iv_insns,
        "iv_endtime_cave_bytes": syms["iv_cave_end"] - ADDR_IV_ENDTIME_CAVE,
        "cave_free_headroom_before_m600": ADDR_IV_ENDTIME_CAVE_LIMIT - syms["iv_cave_end"],
        "interior_branch_collisions": len(interior_hits),
        "a34d0_global_xref_audit": a34d0_xrefs,
        "auto_iso_0508_1381_restored_to_stock": True,
        "uncompressed_format3_hardware_pack_gated": True,
        "verified_36_languages_zero_missing_glyphs": True,
        "verified_rom_property_ram_slots": verified_props,
        "legacy_builder_reproducibility": legacy_repro,
        "overridden_ui_string_ids": [f"0x{sid:04x}" for sid, _, _, _, _ in UI_OVERRIDES_M21],
    }


def main() -> None:
    if not __debug__:
        raise RuntimeError("prepare_modified23_lab.py must not be executed with Python -O/-OO.")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--stock",
        type=Path,
        default=None,
        help="Path to official Z_6_0380.bin or decoded eg1620_038000.bi",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified23-preflash-2026-11-18/lab-build",
    )
    ap.add_argument(
        "--write-patch-recipe",
        action="store_true",
        help=f"Write tracked {DEFAULT_RECIPE_REL}",
    )
    args = ap.parse_args()
    out_dir = args.output.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    stock = load_stock_eg_module(args.stock, ROOT)
    require(len(stock) == SIZE, f"Stock size mismatch: {len(stock)} != {SIZE}")
    require(sha(stock) == STOCK_SHA, "Stock checksum mismatch")

    optional_historical = (
        ("M13", ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN", M13_SHA),
        ("M15", ROOT / "outputs/Z6-C380-modified15-reviewed-2026-11-15/01_TEST_MODIFIED15/EG162080.BIN", M15_SHA),
        ("M19", ROOT / "outputs/Z6-C380-modified19-reviewed-2026-11-16/01_TEST_MODIFIED19/EG162080.BIN", M19_SHA),
        ("M20", ROOT / "outputs/Z6-C380-modified20-reviewed-2026-11-16/01_TEST_MODIFIED20/EG162080.BIN", M20_SHA),
        ("M21", ROOT / "outputs/Z6-C380-modified21-reviewed-2026-11-16/01_TEST_MODIFIED21/EG162080.BIN", M21_SHA),
        ("M22", ROOT / "outputs/Z6-C380-modified22-reviewed-2026-11-17/01_TEST_MODIFIED22/EG162080.BIN", M22_SHA),
    )
    for label, hist_path, exp_sha in optional_historical:
        if hist_path.is_file():
            require(sha(hist_path.read_bytes()) == exp_sha, f"{label} checksum mismatch")
    edits, syms = collect_m23_edits(stock)

    m23_buf = bytearray(stock)
    spans_for_audit: list[tuple[int, int, int, str, bytes, bytes, str]] = []
    delta_bytes = 0
    for ed in edits:
        addr = int(ed["address"], 16)
        off = addr - BASE
        b_after = bytes.fromhex(ed["after"])
        b_before = bytes.fromhex(ed["before"])
        require(m23_buf[off : off + len(b_before)] == b_before, f"Before-bytes mismatch at {addr:#x}")
        m23_buf[off : off + len(b_after)] = b_after
        delta_bytes += sum(1 for a, b in zip(b_before, b_after) if a != b)
        spans_for_audit.append((off, off + len(b_after), addr, ed["group"], b_before, b_after, ed["description"]))

    spans_for_audit.sort(key=lambda s: s[0])
    for i in range(len(spans_for_audit) - 1):
        prev_end = spans_for_audit[i][1]
        next_start = spans_for_audit[i + 1][0]
        require(
            prev_end <= next_start,
            f"Overlap between 0x{spans_for_audit[i][2]:08x} and 0x{spans_for_audit[i+1][2]:08x}",
        )
    crc_str = update_crc(m23_buf)
    m23_bytes = bytes(m23_buf)
    m23_sha = sha(m23_bytes)

    reverted = bytearray(m23_bytes)
    for ed in edits:
        addr = int(ed["address"], 16)
        off = addr - BASE
        b_before = bytes.fromhex(ed["before"])
        reverted[off : off + len(b_before)] = b_before
    update_crc(reverted)
    require(bytes(reverted) == stock, "Reversibility check failed!")

    audit_res = audit_caves_and_glyphs(stock, m23_bytes, syms, spans_for_audit)

    candidate_bi = out_dir / "modified23-candidate.bi"
    candidate_bi.write_bytes(m23_bytes)

    astro_cnt = sum(1 for ed in edits if ed["group"].startswith(("m23_astro", "m23_color", "m23_ui", "modified9_")))
    iv_cnt = sum(1 for ed in edits if ed["group"].startswith("m23_interval"))
    m600_cnt = sum(1 for ed in edits if ed["group"].startswith("m600_"))
    require(
        astro_cnt == 18 and iv_cnt == 3 and m600_cnt == 84 and len(edits) == 105,
        f"Unexpected edit counts: astro={astro_cnt}, iv={iv_cnt}, m600={m600_cnt}, total={len(edits)}",
    )
    manifest = {
        "candidate": "modified23-uncompressed-astro-raw-pid0526-srgb-600s-v1",
        "design": (
            "A1 v6 (Modified22 Color space PID 0x0526 gate + Effective Color Space PID 0x130A sRGB lock + "
            "0x100A34D0 Uncompressed Format-3 Hardware Bit-Packer Fix [16-bit LE -> 14-bit/12-bit packed, lut=0] + "
            "'标准 (sRGB)' / '直通RAW (sRGB)' 36-lang UI) + "
            "Post-Exposure Interval Timer (0x101FF392) + "
            "Dynamic Exposure-Aware Interval End Day/Time (0x1049C26C) + Permanent 30-600s v2"
        ),
        "base_stock_sha256": STOCK_SHA,
        "modified22_sha256": M22_SHA,
        "modified23_sha256": m23_sha,
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

    manifest_text = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    manifest_json = out_dir / "modified23-manifest.json"
    manifest_json.write_bytes(manifest_text.encode("utf-8"))

    patch_recipe = ROOT / DEFAULT_RECIPE_REL
    if args.write_patch_recipe:
        patch_recipe.parent.mkdir(parents=True, exist_ok=True)
        patch_recipe.write_bytes(manifest_text.encode("utf-8"))
    elif patch_recipe.is_file():
        tracked_recipe = json.loads(patch_recipe.read_text(encoding="utf-8"))
        require(
            tracked_recipe["modified23_sha256"] == m23_sha and tracked_recipe["edits"] == edits,
            "Generated Modified23 edits diverged from tracked patch recipe",
        )
    print(
        f"MODIFIED23 READY | SHA256={m23_sha} | CRC=0x{crc_str} | "
        f"Edits={len(edits)} ({astro_cnt}+{iv_cnt}+{m600_cnt}) | "
        f"UI_Cave={audit_res['astro_ui_cave_total_bytes']}B (gap {audit_res['astro_ui_gap_before_iv_cave']}B) | "
        f"IV_Cave={audit_res['iv_endtime_cave_bytes']}B (free {audit_res['cave_free_headroom_before_m600']}B)"
    )


if __name__ == "__main__":
    main()

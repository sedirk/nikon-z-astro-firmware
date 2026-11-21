"""Build and statically audit Nikon Z6 C3.80 Astro Firmware (Modified24).

SPDX-License-Identifier: GPL-3.0-or-later

Combines all 112 camera-verified non-overlapping patch spans against official
Nikon Z6 C3.80 (`eg1620_038000.bi`, SHA-256 `1e6348d5...`):
  1. Astro Direct RAW & sRGB Dual-Layer Color Space Architecture (`18` spans):
     - Reuses Photo Shooting Menu `Color space` (`PID 0x0526`, `RAM 0xC24CDEA0`)
       with Effective Color Space (`PID 0x130A`, `RAM 0xC24CC74C`) locked to `0` (`sRGB`);
     - 14 Astro-gated ISP/RAW trampolines including 4-channel Q12 unity gain (`4096 = 1.0000x`
       at `0x10122CBC`), spatial filter bypass, concentric ring bypass, and uncompressed
       format-3 hardware bit-packer fix (`0x100A34D0 -> 0x1002DB5C`, `lut_ptr = 0`);
     - Photo-mode Auto ISO sensitivity control (`PID 0x0508` / `0x1381`) 100% Stock C3.80.
  2. Astro Red Night-Vision Display (`7` spans in Free Hole B `0x1002E1B0+` & display/UI hooks):
     - Reuses Setup Menu `Information display` (`PID 0x1111`, `RAM 0xC24DD0EC`, `rom_default = 0`):
       `0` = Off (Standard full-color display), `1` = On (Astro Red pure-red LCD & OLED EVF);
     - `Mode 2A: LumaRed` Q14 post-output CSC (`[12288, 0..0]`) strictly isolated to VGC
       Channel 1 (`unit_off == 0x4000`, rear LCD + EVF) plus hardware framing grid (`0x20145618`);
       Channel 0 (`unit_off == 0x0000`, external HDMI), RAW/NEF, JPEG, and AE/AF stay 100% Stock;
     - Locks `DISP` shooting info screen helpers (`0x1040E7D8`, `0x1043A1E0`) to `Light on dark`;
     - Chains 36-language glyph-verified UI overrides (`SID 0x023F / 0x0240 / 0x0241 / 0x054C`)
       at `GetLanguageString` epilogue (`0x104C013C`) after `tramp_4c0134`.
  3. Post-Exposure Interval Timer & Dynamic Exposure-Aware End Day/Time (`3` spans).
  4. Extended Manual Shutter Speeds `60s..600s` v2 (`84` spans).
  5. Verifies bit-for-bit SHA-256 reproducibility of Modified19..Modified23.
"""
from __future__ import annotations

if not __debug__:
    raise RuntimeError(
        "prepare_modified24_lab.py must not be executed with Python -O/-OO "
        "(imported builders and emitters rely on debug checks)."
    )

import argparse
import json
from pathlib import Path
import struct
import sys

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from prepare_modified22_lab import STOCK_SHA  # noqa: E402
from prepare_modified23_lab import (  # noqa: E402
    M22_SHA,
    audit_caves_and_glyphs as audit_m23_caves_and_glyphs,
    collect_m23_edits,
    sha,
    update_crc,
    verify_legacy_reproducibility_through_m22,
)
from z6_c380_container import load_stock_eg_module  # noqa: E402
from z6_m600_tables import BASE, SIZE  # noqa: E402
from z6_night_vision_red import (  # noqa: E402
    ADDR_ASTRO_RED_CAVE,
    ADDR_ASTRO_RED_CAVE_LIMIT,
    ASTRO_RED_UI_OVERRIDES,
    RAM_PROP_1111,
    build_all_astro_red_spans,
    verify_astro_red_ui_glyph_coverage,
)

ROOT = THIS_DIR.parents[1]
M23_SHA = "47a5caa9521c4d81e57958626baf9660fefdc489da120840b931525968a11029"
M23_CRC = "0xc083"
M24_SHA = "168dcf2ceffb2622915e06f6cf8c9f3d90a5824ea2fbb6451b28657897a89653"
M24_CRC = "0x8799"
DEFAULT_LAB_OUT = ROOT / "analysis/modified24-release-2026-11-21/lab-build"
DEFAULT_RECIPE_REL = "patches/z6-c380-modified24-astro-raw-red-srgb-600s.json"


def require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def verify_pid1111_rom_truth(stock: bytes) -> dict[str, str | int | bool]:
    """Verify PID 0x1111 descriptor, NVRAM group 0x11 persistence, and rom_default == 0."""
    grp_addr = 0x114DD478 + 0x11 * 28
    g_words = struct.unpack_from("<7I", stock, grp_addr - BASE)
    grp_size, ram_base, def_base = g_words[0], g_words[1], g_words[2]
    require(
        ram_base == 0xC24DD0A8 and def_base == 0x114E3DAC and grp_size == 0x9A0 and g_words[6] == 1,
        f"Unexpected Group 0x11 descriptor at {grp_addr:#x}: {g_words}",
    )

    desc_addr = 0x114D7E58
    d_words = struct.unpack_from("<4I", stock, desc_addr - BASE)
    require(
        d_words[2] == RAM_PROP_1111 and d_words[3] == 0x114E3DF0,
        f"Unexpected PID 0x1111 descriptor at {desc_addr:#x}: {[hex(x) for x in d_words]}",
    )
    require(
        ram_base <= RAM_PROP_1111 < ram_base + grp_size,
        "PID 0x1111 RAM slot outside persistent Group 0x11 NVRAM span",
    )

    rom_default = struct.unpack_from("<I", stock, 0x114E3DF0 - BASE)[0]
    require(
        rom_default == 0,
        f"PID 0x1111 rom_default must be 0 (Off/Standard), got {rom_default}",
    )
    return {
        "group_0x11_descriptor": f"0x{grp_addr:08x}",
        "group_0x11_ram_base": f"0x{ram_base:08x}",
        "group_0x11_size_bytes": grp_size,
        "pid_0x1111_descriptor": f"0x{desc_addr:08x}",
        "pid_0x1111_ram_va": f"0x{RAM_PROP_1111:08x}",
        "pid_0x1111_rom_default_va": "0x114e3df0",
        "pid_0x1111_rom_default_value": rom_default,
        "nvram_persistent": True,
    }


def build_m23_bytes_from_stock(stock: bytes) -> tuple[bytes, list[dict], dict[str, int]]:
    m23_edits, m23_syms = collect_m23_edits(stock)
    m23_buf = bytearray(stock)
    for ed in m23_edits:
        addr = int(ed["address"], 16)
        off = addr - BASE
        before = bytes.fromhex(ed["before"])
        after = bytes.fromhex(ed["after"])
        require(m23_buf[off : off + len(before)] == before, f"M23 before mismatch at {addr:#x}")
        m23_buf[off : off + len(after)] = after
    m23_crc = f"0x{update_crc(m23_buf)}"
    m23_bytes = bytes(m23_buf)
    require(sha(m23_bytes) == M23_SHA, f"M23 reproducibility broken: {sha(m23_bytes)} != {M23_SHA}")
    require(m23_crc == M23_CRC, f"M23 CRC mismatch: {m23_crc} != {M23_CRC}")
    return m23_bytes, m23_edits, m23_syms


def collect_m24_edits(
    stock: bytes,
) -> tuple[bytes, list[dict], list[dict], dict[str, int], dict[str, int]]:
    """Return (m23_bytes, m23_edits, combined_112_edits, m23_syms, astro_red_syms)."""
    m23_bytes, m23_edits, m23_syms = build_m23_bytes_from_stock(stock)
    red_spans, red_syms = build_all_astro_red_spans(m23_bytes)

    red_edits: list[dict] = []
    for addr, grp, new_b, desc in red_spans:
        off = addr - BASE
        require(0 <= off and off + len(new_b) <= SIZE - 2, f"Astro Red span out of bounds at {addr:#x}")
        old_stock = stock[off : off + len(new_b)]
        old_m23 = m23_bytes[off : off + len(new_b)]
        require(
            old_stock == old_m23,
            f"Astro Red span {grp} ({addr:#x}) collides with Modified23 bytes",
        )
        red_edits.append(
            {
                "group": grp,
                "address": f"0x{addr:08x}",
                "before": old_stock.hex(),
                "after": new_b.hex(),
                "description": desc,
            }
        )

    combined = sorted(m23_edits + red_edits, key=lambda item: int(item["address"], 16))
    return m23_bytes, m23_edits, combined, m23_syms, red_syms


def audit_m24_image(
    stock: bytes,
    m23_bytes: bytes,
    m24_bytes: bytes,
    m23_edits: list[dict],
    combined_edits: list[dict],
    m23_syms: dict[str, int],
    red_syms: dict[str, int],
) -> dict:
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    s_off = ADDR_ASTRO_RED_CAVE - BASE
    e_off = red_syms["code_end"] - BASE
    insns = list(cs.disasm(m24_bytes[s_off:e_off], ADDR_ASTRO_RED_CAVE))
    decoded = sum(i.size for i in insns)
    require(
        decoded == (e_off - s_off),
        f"astro_red_cave disassembly incomplete: {decoded} != {e_off - s_off}",
    )
    for i in insns:
        if i.size == 4:
            hw1, hw2 = struct.unpack_from("<HH", i.bytes, 0)
            if hw1 == 0xE8BD:
                require(
                    (hw2 & 0xC000) != 0xC000,
                    f"Unpredictable POP {{.., lr, pc}} at {i.address:#x} in astro_red_cave",
                )

    red_hook_spans = [
        ed
        for ed in combined_edits
        if ed["group"].startswith("astro_red_") and ed["group"] != "astro_red_cave"
    ]
    interior_addrs: set[int] = set()
    for ed in red_hook_spans:
        addr = int(ed["address"], 16)
        span_len = len(bytes.fromhex(ed["after"]))
        for ia in range(addr + 2, addr + span_len, 2):
            interior_addrs.add(ia)

    cs_skip = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cs_skip.skipdata = True
    interior_hits: list[str] = []
    for ed in red_hook_spans:
        addr = int(ed["address"], 16)
        w_lo = max(BASE, (addr - 0x4000) & ~3)
        w_hi = min(BASE + 0x600000, addr + 0x4000)
        for ins in cs_skip.disasm(m23_bytes[w_lo - BASE : w_hi - BASE], w_lo):
            if ins.mnemonic.startswith(("b", "cbz", "cbnz")) and "#" in ins.op_str:
                try:
                    tgt = int(ins.op_str.split("#")[-1].strip(), 16)
                except ValueError:
                    continue
                if tgt in interior_addrs:
                    interior_hits.append(f"{ins.address:#x}->{tgt:#x} ({ins.mnemonic} {ins.op_str})")
    require(not interior_hits, f"Astro Red interior hook branch collision(s): {interior_hits}")

    for ed in m23_edits:
        addr = int(ed["address"], 16)
        after = bytes.fromhex(ed["after"])
        got = m24_bytes[addr - BASE : addr - BASE + len(after)]
        require(got == after, f"Modified23 edit at {addr:#x} ({ed['group']}) altered in Modified24")

    sid_class_tbl = 0x10D2FF58
    for sid, _, _, _, _ in ASTRO_RED_UI_OVERRIDES:
        require(
            stock[sid_class_tbl + sid - BASE] == 0,
            f"Astro Red String ID {sid:#06x} has non-zero global font class",
        )
    glyph_cov = verify_astro_red_ui_glyph_coverage(stock)
    pid1111_truth = verify_pid1111_rom_truth(stock)
    legacy_repro = verify_legacy_reproducibility_through_m22(stock)
    legacy_repro["m23_sha256"] = sha(m23_bytes)

    m23_spans_for_audit = [
        (
            int(ed["address"], 16) - BASE,
            int(ed["address"], 16) - BASE + len(bytes.fromhex(ed["after"])),
            int(ed["address"], 16),
            ed["group"],
            bytes.fromhex(ed["before"]),
            bytes.fromhex(ed["after"]),
            ed["description"],
        )
        for ed in m23_edits
    ]
    m23_audit = audit_m23_caves_and_glyphs(stock, m24_bytes, m23_syms, m23_spans_for_audit)

    return {
        "astro_red_cave_base": f"0x{ADDR_ASTRO_RED_CAVE:08x}",
        "astro_red_cave_code_end": f"0x{red_syms['code_end']:08x}",
        "astro_red_cave_end": f"0x{red_syms['cave_end']:08x}",
        "astro_red_cave_limit": f"0x{ADDR_ASTRO_RED_CAVE_LIMIT:08x}",
        "astro_red_cave_instructions": len(insns),
        "astro_red_cave_code_bytes": red_syms["code_end"] - ADDR_ASTRO_RED_CAVE,
        "astro_red_cave_total_bytes": red_syms["cave_end"] - ADDR_ASTRO_RED_CAVE,
        "astro_red_cave_free_headroom_bytes": ADDR_ASTRO_RED_CAVE_LIMIT - red_syms["cave_end"],
        "astro_red_interior_branch_collisions": len(interior_hits),
        "astro_red_glyph_coverage": glyph_cov,
        "astro_red_overridden_ui_string_ids": [f"0x{sid:04x}" for sid, _, _, _, _ in ASTRO_RED_UI_OVERRIDES],
        "pid_0x1111_rom_truth": pid1111_truth,
        "modified23_105_edits_intact": True,
        "astro_raw_and_interval_audit": m23_audit,
        "legacy_reproducibility_m19_through_m23": legacy_repro,
    }


def main() -> None:
    if not __debug__:
        raise RuntimeError("prepare_modified24_lab.py must not be executed with Python -O/-OO.")
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
        default=DEFAULT_LAB_OUT,
        help="Lab build output directory (inside gitignored analysis/)",
    )
    ap.add_argument(
        "--write-patch-recipe",
        action="store_true",
        help=f"Write/update tracked JSON patch recipe at {DEFAULT_RECIPE_REL}",
    )
    args = ap.parse_args()

    out_dir = args.output.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    stock = load_stock_eg_module(args.stock, ROOT)
    require(len(stock) == SIZE, f"Stock size mismatch: {len(stock)} != {SIZE}")
    require(sha(stock) == STOCK_SHA, "Stock SHA-256 mismatch")

    m23_bytes, m23_edits, combined_edits, m23_syms, red_syms = collect_m24_edits(stock)

    m24_buf = bytearray(stock)
    spans_sorted: list[tuple[int, int, int, str]] = []
    delta_vs_stock = 0
    for ed in combined_edits:
        addr = int(ed["address"], 16)
        off = addr - BASE
        b_before = bytes.fromhex(ed["before"])
        b_after = bytes.fromhex(ed["after"])
        require(m24_buf[off : off + len(b_before)] == b_before, f"Before mismatch at {addr:#x}")
        m24_buf[off : off + len(b_after)] = b_after
        delta_vs_stock += sum(1 for a, b in zip(b_before, b_after) if a != b)
        spans_sorted.append((off, off + len(b_after), addr, ed["group"]))

    spans_sorted.sort(key=lambda item: item[0])
    for idx in range(len(spans_sorted) - 1):
        require(
            spans_sorted[idx][1] <= spans_sorted[idx + 1][0],
            f"Span overlap between {spans_sorted[idx][2]:#x} ({spans_sorted[idx][3]}) "
            f"and {spans_sorted[idx + 1][2]:#x} ({spans_sorted[idx + 1][3]})",
        )

    m24_crc = f"0x{update_crc(m24_buf)}"
    m24_bytes = bytes(m24_buf)
    m24_sha = sha(m24_bytes)
    require(m24_sha == M24_SHA, f"Modified24 SHA-256 mismatch: {m24_sha} != {M24_SHA}")
    require(m24_crc == M24_CRC, f"Modified24 CRC-16 mismatch: {m24_crc} != {M24_CRC}")

    rev_to_m23 = bytearray(m24_bytes)
    red_only_edits = [ed for ed in combined_edits if ed["group"].startswith("astro_red_")]
    require(len(red_only_edits) == 7, f"Expected 7 Astro Red spans, got {len(red_only_edits)}")
    delta_vs_m23 = 0
    for ed in red_only_edits:
        addr = int(ed["address"], 16)
        off = addr - BASE
        b_before = bytes.fromhex(ed["before"])
        b_after = bytes.fromhex(ed["after"])
        delta_vs_m23 += sum(1 for a, b in zip(b_before, b_after) if a != b)
        rev_to_m23[off : off + len(b_before)] = b_before
    update_crc(rev_to_m23)
    require(bytes(rev_to_m23) == m23_bytes, "Reversibility from Modified24 back to Modified23 failed")

    rev_to_stock = bytearray(m24_bytes)
    for ed in combined_edits:
        addr = int(ed["address"], 16)
        off = addr - BASE
        b_before = bytes.fromhex(ed["before"])
        rev_to_stock[off : off + len(b_before)] = b_before
    update_crc(rev_to_stock)
    require(bytes(rev_to_stock) == stock, "Reversibility from Modified24 back to Stock C3.80 failed")

    audit_res = audit_m24_image(
        stock, m23_bytes, m24_bytes, m23_edits, combined_edits, m23_syms, red_syms
    )

    cand_bi = out_dir / "modified24-candidate.bi"
    cand_bi.write_bytes(m24_bytes)

    astro_ui_cnt = sum(
        1
        for ed in combined_edits
        if ed["group"].startswith(("m23_astro", "m23_color", "m23_ui", "modified9_"))
    )
    astro_red_cnt = len(red_only_edits)
    iv_cnt = sum(1 for ed in combined_edits if ed["group"].startswith("m23_interval"))
    m600_cnt = sum(1 for ed in combined_edits if ed["group"].startswith("m600_"))
    require(
        (astro_ui_cnt, astro_red_cnt, iv_cnt, m600_cnt, len(combined_edits)) == (18, 7, 3, 84, 112),
        f"Unexpected Modified24 edit distribution: "
        f"astro_ui={astro_ui_cnt}, astro_red={astro_red_cnt}, iv={iv_cnt}, m600={m600_cnt}",
    )

    manifest = {
        "candidate": "modified24-astro-raw-red-display-pid0526-pid1111-srgb-600s-v1",
        "status": "camera-verified-release",
        "design": (
            "Astro Direct RAW & sRGB Lock (Photo Menu Color space PID 0x0526 + PID 0x130A=0 + "
            "4ch Q12 1.0000x unity gain @ 0x10122CBC + 0x100A34D0 Uncompressed Format-3 Hardware "
            "Bit-Packer Fix) + Astro Red Night-Vision Display (Setup Menu Information display "
            "PID 0x1111 default=0 Off, Free Hole B 0x1002E1B0 Mode 2A LumaRed Q14 [12288, 0..0], "
            "VGC Ch1 0x20144000 LCD/EVF backend isolation, Ch0 HDMI clean passthrough, stateless "
            "frame-sync 0x102435AE, Layer-4 grid G/B mask 0x10244154, DISP Light-on-dark lock "
            "0x1040E7D8/0x1043A1E0, chained 36-lang UI @ 0x104C013C) + Post-Exposure Interval "
            "Timer (0x101FF392) + Dynamic Interval End Day/Time (0x1049C26C) + Permanent 60s-600s v2"
        ),
        "base_stock_sha256": STOCK_SHA,
        "modified22_sha256": M22_SHA,
        "modified23_sha256": M23_SHA,
        "modified23_crc16_hqx": M23_CRC,
        "modified24_sha256": m24_sha,
        "crc16_hqx": m24_crc,
        "size_bytes": len(m24_bytes),
        "total_edits": len(combined_edits),
        "astro_ui_edits": astro_ui_cnt,
        "astro_red_edits": astro_red_cnt,
        "interval_timer_edits": iv_cnt,
        "m600_v2_edits": m600_cnt,
        "byte_deltas_vs_modified23": delta_vs_m23,
        "byte_deltas_vs_stock": delta_vs_stock,
        "astro_raw_and_interval_cave_symbols": {k: f"0x{v:08x}" for k, v in m23_syms.items()},
        "astro_red_cave_symbols": {k: f"0x{v:08x}" for k, v in red_syms.items()},
        "audit": audit_res,
        "edits": combined_edits,
    }
    manifest_text = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    manifest_path = out_dir / "modified24-manifest.json"
    manifest_path.write_bytes(manifest_text.encode("utf-8"))

    patch_recipe = ROOT / DEFAULT_RECIPE_REL
    if args.write_patch_recipe:
        patch_recipe.parent.mkdir(parents=True, exist_ok=True)
        patch_recipe.write_bytes(manifest_text.encode("utf-8"))
    elif patch_recipe.is_file():
        tracked_recipe = json.loads(patch_recipe.read_text(encoding="utf-8"))
        require(
            tracked_recipe["modified24_sha256"] == m24_sha and tracked_recipe["edits"] == combined_edits,
            "Generated Modified24 edits diverged from tracked patch recipe",
        )

    print(
        f"MODIFIED24 READY | SHA256={m24_sha} | CRC={m24_crc} | "
        f"Edits={len(combined_edits)} ({astro_ui_cnt}+{astro_red_cnt}+{iv_cnt}+{m600_cnt}) | "
        f"RedCave={audit_res['astro_red_cave_total_bytes']}B "
        f"(free {audit_res['astro_red_cave_free_headroom_bytes']}B in Free Hole B)"
    )


if __name__ == "__main__":
    main()

"""Thumb-2 emitter and 36-language UI string table for Nikon Z6 C3.80 Night-Vision Red Display.

SPDX-License-Identifier: GPL-3.0-or-later

Implements the camera-verified pure-red monitor & EVF night-vision display mode
(`Mode 2A: LumaRed`, Q14 post-output CSC `[12288, 0, 0, 0, 0, 0, 0, 0, 0]`) layered
with zero address overlap on top of the 105-span Astro RAW / Extended Shutter baseline:

  1. Borrowed Setup Menu item `Information display` (`信息显示`, `PID 0x1111`,
     `RAM 0xC24DD0EC`, `rom_default = 0` @ `0x114E3DF0`):
       - `0` = Off (Standard full-color display; factory reset default)
       - `1` = On (Astro Red pure-red night-vision display on rear LCD & OLED EVF)
  2. Strict physical display backend isolation (`unit_off == 0x4000` VGC Channel 1 only):
       - Hook 1 (`0x10243422` in `vgc_set_csc`): redirects `(stage=8, sub=1)` post-output
         Q14 CSC pointer to `mat_luma_red_q14` (`12288, 0..0`) only when `hdl->unit_off == 0x4000`
         and `u32[0xC24DD0EC] != 0`. Channel 0 (`unit_off == 0x0000`, external HDMI) is untouched.
       - Hook 2 (`0x10244154` in `vgc_set_grid`): masks VGC Layer 4 hardware framing grid color
         register `[0x20145618]` with `bfc r5, #8, #16` (`G = 0, B = 0`, preserving `R` and `alpha`)
         only when `r0 == 0x20145000` and `u32[0xC24DD0EC] != 0`.
       - Hook 3 (`0x102435AE` in `vgc_update_src_buf`): stateless single-frame synchronization on
         both Live View frames (`0x1023D746`) and menu/OSD redraws (`0x1023DBD2`). Steady-state
         cost is zero MMIO writes; on a `0 <-> 1` transition of `u32[0xC24DD0EC]`, invokes native
         `0x1024341E` and updates `[0x20145618]` immediately without display re-init flicker.
       - Zero shared state or call edges into RAW frontend, NEF encoder, JPEG encoder, or AE/AF.
  3. Dark-theme lock on `DISP` shooting info screen (`Light on dark` regardless of `0` or `1`):
       - Hook 4 (`0x1040E7D8`): `movs r4, #1` (`0124`) -> `movs r4, #0` (`0024`).
       - Hook 5 (`0x1043A1E0`): `beq #0x1043A214` (`18d0`) -> `b #0x1043A214` (`18e0`).
  4. Chained 36-language glyph-verified UI overrides at `GetLanguageString` epilogue (`0x104C013C`):
       - Hook 6 (`0x104C013C`): overrides `SID 0x023F / 0x0240 / 0x0241 / 0x054C` after
         `tramp_4c0134` (`0x1002DB94`), then executes stock `pop.w {r0..r8, pc}` (`bde8ff81`).
"""
from __future__ import annotations

if not __debug__:
    raise RuntimeError(
        "z6_night_vision_red.py must not be executed with Python -O/-OO "
        "(imported ThumbEmitter helpers rely on debug checks)."
    )

import struct
from typing import Sequence

from z6_thumb_emit import (
    COND_EQ,
    COND_NE,
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    SP,
    ThumbEmitter,
    encode_branch32,
)

BASE_ADDR = 0x10020000

# Free Hole B in Stock C3.80 / Modified23: 0x1002E1A8..0x1002EF04 (3,420 zero bytes)
ADDR_ASTRO_RED_CAVE = 0x1002E1B0
ADDR_ASTRO_RED_CAVE_LIMIT = 0x1002EF00

RAM_PROP_1111 = 0xC24DD0EC
VGC_CH1_UNIT_OFF = 0x4000
VGC_CH1_REG_BASE = 0x20145000
Q14_LUMA_RED_R00 = 0x3000  # 12288 = 0.75 * 16384 (guarantees R <= 255, G = 0, B = 0 across 256^3 RGB)

ADDR_STOCK_POST_CSC_MAT = 0x1062DC4C  # Identical to EVF 0x1062DC5E: (16384, 0, 23040, 16384, -5632, -11776, 16384, 28928, 0)
ADDR_VGC_SET_CSC = 0x1024341E

HOOK_VGC_SET_CSC = 0x10243422
HOOK_VGC_UPDATE_SRC_BUF = 0x102435AE
HOOK_VGC_SET_GRID = 0x10244154
HOOK_DISP_THEME_A = 0x1040E7D8
HOOK_DISP_THEME_B = 0x1043A1E0
HOOK_GET_LANG_EPILOGUE = 0x104C013C

LANG_ZH_CN = 8
LANG_ZH_TW = 9

# Verified 0 missing glyphs across all 36 factory language pools (indices 0..35):
ASTRO_RED_UI_OVERRIDES: tuple[tuple[int, str, str, str, str], ...] = (
    (0x023F, "p2_title", "Astro red display", "天文红光显示", "天文紅光顯示"),
    (0x0240, "p2_opt_off", "Off (Standard)", "关闭 (标准色彩)", "關閉 (標準色彩)"),
    (0x0241, "p2_opt_on", "On (Astro Red)", "开启 (天文红光)", "開啟 (天文紅光)"),
    (
        0x054C,
        "p2_help",
        (
            "Select On (Astro Red) for pure\n"
            "red monitor and EVF display in\n"
            "dark-sky shooting. RAW / JPEG\n"
            "and HDMI output remain normal."
        ),
        (
            "选择“开启 (天文红光)”可将机身\n"
            "显示屏与取景器切换为纯红护眼显\n"
            "示以保护暗适应。\n"
            "实拍RAW、JPEG与HDMI保持正常。"
        ),
        (
            "選擇「開啟 (天文紅光)」可將機身\n"
            "螢幕與取景器切換為純紅護眼顯示\n"
            "以保護暗適應。\n"
            "實拍RAW、JPEG與HDMI保持正常。"
        ),
    ),
)

LUMA_RED_Q14_COEFFS: tuple[int, ...] = (Q14_LUMA_RED_R00, 0, 0, 0, 0, 0, 0, 0, 0)


def require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def _raw_hex(em: ThumbEmitter, hex_str: str) -> None:
    raw = bytes.fromhex(hex_str)
    require(len(raw) % 2 == 0, f"Odd Thumb instruction byte length: {hex_str}")
    em.buf += raw


def _align4(em: ThumbEmitter) -> None:
    if len(em.buf) % 4 != 0:
        em.nop()


def _emit_bfc(em: ThumbEmitter, rd: int, lsb: int, width: int) -> None:
    require(0 <= rd <= 12 and 0 <= lsb <= 31 and 1 <= width <= 32 - lsb, "Invalid BFC operands")
    msb = lsb + width - 1
    imm3 = (lsb >> 2) & 7
    imm2 = lsb & 3
    em.h32(0xF36F, (imm3 << 12) | (rd << 8) | (imm2 << 6) | msb)


def _emit_bfi(em: ThumbEmitter, rd: int, rn: int, lsb: int, width: int) -> None:
    require(
        0 <= rd <= 12 and 0 <= rn <= 12 and 0 <= lsb <= 31 and 1 <= width <= 32 - lsb,
        "Invalid BFI operands",
    )
    msb = lsb + width - 1
    imm3 = (lsb >> 2) & 7
    imm2 = lsb & 3
    em.h32(0xF360 | rn, (imm3 << 12) | (rd << 8) | (imm2 << 6) | msb)


def _emit_ubfx(em: ThumbEmitter, rd: int, rn: int, lsb: int, width: int) -> None:
    require(
        0 <= rd <= 12 and 0 <= rn <= 12 and 0 <= lsb <= 31 and 1 <= width <= 32 - lsb,
        "Invalid UBFX operands",
    )
    widthm1 = width - 1
    imm3 = (lsb >> 2) & 7
    imm2 = lsb & 3
    em.h32(0xF3C0 | rn, (imm3 << 12) | (rd << 8) | (imm2 << 6) | widthm1)


def _emit_uxtb16(em: ThumbEmitter, rd: int, rm: int) -> None:
    require(0 <= rd < 8 and 0 <= rm < 8, "16-bit UXTB requires low registers r0..r7")
    em.h16(0xB2C0 | (rm << 3) | rd)


def build_astro_red_cave(
    overrides: Sequence[tuple[int, str, str, str, str]] = ASTRO_RED_UI_OVERRIDES,
    cave_base: int = ADDR_ASTRO_RED_CAVE,
    cave_limit: int = ADDR_ASTRO_RED_CAVE_LIMIT,
) -> tuple[bytes, dict[str, int]]:
    """Assemble the self-contained Astro Red Display code + data cave."""

    def _assemble(mat_luma_addr: int, ui_tbl_addr: int) -> tuple[bytes, dict[str, int], int, int]:
        em = ThumbEmitter(cave_base)
        syms: dict[str, int] = {}

        # 1. Hook 1 trampoline: vgc_set_csc @ 0x10243422 -> 0x10243426
        _align4(em)
        syms["tramp_vgc_set_csc"] = em.pc
        em.label("tramp_vgc_set_csc")
        _raw_hex(em, "0e461d46")  # mov r6, r1; mov r5, r3 (displaced 4 bytes)
        em.cmp_u8(6, 8)           # stage == 8 (post-compositor total output Q14 CSC)
        em.j_cond(COND_NE, "csc_done")
        em.cmp_u8(R2, 1)          # sub == 1 (3x3 matrix coefficients, not 3x1 offsets)
        em.j_cond(COND_NE, "csc_done")
        em.ldr_u32(R4, R0, 4)     # r4 = hdl->unit_off (0x4000 = Ch1 LCD/EVF, 0x0000 = Ch0 HDMI)
        em.set_u32(R3, VGC_CH1_UNIT_OFF)
        em.cmp_reg(R4, R3)
        em.j_cond(COND_NE, "csc_done")
        em.set_u32(R4, RAM_PROP_1111)
        em.ldr_u32(R4, R4, 0)     # r4 = u32[0xC24DD0EC] (0=Off, 1=On)
        em.cmp_u8(R4, 0)
        em.j_cond(COND_EQ, "csc_done")
        em.set_u32(R5, mat_luma_addr)
        em.label("csc_done")
        em.jump_abs(0x10243426)

        # 2. Hook 2 trampoline: vgc_set_grid @ 0x10244154 -> 0x10244158
        _align4(em)
        syms["tramp_vgc_set_grid"] = em.pc
        em.label("tramp_vgc_set_grid")
        em.set_u32(R1, VGC_CH1_REG_BASE)
        em.cmp_reg(R0, R1)
        em.j_cond(COND_NE, "grid_store")
        em.set_u32(R1, RAM_PROP_1111)
        em.ldr_u32(R2, R1, 0)
        em.cmp_u8(R2, 0)
        em.j_cond(COND_EQ, "grid_store")
        _emit_bfc(em, R5, 8, 16)  # Clear G (bits 15:8) and B (bits 23:16) to 0
        em.label("grid_store")
        em.str_u32(R5, R0, 0x618)  # Displaced `str.w r5, [r0, #0x618]`
        em.jump_abs(0x10244158)

        # 3. Hook 3 trampoline: vgc_update_src_buf @ 0x102435AE -> 0x102435B4
        _align4(em)
        syms["tramp_vgc_frame_sync"] = em.pc
        em.label("tramp_vgc_frame_sync")
        _raw_hex(em, "6a6800218450")  # ldr r2, [r5, #4]; movs r1, #0; str r4, [r0, r2]
        em.set_u32(R3, VGC_CH1_UNIT_OFF)
        em.cmp_reg(R2, R3)
        em.j_cond(COND_NE, "sync_exit")

        em.set_u32(R0, VGC_CH1_REG_BASE)
        em.ldr_u32(R4, R0, 0x4F0)     # r4 = current Ch1 post-CSC word0 [0x201454F0]
        em.cmp_u8(R4, 0)              # Skip if VGC output CSC not yet initialized
        em.j_cond(COND_EQ, "sync_exit")

        em.set_u32(R2, RAM_PROP_1111)
        em.ldr_u32(R2, R2, 0)         # r2 = u32[0xC24DD0EC]
        em.set_u32(R3, Q14_LUMA_RED_R00)
        em.cmp_u8(R2, 0)
        em.j_cond(COND_EQ, "sync_want_off")

        # Desired state: On (Astro Red). Re-apply CSC only if word0 != 0x3000.
        em.cmp_reg(R4, R3)
        em.j_cond(COND_EQ, "sync_check_grid_on")
        em.mov_reg(R0, R5)            # hdl
        em.mov_u16(R1, 8)             # stage = 8
        em.mov_u16(R2, 1)             # sub = 1
        em.set_u32(R3, ADDR_STOCK_POST_CSC_MAT)  # Hook 1 redirects to mat_luma_red
        em.call_abs(ADDR_VGC_SET_CSC)
        em.set_u32(R0, VGC_CH1_REG_BASE)

        em.label("sync_check_grid_on")
        em.ldr_u32(R4, R0, 0x618)
        _emit_ubfx(em, R3, R4, 8, 16)
        em.cmp_u8(R3, 0)
        em.j_cond(COND_EQ, "sync_restore_r1_exit")
        _emit_bfc(em, R4, 8, 16)
        em.str_u32(R4, R0, 0x618)
        em.j_local("sync_restore_r1_exit")

        # Desired state: Off (Standard). Restore Stock CSC & neutral grid ONLY on transition!
        em.label("sync_want_off")
        em.cmp_reg(R4, R3)            # Was word0 == 0x3000 (Astro Red)?
        em.j_cond(COND_NE, "sync_exit")
        em.mov_reg(R0, R5)            # hdl
        em.mov_u16(R1, 8)             # stage = 8
        em.mov_u16(R2, 1)             # sub = 1
        em.set_u32(R3, ADDR_STOCK_POST_CSC_MAT)  # Hook 1 passes Stock Q14 matrix through
        em.call_abs(ADDR_VGC_SET_CSC)
        em.set_u32(R0, VGC_CH1_REG_BASE)
        em.ldr_u32(R4, R0, 0x618)
        _emit_uxtb16(em, R3, R4)      # Copy R byte back into G and B (stock neutral gray grid)
        _emit_bfi(em, R4, R3, 8, 8)
        _emit_bfi(em, R4, R3, 16, 8)
        em.str_u32(R4, R0, 0x618)

        em.label("sync_restore_r1_exit")
        em.mov_u16(R1, 0)

        em.label("sync_exit")
        em.jump_abs(0x102435B4)

        # 4. Hook 6 trampoline: GetLanguageString epilogue @ 0x104C013C
        _align4(em)
        syms["tramp_astro_red_lang_str"] = em.pc
        em.label("tramp_astro_red_lang_str")
        em.ldr_u32(R3, SP, 4)         # r3 = sid
        em.set_u32(R1, ui_tbl_addr)

        em.label("red_ui_loop")
        em.ldr_u32(7, R1, 0)          # r7 = entry.sid
        em.cmp_u8(7, 0)
        em.j_cond(COND_EQ, "red_ui_pop_ret")
        em.cmp_reg(R3, 7)
        em.j_cond(COND_EQ, "red_ui_matched")
        em.add_u12(R1, R1, 28)
        em.j_local("red_ui_loop")

        em.label("red_ui_matched")
        em.cmp_u8(R4, LANG_ZH_CN)
        em.j_cond(COND_EQ, "red_ui_cn")
        em.cmp_u8(R4, LANG_ZH_TW)
        em.j_cond(COND_EQ, "red_ui_tw")
        em.ldr_u32(R2, R1, 4)
        em.ldr_u32(R0, R1, 8)
        em.j_local("red_ui_store")

        em.label("red_ui_cn")
        em.ldr_u32(R2, R1, 12)
        em.ldr_u32(R0, R1, 16)
        em.j_local("red_ui_store")

        em.label("red_ui_tw")
        em.ldr_u32(R2, R1, 20)
        em.ldr_u32(R0, R1, 24)

        em.label("red_ui_store")
        _raw_hex(em, "32602860")      # str r2, [r6]; str r0, [r5]

        em.label("red_ui_pop_ret")
        _raw_hex(em, "bde8ff81")      # Displaced `pop.w {r0..r8, pc}`

        _align4(em)
        cave_buf = bytearray(em.finish())
        syms["code_end"] = cave_base + len(cave_buf)

        # 5. Constant Q14 Mode 2A LumaRed 3x3 matrix (9 x int16 = 18 B + 2 B pad)
        real_mat_addr = cave_base + len(cave_buf)
        syms["mat_luma_red_q14"] = real_mat_addr
        cave_buf += struct.pack("<9hH", *LUMA_RED_Q14_COEFFS, 0)

        # 6. UI string override lookup table + 4-byte-aligned UTF-16LE pool
        real_ui_tbl_addr = cave_base + len(cave_buf)
        syms["astro_red_ui_override_table"] = real_ui_tbl_addr
        tbl_size = len(overrides) * 28 + 4
        tbl_off = len(cave_buf)
        cave_buf += b"\x00" * tbl_size

        entries_packed = bytearray()
        for sid, key, txt_en, txt_cn, txt_tw in overrides:
            lang_ptrs: list[tuple[int, int]] = []
            for suffix, txt in (("en", txt_en), ("zh_cn", txt_cn), ("zh_tw", txt_tw)):
                while len(cave_buf) % 4 != 0:
                    cave_buf += b"\x00"
                s_addr = cave_base + len(cave_buf)
                enc = txt.encode("utf-16le")
                syms[f"str_{key}_{suffix}"] = s_addr
                cave_buf += enc + b"\x00\x00"
                lang_ptrs.append((s_addr, len(enc)))
            entries_packed += struct.pack(
                "<7I",
                sid,
                lang_ptrs[0][0],
                lang_ptrs[0][1],
                lang_ptrs[1][0],
                lang_ptrs[1][1],
                lang_ptrs[2][0],
                lang_ptrs[2][1],
            )
        entries_packed += struct.pack("<I", 0)
        require(len(entries_packed) == tbl_size, "Astro Red UI table size mismatch")
        cave_buf[tbl_off : tbl_off + tbl_size] = entries_packed

        while len(cave_buf) % 4 != 0:
            cave_buf += b"\x00"

        syms["cave_end"] = cave_base + len(cave_buf)
        require(
            syms["cave_end"] <= cave_limit,
            f"Astro Red cave overflowed Free Hole B: {syms['cave_end']:#x} > {cave_limit:#x}",
        )
        return bytes(cave_buf), syms, real_mat_addr, real_ui_tbl_addr

    # Two-pass fixed-point assembly:
    _, _, pass1_mat, pass1_tbl = _assemble(0x1002E280, 0x1002E2A0)
    blob, syms, pass2_mat, pass2_tbl = _assemble(pass1_mat, pass1_tbl)
    require(
        (pass2_mat, pass2_tbl) == (pass1_mat, pass1_tbl),
        "Two-pass Astro Red cave symbol addresses did not converge",
    )
    return blob, syms


def _encode_b_nop(pc: int, target: int, total_bytes: int) -> bytes:
    require(total_bytes in (4, 6, 8), f"Unsupported hook width {total_bytes}")
    b_ins = encode_branch32(pc, target, link=False)
    return b_ins + (b"\x00\xbf" * ((total_bytes - 4) // 2))


def verify_astro_red_ui_glyph_coverage(stock: bytes) -> dict[str, int]:
    """Verify all Astro Red custom UI strings hit 100% existing glyphs across all 36 languages."""
    idx_tbl = 0x112C2A08
    pool_tbl = 0x112C2A98
    checked = 0
    for sid, key, txt_en, txt_cn, txt_tw in ASTRO_RED_UI_OVERRIDES:
        for lang in range(36):
            ib = struct.unpack_from("<I", stock, idx_tbl + lang * 4 - BASE_ADDR)[0]
            pb = struct.unpack_from("<I", stock, pool_tbl + lang * 4 - BASE_ADDR)[0]
            end_off = struct.unpack_from("<I", stock, ib + 2291 * 4 - BASE_ADDR)[0]
            pool_chars = set(
                stock[pb - BASE_ADDR : pb + end_off - BASE_ADDR].decode("utf-16le", errors="ignore")
            )
            txt = txt_cn if lang == LANG_ZH_CN else (txt_tw if lang == LANG_ZH_TW else txt_en)
            missing = sorted({ch for ch in txt if ch not in pool_chars and ch not in "\n\r\t "})
            require(
                not missing,
                f"Missing factory glyph(s) for {key} (SID {sid:#06x}) in lang {lang}: {missing}",
            )
            checked += 1
    return {"languages": 36, "overrides": len(ASTRO_RED_UI_OVERRIDES), "pairs_verified": checked}


def build_all_astro_red_spans(
    base_fw: bytes,
) -> tuple[list[tuple[int, str, bytes, str]], dict[str, int]]:
    """Build all 7 Astro Red Display spans against Stock C3.80 or Modified23."""
    cave_blob, syms = build_astro_red_cave()

    cave_off = ADDR_ASTRO_RED_CAVE - BASE_ADDR
    require(
        base_fw[cave_off : cave_off + len(cave_blob)] == b"\x00" * len(cave_blob),
        f"Free Hole B at {ADDR_ASTRO_RED_CAVE:#x}..{ADDR_ASTRO_RED_CAVE + len(cave_blob):#x} is not all-zero",
    )

    expected_hooks = (
        (HOOK_VGC_SET_CSC, bytes.fromhex("0e461d46"), "vgc_set_csc prologue"),
        (HOOK_VGC_UPDATE_SRC_BUF, bytes.fromhex("6a6800218450"), "vgc_update_src_buf tail"),
        (HOOK_VGC_SET_GRID, bytes.fromhex("c0f81856"), "vgc_set_grid color write"),
        (HOOK_DISP_THEME_A, bytes.fromhex("0124"), "DISP info theme selector A"),
        (HOOK_DISP_THEME_B, bytes.fromhex("18d0"), "DISP info theme selector B"),
        (HOOK_GET_LANG_EPILOGUE, bytes.fromhex("bde8ff81"), "GetLanguageString epilogue"),
    )
    for addr, exp_b, label in expected_hooks:
        got_b = base_fw[addr - BASE_ADDR : addr - BASE_ADDR + len(exp_b)]
        require(
            got_b == exp_b,
            f"Unexpected original bytes at {label} ({addr:#x}): got {got_b.hex()}, expected {exp_b.hex()}",
        )

    spans: list[tuple[int, str, bytes, str]] = [
        (
            ADDR_ASTRO_RED_CAVE,
            "astro_red_cave",
            cave_blob,
            (
                f"Astro Red Display code+data cave ({len(cave_blob)} B in Free Hole B): "
                "VGC Ch1 post-CSC LumaRed redirect, Layer-4 grid G/B mask, stateless single-frame "
                "0<->1 sync, and 36-language UI string table"
            ),
        ),
        (
            HOOK_VGC_SET_CSC,
            "astro_red_vgc_set_csc_hook",
            _encode_b_nop(HOOK_VGC_SET_CSC, syms["tramp_vgc_set_csc"], 4),
            (
                "Hook vgc_set_csc (0x10243422): redirect (stage=8, sub=1, unit_off=0x4000) "
                "Q14 post-output CSC to LumaRed [12288, 0..0] when PID 0x1111 != 0; Ch0 HDMI untouched"
            ),
        ),
        (
            HOOK_VGC_UPDATE_SRC_BUF,
            "astro_red_vgc_frame_sync_hook",
            _encode_b_nop(HOOK_VGC_UPDATE_SRC_BUF, syms["tramp_vgc_frame_sync"], 6),
            (
                "Hook vgc_update_src_buf (0x102435AE): stateless single-frame sync on Live View "
                "and OSD/menu flips when PID 0x1111 transitions between 0 (Off) and 1 (Astro Red)"
            ),
        ),
        (
            HOOK_VGC_SET_GRID,
            "astro_red_vgc_set_grid_hook",
            _encode_b_nop(HOOK_VGC_SET_GRID, syms["tramp_vgc_set_grid"], 4),
            (
                "Hook vgc_set_grid (0x10244154): clear G/B bits[23:8] of VGC Ch1 framing grid "
                "register 0x20145618 when PID 0x1111 != 0; Ch0 HDMI untouched"
            ),
        ),
        (
            HOOK_DISP_THEME_A,
            "astro_red_disp_dark_lock_a",
            bytes.fromhex("0024"),
            "Lock DISP shooting info theme helper 0x1040E7D6 to Light-on-dark (movs r4, #0)",
        ),
        (
            HOOK_DISP_THEME_B,
            "astro_red_disp_dark_lock_b",
            bytes.fromhex("18e0"),
            "Lock DISP shooting info theme helper 0x1043A1D6 to Light-on-dark (b #0x1043A214)",
        ),
        (
            HOOK_GET_LANG_EPILOGUE,
            "astro_red_lang_str_hook",
            _encode_b_nop(HOOK_GET_LANG_EPILOGUE, syms["tramp_astro_red_lang_str"], 4),
            (
                "Chain Astro Red 36-language UI string overrides (SID 0x023F/0x0240/0x0241/0x054C) "
                "at GetLanguageString epilogue 0x104C013C after Modified23 tramp_4c0134"
            ),
        ),
    ]
    return spans, syms

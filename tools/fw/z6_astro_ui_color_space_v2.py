"""Nikon Z6 C3.80 UI-Switchable Astro RAW & Color Space Architecture (Modified19 .. Modified22).

Module Overview & Historical Builders:
  - Current Production Entry Point (`build_all_m23_astro_ui_spans`, Modified23; `build_all_m22_astro_ui_spans` retained bit-for-bit):
      1. Gates all 14 Astro RAW hooks (`fn_is_astro_r0` @ `0x1002D900`: 13 Modified13 ISP bypass hooks +
         `0x100A34D0` uncompressed format-3 hardware bit-packer fix) on genuine Photo Shooting Menu ->
         Color space `PID 0x0526` (`uint32([0xC24CDEA0]) == 1`) AND effective RAW recording `PID 0x131B`
         (`uint32([0xC24CC798]) <= 1` for RAW+JPEG / RAW).
      2. Locks Effective Color Space `PID 0x130A` (`0xC24CC74C`) to `0` (`sRGB`) by patching
         `0x1014BB28` (`bne` -> `nop`) inside `0x1014BAEA`, ensuring `Z61_` / `DSC_` filenames,
         MakerNote `0x001E = 1` (sRGB), and sRGB embedded/companion JPEGs in both modes.
      3. Leaves Photo Auto ISO sensitivity control (`PID 0x0508` @ `0x1040AD00` and `PID 0x1381`
         @ `0x1014F678`) 100% factory Stock C3.80.
      4. Overrides 5 UI String IDs (`0x03B3`, `0x03B4`, `0x03B5`, `0x082B`, `0x082C`) across all
         36 camera languages (`天文直通RAW模式` / `标准 (sRGB)` / `直通RAW (sRGB)`).
  - Legacy Reproducibility Builders (`build_all_m19_astro_ui_spans`, `build_all_m20_astro_ui_spans`,
    `build_all_m21_astro_ui_spans`):
      Retained strictly intact so historical M19/M20/M21 SHA-256 digests remain bit-for-bit
      reproducible from Stock C3.80 during regression audits (`M19/M20` read `0xC24CDDC4`;
      `M21` read `0xC24CDE28` / `PID 0x0508`). Do not use M19..M21 builders for new builds.
"""
from __future__ import annotations

if not __debug__:
    raise RuntimeError("z6_astro_ui_color_space_v2.py must not be executed with Python -O/-OO.")

import struct
from typing import Callable

from z6_m600_tables import BASE
from z6_thumb_emit import (
    COND_EQ,
    COND_LS,
    COND_NE,
    LR,
    R0,
    R1,
    R2,
    R3,
    R4,
    R7,
    SP,
    ThumbEmitter,
    encode_branch32,
)

# XIP Hole 1 layout:
#   0x1002D884..0x1002D8C7 (68B): Modified9/13 frontend unity sanitizer (astro target for 0x1017d834)
#   0x1002D900..0x1002DFFF      : Astro UI toggle cave (M20..M23 bounded < ADDR_M20_IV_CAVE 0x1002E000)
ADDR_M9_SANITIZER = 0x1002D884
M9_SANITIZER_HEX = (
    "0f4900223c2341f82320013bfbd144f200028a620a65c1f8a020c1f8c820"
    "42f22002c2f22002c1f8f4202022a1f8f8200022c1f8fc20a1f8fa200120"
    "eff042be54379ac2"
)
ADDR_M19_CAVE = 0x1002D900
ADDR_M20_IV_CAVE = 0x1002E000     # Start of m20 Interval Timer End-Time cave
ADDR_M19_CAVE_LIMIT = 0x1002EF14  # Legacy M19-only ceiling; M20..M23 pass cave_limit=ADDR_M20_IV_CAVE (0x1002E000)

# Native scalar RAM slots:
# NOTE: 0xC24CDDC4 (PID 0x0440 Focus Shift shots) and 0xC24CDE28 / 0xC24CC948 (PID 0x0508 / 0x1381 Auto ISO)
# were misidentified in M18..M21; kept ONLY for M19/M20/M21 bit-for-bit reproducibility.
RAM_PROP_0508 = 0xC24CDDC4       # Legacy M18..M20 slot (PID 0x0440; DO NOT use)
RAM_PROP_0508_REAL = 0xC24CDE28  # Legacy M21 slot (actually PID 0x0508 Auto ISO control; DO NOT use for Color space)
RAM_PROP_1381 = 0xC24CC948       # Legacy M21 slot (actually PID 0x1381 Effective Auto ISO; DO NOT use for Color space)
RAM_PROP_0526 = 0xC24CDEA0       # Genuine PID 0x0526 Photo Shooting Menu -> Color space (type=7, uint32: 0=sRGB, 1=Adobe RGB/Astro RAW)
RAM_PROP_130A = 0xC24CC74C       # Genuine PID 0x130A Effective Color Space (type=7, uint32: 0=sRGB, 1=Adobe RGB; evaluated at 0x1014BAEA)
RAM_PROP_131B = 0xC24CC798       # Genuine PID 0x131B Effective recording format (type=7, uint32: 0=RAW+JPEG, 1=RAW, >=2=TIFF/JPEG-only)

# Localized UI string IDs (verified 0 missing font glyphs across all 36 languages, font class 0):
UI_STR_ID_TITLE = 0x03B3       # Stock 'Color space' / '色空间'
UI_STR_ID_OPT_SRGB = 0x03B4    # Stock 'sRGB'
UI_STR_ID_OPT_ASTRO = 0x03B5   # Stock 'Adobe RGB'
UI_STR_ID_COLON_SRGB = 0x082B  # Stock 'sRGB:' / 'sRGB：'
UI_STR_ID_COLON_ASTRO = 0x082C # Stock 'Adobe RGB:' / 'Adobe RGB：'

LANG_ZH_CN = 8
LANG_ZH_TW = 9

TITLE_EN = "Astro RAW mode"
TITLE_ZH_CN = "天文直通模式"
TITLE_ZH_TW = "天文直通模式"

OPT_SRGB_EN = "Standard (sRGB)"
OPT_SRGB_ZH_CN = "标准 (sRGB)"
OPT_SRGB_ZH_TW = "標準 (sRGB)"

OPT_ASTRO_EN = "Astro RAW"
OPT_ASTRO_ZH_CN = "天文直通"
OPT_ASTRO_ZH_TW = "天文直通"

COLON_SRGB_EN = "Standard (sRGB):"
COLON_SRGB_ZH_CN = "标准 (sRGB)："
COLON_SRGB_ZH_TW = "標準 (sRGB)："

COLON_ASTRO_EN = "Astro RAW:"
COLON_ASTRO_ZH_CN = "天文直通："
COLON_ASTRO_ZH_TW = "天文直通："

UI_OVERRIDES: tuple[tuple[int, str, str, str, str], ...] = (
    (UI_STR_ID_TITLE, "title", TITLE_EN, TITLE_ZH_CN, TITLE_ZH_TW),
    (UI_STR_ID_OPT_SRGB, "opt_srgb", OPT_SRGB_EN, OPT_SRGB_ZH_CN, OPT_SRGB_ZH_TW),
    (UI_STR_ID_OPT_ASTRO, "opt_astro", OPT_ASTRO_EN, OPT_ASTRO_ZH_CN, OPT_ASTRO_ZH_TW),
    (UI_STR_ID_COLON_SRGB, "colon_srgb", COLON_SRGB_EN, COLON_SRGB_ZH_CN, COLON_SRGB_ZH_TW),
    (UI_STR_ID_COLON_ASTRO, "colon_astro", COLON_ASTRO_EN, COLON_ASTRO_ZH_CN, COLON_ASTRO_ZH_TW),
)

# Modified20 idiomatic Chinese "天文直通RAW模式" / "天文直通RAW" wording:
TITLE_M20_ZH_CN = "天文直通RAW模式"
TITLE_M20_ZH_TW = "天文直通 RAW 模式"
OPT_ASTRO_M20_ZH_CN = "天文直通RAW"
OPT_ASTRO_M20_ZH_TW = "天文直通 RAW"
COLON_ASTRO_M20_ZH_CN = "天文直通RAW："
COLON_ASTRO_M20_ZH_TW = "天文直通 RAW："

UI_OVERRIDES_M20: tuple[tuple[int, str, str, str, str], ...] = (
    (UI_STR_ID_TITLE, "title", TITLE_EN, TITLE_M20_ZH_CN, TITLE_M20_ZH_TW),
    (UI_STR_ID_OPT_SRGB, "opt_srgb", OPT_SRGB_EN, OPT_SRGB_ZH_CN, OPT_SRGB_ZH_TW),
    (UI_STR_ID_OPT_ASTRO, "opt_astro", OPT_ASTRO_EN, OPT_ASTRO_M20_ZH_CN, OPT_ASTRO_M20_ZH_TW),
    (UI_STR_ID_COLON_SRGB, "colon_srgb", COLON_SRGB_EN, COLON_SRGB_ZH_CN, COLON_SRGB_ZH_TW),
    (UI_STR_ID_COLON_ASTRO, "colon_astro", COLON_ASTRO_EN, COLON_ASTRO_M20_ZH_CN, COLON_ASTRO_M20_ZH_TW),
)

# Modified21 "标准 (sRGB)" / "直通RAW (sRGB)" wording (clarifies sRGB output while outside Adobe icon acts as Astro indicator):
OPT_ASTRO_M21_EN = "Astro RAW (sRGB)"
OPT_ASTRO_M21_ZH_CN = "直通RAW (sRGB)"
OPT_ASTRO_M21_ZH_TW = "直通RAW (sRGB)"
COLON_ASTRO_M21_EN = "Astro RAW (sRGB):"
COLON_ASTRO_M21_ZH_CN = "直通RAW (sRGB)："
COLON_ASTRO_M21_ZH_TW = "直通RAW (sRGB)："

UI_OVERRIDES_M21: tuple[tuple[int, str, str, str, str], ...] = (
    (UI_STR_ID_TITLE, "title", TITLE_EN, TITLE_M20_ZH_CN, TITLE_M20_ZH_TW),
    (UI_STR_ID_OPT_SRGB, "opt_srgb", OPT_SRGB_EN, OPT_SRGB_ZH_CN, OPT_SRGB_ZH_TW),
    (UI_STR_ID_OPT_ASTRO, "opt_astro", OPT_ASTRO_M21_EN, OPT_ASTRO_M21_ZH_CN, OPT_ASTRO_M21_ZH_TW),
    (UI_STR_ID_COLON_SRGB, "colon_srgb", COLON_SRGB_EN, COLON_SRGB_ZH_CN, COLON_SRGB_ZH_TW),
    (UI_STR_ID_COLON_ASTRO, "colon_astro", COLON_ASTRO_M21_EN, COLON_ASTRO_M21_ZH_CN, COLON_ASTRO_M21_ZH_TW),
)


def _raw(em: ThumbEmitter, hex_bytes: str) -> None:
    b = bytes.fromhex(hex_bytes)
    assert len(b) % 2 == 0
    em.buf += b


def _align4(em: ThumbEmitter) -> None:
    while len(em.buf) % 4 != 0:
        em.nop()


def _emit_bl_dual(
    em: ThumbEmitter,
    label_name: str,
    fn_is_astro_addr: int,
    stock_body: Callable[[ThumbEmitter], None],
    astro_body: Callable[[ThumbEmitter], None],
) -> int:
    """Emit a BL-target trampoline preserving r0..r12, sp, lr across fn_is_astro_r0."""
    _align4(em)
    entry = em.pc
    em.label(label_name)
    em.push(R0, R1, R2, LR)  # 16 bytes (8-byte stack alignment preserved)
    em.call_abs(fn_is_astro_addr)
    em.cmp_u8(R0, 1)
    em.j_cond(COND_EQ, f"{label_name}_astro")
    em.pop(R0, R1, R2, LR)
    stock_body(em)
    em.label(f"{label_name}_astro")
    em.pop(R0, R1, R2, LR)
    astro_body(em)
    return entry


def _emit_bw_dual(
    em: ThumbEmitter,
    label_name: str,
    fn_is_astro_addr: int,
    stock_body: Callable[[ThumbEmitter], None],
    astro_body: Callable[[ThumbEmitter], None],
) -> int:
    """Emit a B.W-target trampoline preserving ALL r0..r12, sp, lr, AND APSR_nzcvq flags."""
    _align4(em)
    entry = em.pc
    em.label(label_name)
    em.push(R0, R1, R2, LR)  # 16 bytes (8-byte stack alignment preserved)
    em.save_flags(R2)
    em.call_abs(fn_is_astro_addr)
    em.cmp_u8(R0, 1)
    em.j_cond(COND_EQ, f"{label_name}_astro")
    em.restore_flags(R2)
    em.pop(R0, R1, R2, LR)
    stock_body(em)
    em.label(f"{label_name}_astro")
    em.restore_flags(R2)
    em.pop(R0, R1, R2, LR)
    astro_body(em)
    return entry


def build_astro_ui_v2_cave(
    overrides: tuple[tuple[int, str, str, str, str], ...] = UI_OVERRIDES,
    cave_limit: int = ADDR_M19_CAVE_LIMIT,
    ram_prop_0508: int = RAM_PROP_0508,
    use_u32_0508: bool = False,
    include_uncomp_raw_pack_fix: bool = False,
) -> tuple[bytes, dict[str, int]]:
    """Assemble the complete astro_ui_cave blob at 0x1002D900 and return (blob, symbols)."""

    def _assemble(tbl_addr: int) -> tuple[bytes, dict[str, int], int]:
        em = ThumbEmitter(ADDR_M19_CAVE)
        syms: dict[str, int] = {}

        # 0. Shared predicate: fn_is_astro_r0() -> r0 = 1 iff ([ram_prop_0508] == 1 and uint32([0xC24CC798]) <= 1)
        syms["fn_is_astro_r0"] = em.pc
        em.label("fn_is_astro_r0")
        em.set_u32(R1, ram_prop_0508)
        if use_u32_0508:
            em.ldr_u32(R0, R1, 0)
        else:
            em.ldr_u8(R0, R1, 0)
        em.cmp_u8(R0, 1)
        em.j_cond(COND_NE, "astro_inactive")
        em.set_u32(R1, RAM_PROP_131B)
        em.ldr_u32(R0, R1, 0)
        em.cmp_u8(R0, 1)
        em.j_cond(COND_LS, "astro_active")
        em.label("astro_inactive")
        em.mov_u16(R0, 0)
        em.ret_lr()
        em.label("astro_active")
        em.mov_u16(R0, 1)
        em.ret_lr()

        fn_pred = syms["fn_is_astro_r0"]

        # 1. Site 0x100ae3a4 (fullsize_front_raw_preserve): BL #0x101ba474 vs BL #0x101ba4b6
        syms["tramp_ae3a4"] = _emit_bl_dual(
            em,
            "tramp_ae3a4",
            fn_pred,
            lambda e: e.jump_abs(0x101BA474),
            lambda e: e.jump_abs(0x101BA4B6),
        )

        # 2. Site 0x100c2654 (modified1_dark_preserve): BL #0x100c2b22 vs mov.w r0, #0; bx lr
        syms["tramp_c2654"] = _emit_bl_dual(
            em,
            "tramp_c2654",
            fn_pred,
            lambda e: e.jump_abs(0x100C2B22),
            lambda e: (_raw(e, "4ff00000"), e.ret_lr()),
        )

        # 3. Site 0x100c267c (modified1_dark_preserve): BL #0x100c2b0a vs mov.w r0, #2; bx lr
        syms["tramp_c267c"] = _emit_bl_dual(
            em,
            "tramp_c267c",
            fn_pred,
            lambda e: e.jump_abs(0x100C2B0A),
            lambda e: (_raw(e, "4ff00200"), e.ret_lr()),
        )

        # 4. Site 0x100c2690 (modified1_dark_preserve): ldrb.w r1, [r0, #0x81a] vs mov.w r1, #2 -> 0x100c2694
        syms["tramp_c2690"] = _emit_bw_dual(
            em,
            "tramp_c2690",
            fn_pred,
            lambda e: (_raw(e, "90f81a18"), e.jump_abs(0x100C2694)),
            lambda e: (_raw(e, "4ff00201"), e.jump_abs(0x100C2694)),
        )

        # 5. Site 0x100c28b2 (modified2_vignette_neutral): strb.w r0, [r4, #0x62] vs strb.w sb, [r4, #0x62] -> 0x100c28b6
        syms["tramp_c28b2"] = _emit_bw_dual(
            em,
            "tramp_c28b2",
            fn_pred,
            lambda e: (_raw(e, "84f86200"), e.jump_abs(0x100C28B6)),
            lambda e: (_raw(e, "84f86290"), e.jump_abs(0x100C28B6)),
        )

        # 6. Site 0x100c28c8 (modified2_vignette_neutral): strb.w sb, [r4, #0x63] vs strb.w r0, [r4, #0x63] -> 0x100c28cc
        syms["tramp_c28c8"] = _emit_bw_dual(
            em,
            "tramp_c28c8",
            fn_pred,
            lambda e: (_raw(e, "84f86390"), e.jump_abs(0x100C28CC)),
            lambda e: (_raw(e, "84f86300"), e.jump_abs(0x100C28CC)),
        )

        # 7. Site 0x100c2964 (modified2_vignette_neutral): ldrb.w r0, [r0, #0x25f] vs mov.w r0, #1 -> 0x100c2968
        syms["tramp_c2964"] = _emit_bw_dual(
            em,
            "tramp_c2964",
            fn_pred,
            lambda e: (_raw(e, "90f85f02"), e.jump_abs(0x100C2968)),
            lambda e: (_raw(e, "4ff00100"), e.jump_abs(0x100C2968)),
        )

        # 8. Site 0x1011e2dc (modified13_frontend_cal33_unity_group4):
        syms["tramp_11e2dc"] = _emit_bw_dual(
            em,
            "tramp_11e2dc",
            fn_pred,
            lambda e: (_raw(e, "3e46"), e.h16(0xB108), e.jump_abs(0x1011E322), e.jump_abs(0x1011E2E0)),
            lambda e: (_raw(e, "3e46"), e.h16(0xB108), e.jump_abs(0x1011E30C), e.jump_abs(0x1011E2E0)),
        )

        # 9. Site 0x10122cbc (modified12_frontend_digital_gain_unity_safe):
        syms["tramp_122cbc"] = _emit_bw_dual(
            em,
            "tramp_122cbc",
            fn_pred,
            lambda e: (_raw(e, "08681860"), e.jump_abs(0x10122CC0)),
            lambda e: (_raw(e, "41f20000186058609860d860"), e.jump_abs(0x10122CCC)),
        )

        # 10. Site 0x1017d834 (modified9_frontend_unity_sanitizer):
        syms["tramp_17d834"] = _emit_bl_dual(
            em,
            "tramp_17d834",
            fn_pred,
            lambda e: (_raw(e, "0120"), e.jump_abs(0x1011D548)),
            lambda e: e.jump_abs(ADDR_M9_SANITIZER),
        )

        # 11. Site 0x10197418 (modified3_spatial17_neutral):
        syms["tramp_197418"] = _emit_bw_dual(
            em,
            "tramp_197418",
            fn_pred,
            lambda e: (_raw(e, "c069"), e.h16(0xB109), e.jump_abs(0x1019741C), e.jump_abs(0x10197434)),
            lambda e: (_raw(e, "c069"), e.jump_abs(0x1019743A)),
        )

        # 12. Site 0x10197866 (modified3_spatial17_neutral):
        syms["tramp_197866"] = _emit_bw_dual(
            em,
            "tramp_197866",
            fn_pred,
            lambda e: (_raw(e, "0a774e77"), e.jump_abs(0x10197880)),
            lambda e: (_raw(e, "0a774a77"), e.jump_abs(0x10197880)),
        )

        # 13. Site 0x10197874 (modified3_spatial17_neutral):
        syms["tramp_197874"] = _emit_bw_dual(
            em,
            "tramp_197874",
            fn_pred,
            lambda e: (_raw(e, "006940784877"), e.jump_abs(0x1019787A)),
            lambda e: (_raw(e, "006900204877"), e.jump_abs(0x1019787A)),
        )

        if include_uncomp_raw_pack_fix:
            # 14. Site 0x100a34d0 (m23_astro_gate_uncomp_raw_pack):
            #     Uncompressed RAW encoder 0x100A3480 enters 0x100A34D0 when input descriptor format == 3
            #     (16-bit LE unpacked, selected on >= 1s / wide=1 or slow_1af0!=0 captures).
            #     Stock sets [r4+2]=0, [r4+3]=0 (r2=0), writing 48,997,120 B 16-bit LE that overflows
            #     the 42,920,960 B packed-14 RAW slot and collides with embedded preview JPEGs.
            #     In Astro mode, keep input [r4+2]=0 (16-bit LE) and set output [r4+3] to 1 (14-bit packed)
            #     or 2 (12-bit packed, when [r5+1]==2) with lut_ptr=0, preserving r0..r12, sp, lr, and APSR.
            _align4(em)
            syms["tramp_a34d0"] = em.pc
            em.label("tramp_a34d0")
            em.push(R0, R1, R2, LR)
            em.save_flags(R2)
            em.call_abs(fn_pred)
            em.cmp_u8(R0, 1)
            em.j_cond(COND_EQ, "tramp_a34d0_astro")
            em.restore_flags(R2)
            em.pop(R0, R1, R2, LR)
            _raw(em, "a270e270")  # strb r2, [r4, #2]; strb r2, [r4, #3]
            em.jump_abs(0x100A34AA)
            em.label("tramp_a34d0_astro")
            em.mov_u16(R0, 0)
            _raw(em, "a070")      # strb r0, [r4, #2]  (0 = 16-bit LE input)
            _raw(em, "6978")      # ldrb r1, [r5, #1]  (target NEF format: 4=14-bit, 2=12-bit)
            em.cmp_u8(R1, 2)
            em.j_cond(COND_EQ, "tramp_a34d0_store")
            em.mov_u16(R1, 1)     # movs r1, #1        (1 = 14-bit packed output)
            em.label("tramp_a34d0_store")
            _raw(em, "e170")      # strb r1, [r4, #3]
            em.restore_flags(R2)
            em.pop(R0, R1, R2, LR)
            em.jump_abs(0x100A34AA)

        # 15. Table-driven UI String override trampoline for 0x104C0134:
        #     Hooked at 0x104C0134 inside GetLanguageString (0x104C0104):
        #       r4 = language index (8=ZH_CN, 9=ZH_TW, others=EN/default)
        #       r6 = out_ptr, r5 = out_len, [sp, #4] = String ID
        #       0x104C013C pops {r0..r8, pc}, so r1, r3, r7 are dead scratch registers.
        _align4(em)
        syms["tramp_4c0134"] = em.pc
        em.label("tramp_4c0134")
        _raw(em, "1a18")  # adds r2, r3, r0 (stock ptr)
        _raw(em, "081a")  # subs r0, r1, r0 (stock byte_len)
        em.ldr_u32(R3, SP, 4)
        em.set_u32(R1, tbl_addr)

        em.label("ui_tbl_loop")
        em.ldr_u32(R7, R1, 0)
        em.cmp_u8(R7, 0)
        em.j_cond(COND_EQ, "ui_commit")
        em.cmp_reg(R3, R7)
        em.j_cond(COND_EQ, "ui_matched")
        em.add_u12(R1, R1, 28)
        em.j_local("ui_tbl_loop")

        em.label("ui_matched")
        em.cmp_u8(R4, LANG_ZH_CN)
        em.j_cond(COND_EQ, "ui_pick_cn")
        em.cmp_u8(R4, LANG_ZH_TW)
        em.j_cond(COND_EQ, "ui_pick_tw")
        em.ldr_u32(R2, R1, 4)
        em.ldr_u32(R0, R1, 8)
        em.j_local("ui_commit")

        em.label("ui_pick_cn")
        em.ldr_u32(R2, R1, 12)
        em.ldr_u32(R0, R1, 16)
        em.j_local("ui_commit")

        em.label("ui_pick_tw")
        em.ldr_u32(R2, R1, 20)
        em.ldr_u32(R0, R1, 24)

        em.label("ui_commit")
        _raw(em, "3260")  # str r2, [r6]
        _raw(em, "2860")  # str r0, [r5]
        em.jump_abs(0x104C013C)

        _align4(em)
        code_bytes = bytearray(em.finish())
        real_tbl_addr = ADDR_M19_CAVE + len(code_bytes)
        syms["code_end"] = real_tbl_addr
        syms["ui_override_table"] = real_tbl_addr

        # Reserve (len(overrides) * 28 + 4) bytes for the lookup table + sentinel word 0:
        tbl_size = len(overrides) * 28 + 4
        tbl_off = len(code_bytes)
        code_bytes += b"\x00" * tbl_size

        # Emit UTF-16LE strings (4-byte aligned + defensive UTF-16 NUL 0x0000) and populate table:
        entries_packed = bytearray()
        for sid, key, txt_en, txt_cn, txt_tw in overrides:
            lang_ptrs: list[tuple[int, int]] = []
            for suffix, txt in (("en", txt_en), ("zh_cn", txt_cn), ("zh_tw", txt_tw)):
                while len(code_bytes) % 4 != 0:
                    code_bytes += b"\x00"
                s_addr = ADDR_M19_CAVE + len(code_bytes)
                enc = txt.encode("utf-16le")
                syms[f"str_{key}_{suffix}"] = s_addr
                code_bytes += enc + b"\x00\x00"
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
        entries_packed += struct.pack("<I", 0)  # Sentinel sid = 0
        assert len(entries_packed) == tbl_size
        code_bytes[tbl_off : tbl_off + tbl_size] = entries_packed

        while len(code_bytes) % 4 != 0:
            code_bytes += b"\x00"

        syms["cave_end"] = ADDR_M19_CAVE + len(code_bytes)
        assert syms["cave_end"] <= cave_limit, (
            f"astro ui cave overflowed limit: {syms['cave_end']:#x} > {cave_limit:#x}"
        )
        return bytes(code_bytes), syms, real_tbl_addr

    # Pass 1 with dummy address in 0x1002Dxxx (> 0xFF low16 so set_u32 emits identical movw+movt):
    _, _, computed_tbl = _assemble(0x1002DC00)
    # Pass 2 with exact table address; assert fixed-point convergence:
    blob, syms, check_tbl = _assemble(computed_tbl)
    assert check_tbl == computed_tbl, "Two-pass table address layout did not converge!"
    return blob, syms


def build_all_m19_astro_ui_spans(
    stock: bytes,
    overrides: tuple[tuple[int, str, str, str, str], ...] = UI_OVERRIDES,
    cave_limit: int = ADDR_M19_CAVE_LIMIT,
    tag_prefix: str = "m19",
    ram_prop_0508: int = RAM_PROP_0508,
    use_u32_0508: bool = False,
    lock_1381_srgb: bool = False,
    include_legacy_0508_lock: bool = True,
    lock_130a_srgb: bool = False,
    include_uncomp_raw_pack_fix: bool = False,
) -> tuple[list[tuple[int, str, bytes, str]], dict[str, int]]:
    """Build all Astro UI v2/v3/v4/v5 (full Color space title + sRGB/Astro labels + sRGB lock) spans."""
    cave_blob, syms = build_astro_ui_v2_cave(
        overrides=overrides,
        cave_limit=cave_limit,
        ram_prop_0508=ram_prop_0508,
        use_u32_0508=use_u32_0508,
        include_uncomp_raw_pack_fix=include_uncomp_raw_pack_fix,
    )
    m9_bytes = bytes.fromhex(M9_SANITIZER_HEX)
    assert len(m9_bytes) == 68

    def _b_nop(pc: int, target: int, total_bytes: int, link: bool = False) -> bytes:
        assert total_bytes >= 4 and total_bytes % 2 == 0
        b = encode_branch32(pc, target, link=link)
        return b + b"\x00\xbf" * ((total_bytes - 4) // 2)

    expected_anchors: list[tuple[int, str, str, bytes, str]] = [
        (
            ADDR_M9_SANITIZER,
            "modified9_frontend_unity_sanitizer",
            "00" * 68,
            m9_bytes,
            "Frontend 2D polynomial zeroing + unity 16384 DC gains + tail-call 0x1011d548(1) (invoked only in Astro mode)",
        ),
        (
            ADDR_M19_CAVE,
            "m19_astro_ui_cave",
            "00" * len(cave_blob),
            cave_blob,
            f"Modified19 dynamic Astro gate ([0x{ram_prop_0508:08X}]==1 && [0xC24CC798]<=1), {14 if include_uncomp_raw_pack_fix else 13} dual-path RAW trampolines, and 5x36-lang Color Space UI string overrides ({len(cave_blob)}B)",
        ),
        (
            0x100AE3A4,
            "m19_astro_gate_fullsize_raw",
            "0cf166f8",
            _b_nop(0x100AE3A4, syms["tramp_ae3a4"], 4, link=True),
            "Gate 0x100ae3a4: BL 0x101ba4b6 (preserve full-size front RAW) in Astro mode vs BL 0x101ba474 in Stock mode",
        ),
        (
            0x100C2654,
            "m19_astro_gate_dark_preserve",
            "00f065fa",
            _b_nop(0x100C2654, syms["tramp_c2654"], 4, link=True),
            "Gate 0x100c2654: mov.w r0, #0 in Astro mode vs BL 0x100c2b22 in Stock mode",
        ),
        (
            0x100C267C,
            "m19_astro_gate_dark_preserve",
            "00f045fa",
            _b_nop(0x100C267C, syms["tramp_c267c"], 4, link=True),
            "Gate 0x100c267c: mov.w r0, #2 in Astro mode vs BL 0x100c2b0a in Stock mode",
        ),
        (
            0x100C2690,
            "m19_astro_gate_dark_preserve",
            "90f81a18",
            _b_nop(0x100C2690, syms["tramp_c2690"], 4, link=False),
            "Gate 0x100c2690: mov.w r1, #2 in Astro mode vs ldrb.w r1, [r0, #0x81a] in Stock mode",
        ),
        (
            0x100C28B2,
            "m19_astro_gate_vignette_neutral",
            "84f86200",
            _b_nop(0x100C28B2, syms["tramp_c28b2"], 4, link=False),
            "Gate 0x100c28b2: strb.w sb, [r4, #0x62] in Astro mode vs strb.w r0, [r4, #0x62] in Stock mode",
        ),
        (
            0x100C28C8,
            "m19_astro_gate_vignette_neutral",
            "84f86390",
            _b_nop(0x100C28C8, syms["tramp_c28c8"], 4, link=False),
            "Gate 0x100c28c8: strb.w r0, [r4, #0x63] in Astro mode vs strb.w sb, [r4, #0x63] in Stock mode",
        ),
        (
            0x100C2964,
            "m19_astro_gate_vignette_neutral",
            "90f85f02",
            _b_nop(0x100C2964, syms["tramp_c2964"], 4, link=False),
            "Gate 0x100c2964: mov.w r0, #1 in Astro mode vs ldrb.w r0, [r0, #0x25f] in Stock mode",
        ),
        (
            0x1011E2DC,
            "m19_astro_gate_cal33_group4",
            "3e4600bb",
            _b_nop(0x1011E2DC, syms["tramp_11e2dc"], 4, link=False),
            "Gate 0x1011e2dc: static CAL33 factory unity Group 4 (0x1011e30c) in Astro mode vs Group 0 (0x1011e322) in Stock mode",
        ),
        (
            0x10122CBC,
            "m19_astro_gate_digital_gain_unity",
            "08681860",
            _b_nop(0x10122CBC, syms["tramp_122cbc"], 4, link=False),
            "Gate 0x10122cbc: unity 4096x4 frontend digital gain in Astro mode vs factory gain table copy in Stock mode",
        ),
        (
            0x1017D834,
            "m19_astro_gate_frontend_sanitizer",
            "01209ff787fe",
            _b_nop(0x1017D834, syms["tramp_17d834"], 6, link=True),
            "Gate 0x1017d834: BL 0x1002d884 frontend 2D polynomial sanitizer in Astro mode vs Stock movs r0,#1; BL 0x1011d548",
        ),
        (
            0x10197418,
            "m19_astro_gate_spatial17_neutral",
            "c06959b1",
            _b_nop(0x10197418, syms["tramp_197418"], 4, link=False),
            "Gate 0x10197418: bypass spatial17 table loader to 0x1019743a in Astro mode vs Stock cbz r1, #0x10197434",
        ),
        (
            0x10197866,
            "m19_astro_gate_spatial17_neutral",
            "0a774e7709e0",
            _b_nop(0x10197866, syms["tramp_197866"], 6, link=False),
            "Gate 0x10197866: strb r2, [r1, #0x1d] in Astro mode vs Stock strb r6, [r1, #0x1d]",
        ),
        (
            0x10197874,
            "m19_astro_gate_spatial17_neutral",
            "006940784877",
            _b_nop(0x10197874, syms["tramp_197874"], 6, link=False),
            "Gate 0x10197874: movs r0, #0 -> [r1, #0x1d] in Astro mode vs Stock ldrb r0, [r0, #1]",
        ),
        (
            0x104C0134,
            "m19_ui_string_override",
            "1a183260081a2860",
            _b_nop(0x104C0134, syms["tramp_4c0134"], 8, link=False),
            "Override all 5 Color Space UI string IDs (0x03B3 title, 0x03B4 Standard sRGB, 0x03B5 Astro RAW, 0x082B/0x082C colon labels) across all 36 languages",
        ),
    ]
    if include_legacy_0508_lock:
        expected_anchors.append(
            (
                0x1040AD00,
                "m19_color_space_lock_srgb",
                "10b5002440f2",
                bytes.fromhex("0120704700bf"),
                "Lock IsColorSpace_sRGB() to 1 (movs r0, #1; bx lr) so EXIF ColorSpace and file prefix DSC_xxxx remain standard sRGB",
            )
        )
    if lock_1381_srgb:
        expected_anchors.append(
            (
                0x1014F678,
                "m19_color_space_eval_lock_srgb",
                "00d1",
                bytes.fromhex("00bf"),
                "NOP bne #0x1014f67c in 0x1014F638 so Photo-mode Effective Color Space 0x1381 ([0xC24CC948]) is locked to 0 (sRGB) for JPEG/EXIF/DCF while 0x0508 ([0xC24CDE28]) stays 0/1",
            )
        )
    if lock_130a_srgb:
        expected_anchors.append(
            (
                0x1014BB28,
                "m19_color_space_eval_lock_srgb",
                "01d1",
                bytes.fromhex("00bf"),
                "NOP bne #0x1014bb2e in 0x1014BAEA so Effective Color Space PID 0x130A ([0xC24CC74C]) is locked to 0 (sRGB: Z61_/DSC_ DCF prefix, MakerNote ColorSpace=1, sRGB JPEG/LiveView) while Color space menu PID 0x0526 ([0xC24CDEA0]) stays 0/1",
            )
        )
    if include_uncomp_raw_pack_fix:
        expected_anchors.append(
            (
                0x100A34D0,
                "m19_astro_gate_uncomp_raw_pack",
                "a270e270",
                _b_nop(0x100A34D0, syms["tramp_a34d0"], 4, link=False),
                "Gate 0x100a34d0 in 0x100A3480: hardware-pack format-3 (16-bit LE) input to target 14-bit/12-bit packed NEF output ([r4+2]=0, [r4+3]=1/2, lut=0) in Astro mode vs Stock [r4+2]=0, [r4+3]=0",
            )
        )

    spans: list[tuple[int, str, bytes, str]] = []
    for addr, grp, expected_hex, new_bytes, desc in expected_anchors:
        if tag_prefix != "m19" and grp.startswith("m19_"):
            grp = f"{tag_prefix}_{grp[4:]}"
        if tag_prefix == "m20":
            desc = desc.replace("Modified19", "Modified20")
        elif tag_prefix == "m21":
            desc = desc.replace("Modified19", "Modified21")
        elif tag_prefix == "m22":
            desc = desc.replace("Modified19", "Modified22")
        elif tag_prefix == "m23":
            desc = desc.replace("Modified19", "Modified23")
        off = addr - BASE
        expected_bytes = bytes.fromhex(expected_hex)
        actual_bytes = stock[off : off + len(expected_bytes)]
        assert actual_bytes == expected_bytes, (
            f"Anchor mismatch at 0x{addr:08x} ({grp}): expected {expected_hex}, found {actual_bytes.hex()}"
        )
        spans.append((addr, grp, new_bytes, desc))

    spans.sort(key=lambda s: s[0])
    return spans, syms


def build_all_m20_astro_ui_spans(
    stock: bytes,
) -> tuple[list[tuple[int, str, bytes, str]], dict[str, int]]:
    """Build Modified20 Astro RAW UI spans ('天文直通RAW模式' / '天文直通RAW') bounded below 0x1002E000."""
    return build_all_m19_astro_ui_spans(
        stock,
        overrides=UI_OVERRIDES_M20,
        cave_limit=ADDR_M20_IV_CAVE,
        tag_prefix="m20",
    )


def build_all_m21_astro_ui_spans(
    stock: bytes,
) -> tuple[list[tuple[int, str, bytes, str]], dict[str, int]]:
    """Build Modified21 Astro RAW UI spans (fixed 0xC24CDE28 gate + 0x1381 sRGB lock + '直通RAW (sRGB)')."""
    return build_all_m19_astro_ui_spans(
        stock,
        overrides=UI_OVERRIDES_M21,
        cave_limit=ADDR_M20_IV_CAVE,
        tag_prefix="m21",
        ram_prop_0508=RAM_PROP_0508_REAL,
        use_u32_0508=True,
        lock_1381_srgb=True,
    )


def build_all_m22_astro_ui_spans(
    stock: bytes,
) -> tuple[list[tuple[int, str, bytes, str]], dict[str, int]]:
    """Build Modified22 Astro RAW UI spans (genuine PID 0x0526 0xC24CDEA0 gate + PID 0x130A 0x1014BB28 sRGB lock + restored Auto ISO 0x0508/0x1381)."""
    return build_all_m19_astro_ui_spans(
        stock,
        overrides=UI_OVERRIDES_M21,
        cave_limit=ADDR_M20_IV_CAVE,
        tag_prefix="m22",
        ram_prop_0508=RAM_PROP_0526,
        use_u32_0508=True,
        lock_1381_srgb=False,
        include_legacy_0508_lock=False,
        lock_130a_srgb=True,
    )


def build_all_m23_astro_ui_spans(
    stock: bytes,
) -> tuple[list[tuple[int, str, bytes, str]], dict[str, int]]:
    """Build Modified23 Astro RAW UI spans (M22 PID 0x0526 gate + PID 0x130A sRGB lock + 0x100A34D0 long-exposure uncompressed format-3 hardware bit-packer fix)."""
    return build_all_m19_astro_ui_spans(
        stock,
        overrides=UI_OVERRIDES_M21,
        cave_limit=ADDR_M20_IV_CAVE,
        tag_prefix="m23",
        ram_prop_0508=RAM_PROP_0526,
        use_u32_0508=True,
        lock_1381_srgb=False,
        include_legacy_0508_lock=False,
        lock_130a_srgb=True,
        include_uncomp_raw_pack_fix=True,
    )

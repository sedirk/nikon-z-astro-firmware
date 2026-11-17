"""Nikon Z6 C3.80 Modified16 UI-Switchable Astro Lossless RAW + Lossless Coercion Builder.

Design A3:
  Repurposes the 2nd option (val == 2, stock 'Compressed' lossy RAW) inside
  Photo Shooting Menu -> NEF (RAW) recording -> NEF (RAW) compression (property 0x0506):
    - val == 1 ('无损压缩' / 'Lossless compressed'):
        100% Stock C3.80 RAW processing path + standard Lossless NEF compression.
    - val == 2 ('天文无损' / '天文無損' / 'Astro Lossless'):
        100% Modified13 14-site Astro RAW path (gated dynamically on effective
        NEF compression 0x1315 == 2 at 0xC24CC77C AND effective RAW recording
        0x131b <= 1 at 0xC24CC798) + forced genuine Lossless NEF compression
        (lossless bitstream buffer allocation, lossless hardware codec [0xC23234C8]=1,
        lossless EXIF MakerNote 0x0093 NEFCompression=3, lossless remaining-shots
        capacity 0x40000318=1).
    - val == 0 ('未压缩' / 'Uncompressed'):
        100% Stock C3.80 RAW processing path + standard Uncompressed NEF.

Safety Invariants:
  1. Medium/Small RAW (0x0505 != 0) natively sets 0x1315 = 1 in 0x1014a852,
     automatically bypassing Astro RAW and using Stock resize/compression.
  2. JPEG-only quality modes (0x131b >= 2, including HDR/special forced JPEG)
     are explicitly excluded by checking uint32([0xC24CC798]) <= 1, so residual
     0x0506=2 / 0x1315=2 never activates Astro front/back RAW hooks during JPEG-only capture.
  3. All non-BL hook trampolines save & restore {r0, r1, r2, lr} (16B, 8-byte AAPCS
     stack-aligned) AND APSR_nzcvq flags before executing Stock or Astro instructions.
  4. Playback / in-camera Retouch NEF decoders (0x102dd092 / 0x102dd14c) are untouched,
     preserving full playback compatibility with existing Lossy Compressed NEFs on card.
  5. U1/U2/U3 and Save/load settings (0x103c68ce -> 0x10409234) read raw 0x0506 directly,
     preserving 'Astro Lossless' across power cycles and user settings banks.
"""
from __future__ import annotations
import struct
from typing import Callable

from z6_m600_tables import BASE
from z6_thumb_emit import (
    COND_EQ,
    COND_LS,
    COND_NE,
    LR,
    PC,
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    SP,
    ThumbEmitter,
    encode_branch32,
)

# XIP Hole 1 layout:
#   0x1002D884..0x1002D8C7 (68B): Modified9/13 frontend unity sanitizer (astro target for 0x1017d834)
#   0x1002D900..0x1002EEFF      : Modified16 Astro UI toggle cave (< ADDR_PTP_HDR 0x1002EF14)
ADDR_M9_SANITIZER = 0x1002D884
M9_SANITIZER_HEX = (
    "0f4900223c2341f82320013bfbd144f200028a620a65c1f8a020c1f8c820"
    "42f22002c2f22002c1f8f4202022a1f8f8200022c1f8fc20a1f8fa200120"
    "eff042be54379ac2"
)
ADDR_M16_CAVE = 0x1002D900
ADDR_M16_CAVE_LIMIT = 0x1002EF14  # Start of m600_v2 ADDR_PTP_HDR

# Native scalar / derived property RAM slots (from 0x114D4FF8 & 0x1014a852):
RAM_PROP_0506 = 0xC24CDE20  # Menu NEF compression (1=Lossless, 2=Astro Lossless, 0=Uncompressed)
RAM_PROP_1315 = 0xC24CC77C  # Effective NEF compression ((0x0505==0) ? 0x0506 : 1)
RAM_PROP_131B = 0xC24CC798  # Effective recording format (0=RAW, 1=RAW+JPEG, >=2=JPEG-only); == RAM_PROP_1315 + 0x1C

# Localized UI strings (UTF-16LE, verified 0/36 missing font glyphs across all 36 languages):
UI_STR_ID_LABEL = 0x0364
UI_STR_ID_HELP = 0x057E
LANG_ZH_CN = 8
LANG_ZH_TW = 9

LABEL_EN = "Astro Lossless"
LABEL_ZH_CN = "天文无损"
LABEL_ZH_TW = "天文無損"

HELP_EN = (
    "Astro Lossless: NEF (RAW) images\n"
    "are recorded using lossless\n"
    "compression. Dark and spatial\n"
    "RAW calibration are bypassed."
)
HELP_ZH_CN = (
    "天文无损：关闭机内RAW暗电流裁切\n"
    "与空间彩圈校正，并以可逆无损压\n"
    "缩记录NEF(RAW)图像。"
)
HELP_ZH_TW = (
    "天文無損：關閉機內RAW暗場裁切與\n"
    "空間彩圈校正，並以可復原的無損\n"
    "壓縮記錄NEF(RAW)影像。"
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


def build_astro_ui_cave() -> tuple[bytes, dict[str, int]]:
    """Assemble the complete m16_astro_ui_cave blob at 0x1002D900 and return (blob, symbols)."""
    # First reserve deterministic UTF-16LE string block offsets at the end via two-pass sizing,
    # or place UTF-16LE strings at the start (after an unconditional jump? No: placing strings
    # at the very beginning after a 4-byte aligned header or placing strings FIRST before code?
    # Even cleaner: place strings FIRST? Wait: cave is pure helper functions/trampolines entered
    # via explicit symbol addresses returned in `syms`! Nothing jumps blindly to 0x1002D900 except
    # callers of `syms["fn_is_astro_r0"]`! Still, putting `fn_is_astro_r0` first at 0x1002D900
    # and strings at a two-pass resolved offset is super clean so Capstone disassembles code
    # cleanly from 0x1002D900..code_end and data from data_start..cave_end!)
    str_items = [
        ("str_lbl_en", LABEL_EN),
        ("str_lbl_zh_cn", LABEL_ZH_CN),
        ("str_lbl_zh_tw", LABEL_ZH_TW),
        ("str_help_en", HELP_EN),
        ("str_help_zh_cn", HELP_ZH_CN),
        ("str_help_zh_tw", HELP_ZH_TW),
    ]

    def _assemble(str_addrs: dict[str, tuple[int, int]]) -> tuple[bytes, dict[str, int]]:
        em = ThumbEmitter(ADDR_M16_CAVE)
        syms: dict[str, int] = {}

        # 0. Shared predicate: fn_is_astro_r0() -> r0 = 1 iff ([0xC24CC77C] == 2 and uint32([0xC24CC798]) <= 1)
        syms["fn_is_astro_r0"] = em.pc
        em.label("fn_is_astro_r0")
        em.set_u32(R1, RAM_PROP_1315)
        em.ldr_u32(R0, R1, 0)
        em.cmp_u8(R0, 2)
        em.j_cond(COND_NE, "astro_inactive")
        em.ldr_u32(R0, R1, RAM_PROP_131B - RAM_PROP_1315)  # +0x1C -> 0xC24CC798
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
        #    Stock: mov r6, r7; cbnz r0, #0x1011e322 (fallthrough 0x1011e2e0)
        #    Astro: mov r6, r7; cbnz r0, #0x1011e30c (fallthrough 0x1011e2e0)
        #    Note: cbz r0, +6 (0xB108) skips a 4-byte b.w without modifying APSR flags!
        syms["tramp_11e2dc"] = _emit_bw_dual(
            em,
            "tramp_11e2dc",
            fn_pred,
            lambda e: (_raw(e, "3e46"), e.h16(0xB108), e.jump_abs(0x1011E322), e.jump_abs(0x1011E2E0)),
            lambda e: (_raw(e, "3e46"), e.h16(0xB108), e.jump_abs(0x1011E30C), e.jump_abs(0x1011E2E0)),
        )

        # 9. Site 0x10122cbc (modified12_frontend_digital_gain_unity_safe):
        #    0x10122cba (cbz r1, #0x10122cce) is untouched.
        #    Stock: ldr r0, [r1]; str r0, [r3] -> 0x10122cc0
        #    Astro: movw r0, #0x1000; str r0, [r3]; str r0, [r3, #4]; str r0, [r3, #8]; str r0, [r3, #0xc] -> 0x10122ccc
        syms["tramp_122cbc"] = _emit_bw_dual(
            em,
            "tramp_122cbc",
            fn_pred,
            lambda e: (_raw(e, "08681860"), e.jump_abs(0x10122CC0)),
            lambda e: (_raw(e, "41f20000186058609860d860"), e.jump_abs(0x10122CCC)),
        )

        # 10. Site 0x1017d834 (modified9_frontend_unity_sanitizer):
        #     Stock: movs r0, #1; b.w 0x1011d548
        #     Astro: b.w 0x1002d884 (which zeroes 2D polynomials, sets unity DC gains, and tail-calls 0x1011d548(1))
        syms["tramp_17d834"] = _emit_bl_dual(
            em,
            "tramp_17d834",
            fn_pred,
            lambda e: (_raw(e, "0120"), e.jump_abs(0x1011D548)),
            lambda e: e.jump_abs(ADDR_M9_SANITIZER),
        )

        # 11. Site 0x10197418 (modified3_spatial17_neutral):
        #     Stock: ldr r0, [r0, #0x1c]; cbz r1, #0x10197434 (fallthrough 0x1019741c)
        #     Astro: ldr r0, [r0, #0x1c]; b.w #0x1019743a
        #     Note: cbz r1, +6 (0xB109) skips 4-byte b.w without modifying APSR flags!
        syms["tramp_197418"] = _emit_bw_dual(
            em,
            "tramp_197418",
            fn_pred,
            lambda e: (_raw(e, "c069"), e.h16(0xB109), e.jump_abs(0x1019741C), e.jump_abs(0x10197434)),
            lambda e: (_raw(e, "c069"), e.jump_abs(0x1019743A)),
        )

        # 12. Site 0x10197866 (modified3_spatial17_neutral):
        #     Stock: strb r2, [r1, #0x1c]; strb r6, [r1, #0x1d] -> 0x10197880
        #     Astro: strb r2, [r1, #0x1c]; strb r2, [r1, #0x1d] -> 0x10197880
        syms["tramp_197866"] = _emit_bw_dual(
            em,
            "tramp_197866",
            fn_pred,
            lambda e: (_raw(e, "0a774e77"), e.jump_abs(0x10197880)),
            lambda e: (_raw(e, "0a774a77"), e.jump_abs(0x10197880)),
        )

        # 13. Site 0x10197874 (modified3_spatial17_neutral):
        #     Stock: ldr r0, [r0, #0x10]; ldrb r0, [r0, #1]; strb r0, [r1, #0x1d] -> 0x1019787a
        #     Astro: ldr r0, [r0, #0x10]; movs r0, #0;      strb r0, [r1, #0x1d] -> 0x1019787a
        syms["tramp_197874"] = _emit_bw_dual(
            em,
            "tramp_197874",
            fn_pred,
            lambda e: (_raw(e, "006940784877"), e.jump_abs(0x1019787A)),
            lambda e: (_raw(e, "006900204877"), e.jump_abs(0x1019787A)),
        )

        # 14. Lossless Coercion Helper for property getter 0x10164bfa (used at 0x10142396 & 0x10144c30):
        _align4(em)
        syms["tramp_get_prop_coerce_2_to_1"] = em.pc
        em.label("tramp_get_prop_coerce_2_to_1")
        em.push(R4, LR)  # 8-byte stack alignment preserved across bl 0x10164bfa
        em.call_abs(0x10164BFA)
        em.cmp_u8(R0, 2)
        em.j_cond(COND_NE, "coerce_prop_ret")
        em.mov_u16(R0, 1)
        em.label("coerce_prop_ret")
        em.pop(R4, PC)

        # 15. Lossless Coercion at 0x10125782 (encoded NEF output descriptor & buffer size builder 0x101254bc):
        #     Replaces `ldrb.w r0, [r5, #0x194]`. Coerces r0: 2 -> 1 AND writes 1 back to [r5, #0x194]
        #     so subsequent `0x101257c4: ldrb.w r7, [r5, #0x194]` also selects the Lossless buffer size!
        _align4(em)
        syms["tramp_125782"] = em.pc
        em.label("tramp_125782")
        em.push(R1, R2)
        em.save_flags(R1)
        em.ldr_u8(R0, R5, 0x194)
        em.cmp_u8(R0, 2)
        em.j_cond(COND_NE, "s125782_ret")
        em.mov_u16(R0, 1)
        em.str_u8(R0, R5, 0x194)
        em.label("s125782_ret")
        em.restore_flags(R1)
        em.pop(R1, R2)
        em.jump_abs(0x10125786)

        # 16. Lossless Coercion at 0x1028d2c8 (EXIF MakerNote 0x0093 NEFCompression tag builder):
        #     Replaces `ldrb.w r0, [r6, #0x194]` followed by `0x1028d2cc: cmp r0, #1`.
        #     Coerces 2 -> 1 so EXIF NEFCompression is written as 3 (Lossless) instead of 4 (Lossy).
        _align4(em)
        syms["tramp_28d2c8"] = em.pc
        em.label("tramp_28d2c8")
        em.ldr_u8(R0, R6, 0x194)
        em.cmp_u8(R0, 2)
        em.j_cond(COND_NE, "s28d2c8_ret")
        em.mov_u16(R0, 1)
        em.label("s28d2c8_ret")
        em.jump_abs(0x1028D2CC)

        # 17. Lossless Coercion at 0x10312c24 (main still capture owner builder 0x10312be8):
        #     Replaces `ldrb.w r2, [r0, #0x4c]; strb.w r2, [r5, #0x194]` (8B -> 0x10312c2c).
        _align4(em)
        syms["tramp_312c24"] = em.pc
        em.label("tramp_312c24")
        em.push(R1, R3)
        em.save_flags(R1)
        em.ldr_u8(R2, R0, 0x4C)
        em.cmp_u8(R2, 2)
        em.j_cond(COND_NE, "s312c24_store")
        em.mov_u16(R2, 1)
        em.label("s312c24_store")
        em.str_u8(R2, R5, 0x194)
        em.restore_flags(R1)
        em.pop(R1, R3)
        em.jump_abs(0x10312C2C)

        # 18. UI Localized String Resolver Hook at 0x104c0134 (inside 0x104c0104):
        #     Replaces `adds r2, r3, r0; str r2, [r6]; subs r0, r1, r0; str r0, [r5]` (8B)
        #     immediately before `0x104c013c: pop.w {r0, r1, r2, r3, r4, r5, r6, r7, r8, pc}`.
        #     Inputs at 0x104c0134:
        #       r0 = start_off, r1 = end_off, r3 = lang_pool_base, r4 = lang_id (0..35),
        #       r6 = out_ptr (uint16_t**), r5 = out_byte_len (uint32_t*), [sp, #4] = mapped str_id.
        _align4(em)
        syms["tramp_4c0134"] = em.pc
        em.label("tramp_4c0134")
        _raw(em, "1a18")  # adds r2, r3, r0 (stock ptr)
        _raw(em, "081a")  # subs r0, r1, r0 (stock byte_len)
        em.ldr_u32(R3, SP, 4)
        em.mov_u16(R7, UI_STR_ID_LABEL)
        em.cmp_reg(R3, R7)
        em.j_cond(COND_EQ, "ui_is_label")
        em.mov_u16(R7, UI_STR_ID_HELP)
        em.cmp_reg(R3, R7)
        em.j_cond(COND_NE, "ui_commit")

        # Help text (0x057E) override:
        em.cmp_u8(R4, LANG_ZH_CN)
        em.j_cond(COND_EQ, "ui_help_cn")
        em.cmp_u8(R4, LANG_ZH_TW)
        em.j_cond(COND_EQ, "ui_help_tw")
        em.set_u32(R2, str_addrs["str_help_en"][0])
        em.mov_u16(R0, str_addrs["str_help_en"][1])
        em.j_local("ui_commit")

        em.label("ui_help_cn")
        em.set_u32(R2, str_addrs["str_help_zh_cn"][0])
        em.mov_u16(R0, str_addrs["str_help_zh_cn"][1])
        em.j_local("ui_commit")

        em.label("ui_help_tw")
        em.set_u32(R2, str_addrs["str_help_zh_tw"][0])
        em.mov_u16(R0, str_addrs["str_help_zh_tw"][1])
        em.j_local("ui_commit")

        # Option label (0x0364) override:
        em.label("ui_is_label")
        em.cmp_u8(R4, LANG_ZH_CN)
        em.j_cond(COND_EQ, "ui_lbl_cn")
        em.cmp_u8(R4, LANG_ZH_TW)
        em.j_cond(COND_EQ, "ui_lbl_tw")
        em.set_u32(R2, str_addrs["str_lbl_en"][0])
        em.mov_u16(R0, str_addrs["str_lbl_en"][1])
        em.j_local("ui_commit")

        em.label("ui_lbl_cn")
        em.set_u32(R2, str_addrs["str_lbl_zh_cn"][0])
        em.mov_u16(R0, str_addrs["str_lbl_zh_cn"][1])
        em.j_local("ui_commit")

        em.label("ui_lbl_tw")
        em.set_u32(R2, str_addrs["str_lbl_zh_tw"][0])
        em.mov_u16(R0, str_addrs["str_lbl_zh_tw"][1])

        em.label("ui_commit")
        _raw(em, "3260")  # str r2, [r6]
        _raw(em, "2860")  # str r0, [r5]
        em.jump_abs(0x104C013C)

        code_bytes = bytearray(em.finish())
        syms["code_end"] = ADDR_M16_CAVE + len(code_bytes)

        # Append 4-byte aligned UTF-16LE string pool (each followed by a defensive UTF-16 NUL 0x0000,
        # while reported byte_len is exact UTF-16LE character byte count matching Nikon's pool convention).
        computed_addrs: dict[str, tuple[int, int]] = {}
        for key, text in str_items:
            while len(code_bytes) % 4 != 0:
                code_bytes += b"\x00"
            s_addr = ADDR_M16_CAVE + len(code_bytes)
            enc = text.encode("utf-16le")
            computed_addrs[key] = (s_addr, len(enc))
            syms[key] = s_addr
            code_bytes += enc + b"\x00\x00"
        while len(code_bytes) % 4 != 0:
            code_bytes += b"\x00"

        syms["cave_end"] = ADDR_M16_CAVE + len(code_bytes)
        assert syms["cave_end"] <= ADDR_M16_CAVE_LIMIT, (
            f"m16 cave overflowed into m600_v2: {syms['cave_end']:#x} > {ADDR_M16_CAVE_LIMIT:#x}"
        )
        return bytes(code_bytes), syms, computed_addrs

    # Pass 1 with dummy non-zero 32-bit addresses in 0x1002xxxx so set_u32 emits identical movw+movt sizes:
    dummy_addrs = {k: (0x1002DC00, len(t.encode("utf-16le"))) for k, t in str_items}
    _, _, real_addrs = _assemble(dummy_addrs)
    # Pass 2 with exact string addresses; assert fixed-point convergence:
    blob, syms, check_addrs = _assemble(real_addrs)
    assert check_addrs == real_addrs, "Two-pass string address layout did not converge!"
    return blob, syms


def build_all_m16_astro_ui_spans(stock: bytes) -> tuple[list[tuple[int, str, bytes, str]], dict[str, int]]:
    """Build all 20 Modified16 Astro UI + Lossless coercion spans (sorted) and return (spans, syms)."""
    cave_blob, syms = build_astro_ui_cave()
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
            ADDR_M16_CAVE,
            "m16_astro_ui_cave",
            "00" * len(cave_blob),
            cave_blob,
            f"Modified16 dynamic Astro gate ([0xC24CC77C]==2 && [0xC24CC798]<=1), 13 dual-path RAW trampolines, lossless NEF coercers, and 36-lang UI strings ({len(cave_blob)}B)",
        ),
        (
            0x100AE3A4,
            "m16_astro_gate_fullsize_raw",
            "0cf166f8",
            _b_nop(0x100AE3A4, syms["tramp_ae3a4"], 4, link=True),
            "Gate 0x100ae3a4: BL 0x101ba4b6 (preserve full-size front RAW) in Astro mode vs BL 0x101ba474 in Stock mode",
        ),
        (
            0x100C2654,
            "m16_astro_gate_dark_preserve",
            "00f065fa",
            _b_nop(0x100C2654, syms["tramp_c2654"], 4, link=True),
            "Gate 0x100c2654: mov.w r0, #0 in Astro mode vs BL 0x100c2b22 in Stock mode",
        ),
        (
            0x100C267C,
            "m16_astro_gate_dark_preserve",
            "00f045fa",
            _b_nop(0x100C267C, syms["tramp_c267c"], 4, link=True),
            "Gate 0x100c267c: mov.w r0, #2 in Astro mode vs BL 0x100c2b0a in Stock mode",
        ),
        (
            0x100C2690,
            "m16_astro_gate_dark_preserve",
            "90f81a18",
            _b_nop(0x100C2690, syms["tramp_c2690"], 4, link=False),
            "Gate 0x100c2690: mov.w r1, #2 in Astro mode vs ldrb.w r1, [r0, #0x81a] in Stock mode",
        ),
        (
            0x100C28B2,
            "m16_astro_gate_vignette_neutral",
            "84f86200",
            _b_nop(0x100C28B2, syms["tramp_c28b2"], 4, link=False),
            "Gate 0x100c28b2: strb.w sb, [r4, #0x62] in Astro mode vs strb.w r0, [r4, #0x62] in Stock mode",
        ),
        (
            0x100C28C8,
            "m16_astro_gate_vignette_neutral",
            "84f86390",
            _b_nop(0x100C28C8, syms["tramp_c28c8"], 4, link=False),
            "Gate 0x100c28c8: strb.w r0, [r4, #0x63] in Astro mode vs strb.w sb, [r4, #0x63] in Stock mode",
        ),
        (
            0x100C2964,
            "m16_astro_gate_vignette_neutral",
            "90f85f02",
            _b_nop(0x100C2964, syms["tramp_c2964"], 4, link=False),
            "Gate 0x100c2964: mov.w r0, #1 in Astro mode vs ldrb.w r0, [r0, #0x25f] in Stock mode",
        ),
        (
            0x1011E2DC,
            "m16_astro_gate_cal33_group4",
            "3e4600bb",
            _b_nop(0x1011E2DC, syms["tramp_11e2dc"], 4, link=False),
            "Gate 0x1011e2dc: static CAL33 factory unity Group 4 (0x1011e30c) in Astro mode vs Group 0 (0x1011e322) in Stock mode",
        ),
        (
            0x10122CBC,
            "m16_astro_gate_digital_gain_unity",
            "08681860",
            _b_nop(0x10122CBC, syms["tramp_122cbc"], 4, link=False),
            "Gate 0x10122cbc: unity 4096x4 frontend digital gain in Astro mode vs factory gain table copy in Stock mode",
        ),
        (
            0x10125782,
            "m16_lossless_nef_coercion",
            "95f89401",
            _b_nop(0x10125782, syms["tramp_125782"], 4, link=False),
            "Coerce owner+0x194 mode 2 -> 1 in 0x101254bc so Astro Lossless allocates full Lossless buffer & runs Lossless codec",
        ),
        (
            0x10142396,
            "m16_lossless_nef_coercion",
            "22f030fc",
            _b_nop(0x10142396, syms["tramp_get_prop_coerce_2_to_1"], 4, link=True),
            "Coerce 0x0506 read 2 -> 1 at 0x10142396 when populating secondary capture owner+0x194",
        ),
        (
            0x10144C30,
            "m16_lossless_nef_coercion",
            "1ff0e3ff",
            _b_nop(0x10144C30, syms["tramp_get_prop_coerce_2_to_1"], 4, link=True),
            "Coerce 0x1315 read 2 -> 1 at 0x10144c30 so remaining-shots capacity & 0x40000318 IPC report Lossless",
        ),
        (
            0x1017D834,
            "m16_astro_gate_frontend_sanitizer",
            "01209ff787fe",
            _b_nop(0x1017D834, syms["tramp_17d834"], 6, link=True),
            "Gate 0x1017d834: BL 0x1002d884 frontend 2D polynomial sanitizer in Astro mode vs Stock movs r0,#1; BL 0x1011d548",
        ),
        (
            0x10197418,
            "m16_astro_gate_spatial17_neutral",
            "c06959b1",
            _b_nop(0x10197418, syms["tramp_197418"], 4, link=False),
            "Gate 0x10197418: bypass spatial17 table loader to 0x1019743a in Astro mode vs Stock cbz r1, #0x10197434",
        ),
        (
            0x10197866,
            "m16_astro_gate_spatial17_neutral",
            "0a774e7709e0",
            _b_nop(0x10197866, syms["tramp_197866"], 6, link=False),
            "Gate 0x10197866: strb r2, [r1, #0x1d] in Astro mode vs Stock strb r6, [r1, #0x1d]",
        ),
        (
            0x10197874,
            "m16_astro_gate_spatial17_neutral",
            "006940784877",
            _b_nop(0x10197874, syms["tramp_197874"], 6, link=False),
            "Gate 0x10197874: movs r0, #0 -> [r1, #0x1d] in Astro mode vs Stock ldrb r0, [r0, #1]",
        ),
        (
            0x1028D2C8,
            "m16_lossless_nef_coercion",
            "96f89401",
            _b_nop(0x1028D2C8, syms["tramp_28d2c8"], 4, link=False),
            "Coerce owner+0x194 mode 2 -> 1 in 0x1028d2c8 so EXIF MakerNote 0x0093 NEFCompression writes 3 (Lossless)",
        ),
        (
            0x10312C24,
            "m16_lossless_nef_coercion",
            "90f84c2085f89421",
            _b_nop(0x10312C24, syms["tramp_312c24"], 8, link=False),
            "Coerce [r0, #0x4c] mode 2 -> 1 in 0x10312be8 when populating main still capture owner+0x194",
        ),
        (
            0x104C0134,
            "m16_ui_string_override",
            "1a183260081a2860",
            _b_nop(0x104C0134, syms["tramp_4c0134"], 8, link=False),
            "Override localized UI string IDs 0x0364 ('天文无损'/'天文無損'/'Astro Lossless') & 0x057e (? help text) across all 36 languages",
        ),
    ]

    spans: list[tuple[int, str, bytes, str]] = []
    for addr, grp, exp_hex, new_b, desc in expected_anchors:
        off = addr - BASE
        exp_old = bytes.fromhex(exp_hex)
        actual_old = stock[off : off + len(new_b)]
        assert actual_old == exp_old, (
            f"Stock anchor mismatch at {addr:#x}: actual={actual_old.hex()} != expected={exp_old.hex()}"
        )
        spans.append((addr, grp, new_b, desc))

    spans.sort(key=lambda x: x[0])
    return spans, syms

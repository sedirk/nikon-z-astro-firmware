"""Nikon Z6 C3.80 Modified18 UI-Switchable Astro RAW (Design A1: Color Space Switch + Uncompressed/Lossless Decoupled + Permanent 30-600s v2).

Design A1:
  Repurposes Photo Shooting Menu -> Color space (property 0x0508):
    - val == 0 ('sRGB' / '原厂标准'):
        100% Stock C3.80 RAW processing path. All 13 dynamic RAW hooks execute factory ISP logic.
    - val == 1 ('Astro RAW' / '天文直通'):
        100% Modified13 13-site Astro RAW path (gated dynamically on effective
        Color space [0xC24CDDC4] == 1 AND effective RAW recording [0xC24CC798] <= 1).
        Bypasses dark current clipping, normalizes CAL33 Group 4 vignetting curve,
        neutralizes 4096x4 digital gains, zeroes 2D polynomial corrections, bypasses
        spatial dual 17-point filters, and preserves full-size front RAW buffers.

Key Decoupling Advantage (Astro Uncompressed RAW):
  Unlike Design A3 (Modified16), which repurposed NEF compression 0x0506 and forced
  genuine lossless compression (preventing Uncompressed RAW capture), Design A1 leaves
  Photo Shooting Menu -> NEF (RAW) recording -> NEF (RAW) compression (property 0x0506)
  100% FACTORY STOCK (0=Uncompressed, 1=Lossless compressed, 2=Compressed).
  When Astro mode is enabled (Color space == 1):
    - Selecting 'Uncompressed' (0) produces genuine Uncompressed Astro RAW, enabling
      massively accelerated parallel stacking and preprocessing in PixInsight and Siril!
    - Selecting 'Lossless compressed' (1) produces standard Lossless Astro RAW.
    - Zero compression hijacking, zero memory footprint distortion, 100% factory codec integrity.

Color & EXIF Safety Lock:
  Hook at 0x1040AD00 forces IsColorSpace_sRGB() to unconditionally return 1 (true).
  This locks in-camera JPEG preview generation, EXIF ColorSpace tag (=1, sRGB), and file
  naming convention to standard 'DSC_xxxx.NEF' (preventing '_DSCxxxx' prefix).

Accessibility & Usability:
  - Color space natively supports being added to the 'i' Quick Menu for instant 1-touch toggle.
  - Color space natively persists into User Modes U1 / U2 / U3 and Save/Load Settings.
    Astrophotographers can save U3 as (M mode + 300s shutter + Astro RAW + Uncompressed RAW)
    for instant one-twist night sky readiness.
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
#   0x1002D900..0x1002EEFF      : Modified18 Astro UI toggle cave (< ADDR_PTP_HDR 0x1002EF14)
ADDR_M9_SANITIZER = 0x1002D884
M9_SANITIZER_HEX = (
    "0f4900223c2341f82320013bfbd144f200028a620a65c1f8a020c1f8c820"
    "42f22002c2f22002c1f8f4202022a1f8f8200022c1f8fc20a1f8fa200120"
    "eff042be54379ac2"
)
ADDR_M18_CAVE = 0x1002D900
ADDR_M18_CAVE_LIMIT = 0x1002EF14  # Start of m600_v2 ADDR_PTP_HDR

# Native scalar RAM slots:
RAM_PROP_0508 = 0xC24CDDC4  # Color space menu property (uint8, 0=sRGB, 1=Adobe RGB/Astro)
RAM_PROP_131B = 0xC24CC798  # Effective recording format (uint32, 0=RAW, 1=RAW+JPEG, >=2=JPEG-only)

# Localized UI strings (UTF-16LE, verified 0 missing font glyphs across all 36 languages):
UI_STR_ID_LABEL = 0x03B5  # Stock 'Adobe RGB' label
UI_STR_ID_HELP = 0x082C   # Stock 'Adobe RGB' help text
LANG_ZH_CN = 8
LANG_ZH_TW = 9

LABEL_EN = "Astro RAW"
LABEL_ZH_CN = "天文直通"
LABEL_ZH_TW = "天文直通"

HELP_EN = (
    "Astro RAW: in-camera dark clipping\n"
    "and spatial corrections are bypassed.\n"
    "Compatible for Uncompressed\n"
    "and Lossless NEF (RAW)."
)
HELP_ZH_CN = (
    "天文直通：关闭机内RAW暗电流裁切\n"
    "与空间彩圈校正。\n"
    "支持未压缩或无损压缩记录NEF图像。"
)
HELP_ZH_TW = (
    "天文直通：關閉機內RAW暗場裁切與\n"
    "空間彩圈校正。\n"
    "支援未壓縮或無損壓縮記錄NEF影像。"
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
    """Assemble the complete m18_astro_ui_cave blob at 0x1002D900 and return (blob, symbols)."""
    str_items = [
        ("str_lbl_en", LABEL_EN),
        ("str_lbl_zh_cn", LABEL_ZH_CN),
        ("str_lbl_zh_tw", LABEL_ZH_TW),
        ("str_help_en", HELP_EN),
        ("str_help_zh_cn", HELP_ZH_CN),
        ("str_help_zh_tw", HELP_ZH_TW),
    ]

    def _assemble(str_addrs: dict[str, tuple[int, int]]) -> tuple[bytes, dict[str, int]]:
        em = ThumbEmitter(ADDR_M18_CAVE)
        syms: dict[str, int] = {}

        # 0. Shared predicate: fn_is_astro_r0() -> r0 = 1 iff (uint8([0xC24CDDC4]) == 1 and uint32([0xC24CC798]) <= 1)
        syms["fn_is_astro_r0"] = em.pc
        em.label("fn_is_astro_r0")
        em.set_u32(R1, RAM_PROP_0508)
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

        # 14. UI String override trampoline for 0x104C0134:
        #     Hooked at 0x104C0134 inside GetLanguageString (0x104C0104):
        #       Stock at 0x104C0134:
        #         adds r2, r3, r0     (r2 = pointer to UTF-16LE string)
        #         str r2, [r6]        (return *p_str)
        #         subs r0, r1, r0     (r0 = byte length)
        #         str r0, [r5]        (return *p_len)
        #         pop {r0..r8, pc}
        #       Context in GetLanguageString:
        #         r4 = language index (0=EN, 8=ZH_CN, 9=ZH_TW)
        #         [sp, 4] = String ID
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

        # Help text (0x082C) override:
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

        # Option label (0x03B5) override:
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
        syms["code_end"] = ADDR_M18_CAVE + len(code_bytes)

        # Append 4-byte aligned UTF-16LE string pool (each followed by a defensive UTF-16 NUL 0x0000,
        # while reported byte_len is exact UTF-16LE character byte count matching Nikon's pool convention).
        computed_addrs: dict[str, tuple[int, int]] = {}
        for key, text in str_items:
            while len(code_bytes) % 4 != 0:
                code_bytes += b"\x00"
            s_addr = ADDR_M18_CAVE + len(code_bytes)
            enc = text.encode("utf-16le")
            computed_addrs[key] = (s_addr, len(enc))
            syms[key] = s_addr
            code_bytes += enc + b"\x00\x00"
        while len(code_bytes) % 4 != 0:
            code_bytes += b"\x00"

        syms["cave_end"] = ADDR_M18_CAVE + len(code_bytes)
        assert syms["cave_end"] <= ADDR_M18_CAVE_LIMIT, (
            f"m18 cave overflowed into m600_v2: {syms['cave_end']:#x} > {ADDR_M18_CAVE_LIMIT:#x}"
        )
        return bytes(code_bytes), syms, computed_addrs

    # Pass 1 with dummy non-zero 32-bit addresses in 0x1002xxxx so set_u32 emits identical movw+movt sizes:
    dummy_addrs = {k: (0x1002DC00, len(t.encode("utf-16le"))) for k, t in str_items}
    _, _, real_addrs = _assemble(dummy_addrs)
    # Pass 2 with exact string addresses; assert fixed-point convergence:
    blob, syms, check_addrs = _assemble(real_addrs)
    assert check_addrs == real_addrs, "Two-pass string address layout did not converge!"
    return blob, syms


def build_all_m18_astro_ui_spans(stock: bytes) -> tuple[list[tuple[int, str, bytes, str]], dict[str, int]]:
    """Build all Modified18 Astro UI (Color space switch + sRGB safety lock) spans and return (spans, syms)."""
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
            ADDR_M18_CAVE,
            "m18_astro_ui_cave",
            "00" * len(cave_blob),
            cave_blob,
            f"Modified18 dynamic Astro gate ([0xC24CDDC4]==1 && [0xC24CC798]<=1), 13 dual-path RAW trampolines, sRGB safety lock, and 36-lang UI strings ({len(cave_blob)}B)",
        ),
        (
            0x100AE3A4,
            "m18_astro_gate_fullsize_raw",
            "0cf166f8",
            _b_nop(0x100AE3A4, syms["tramp_ae3a4"], 4, link=True),
            "Gate 0x100ae3a4: BL 0x101ba4b6 (preserve full-size front RAW) in Astro mode vs BL 0x101ba474 in Stock mode",
        ),
        (
            0x100C2654,
            "m18_astro_gate_dark_preserve",
            "00f065fa",
            _b_nop(0x100C2654, syms["tramp_c2654"], 4, link=True),
            "Gate 0x100c2654: mov.w r0, #0 in Astro mode vs BL 0x100c2b22 in Stock mode",
        ),
        (
            0x100C267C,
            "m18_astro_gate_dark_preserve",
            "00f045fa",
            _b_nop(0x100C267C, syms["tramp_c267c"], 4, link=True),
            "Gate 0x100c267c: mov.w r0, #2 in Astro mode vs BL 0x100c2b0a in Stock mode",
        ),
        (
            0x100C2690,
            "m18_astro_gate_dark_preserve",
            "90f81a18",
            _b_nop(0x100C2690, syms["tramp_c2690"], 4, link=False),
            "Gate 0x100c2690: mov.w r1, #2 in Astro mode vs ldrb.w r1, [r0, #0x81a] in Stock mode",
        ),
        (
            0x100C28B2,
            "m18_astro_gate_vignette_neutral",
            "84f86200",
            _b_nop(0x100C28B2, syms["tramp_c28b2"], 4, link=False),
            "Gate 0x100c28b2: strb.w sb, [r4, #0x62] in Astro mode vs strb.w r0, [r4, #0x62] in Stock mode",
        ),
        (
            0x100C28C8,
            "m18_astro_gate_vignette_neutral",
            "84f86390",
            _b_nop(0x100C28C8, syms["tramp_c28c8"], 4, link=False),
            "Gate 0x100c28c8: strb.w r0, [r4, #0x63] in Astro mode vs strb.w sb, [r4, #0x63] in Stock mode",
        ),
        (
            0x100C2964,
            "m18_astro_gate_vignette_neutral",
            "90f85f02",
            _b_nop(0x100C2964, syms["tramp_c2964"], 4, link=False),
            "Gate 0x100c2964: mov.w r0, #1 in Astro mode vs ldrb.w r0, [r0, #0x25f] in Stock mode",
        ),
        (
            0x1011E2DC,
            "m18_astro_gate_cal33_group4",
            "3e4600bb",
            _b_nop(0x1011E2DC, syms["tramp_11e2dc"], 4, link=False),
            "Gate 0x1011e2dc: static CAL33 factory unity Group 4 (0x1011e30c) in Astro mode vs Group 0 (0x1011e322) in Stock mode",
        ),
        (
            0x10122CBC,
            "m18_astro_gate_digital_gain_unity",
            "08681860",
            _b_nop(0x10122CBC, syms["tramp_122cbc"], 4, link=False),
            "Gate 0x10122cbc: unity 4096x4 frontend digital gain in Astro mode vs factory gain table copy in Stock mode",
        ),
        (
            0x1017D834,
            "m18_astro_gate_frontend_sanitizer",
            "01209ff787fe",
            _b_nop(0x1017D834, syms["tramp_17d834"], 6, link=True),
            "Gate 0x1017d834: BL 0x1002d884 frontend 2D polynomial sanitizer in Astro mode vs Stock movs r0,#1; BL 0x1011d548",
        ),
        (
            0x10197418,
            "m18_astro_gate_spatial17_neutral",
            "c06959b1",
            _b_nop(0x10197418, syms["tramp_197418"], 4, link=False),
            "Gate 0x10197418: bypass spatial17 table loader to 0x1019743a in Astro mode vs Stock cbz r1, #0x10197434",
        ),
        (
            0x10197866,
            "m18_astro_gate_spatial17_neutral",
            "0a774e7709e0",
            _b_nop(0x10197866, syms["tramp_197866"], 6, link=False),
            "Gate 0x10197866: strb r2, [r1, #0x1d] in Astro mode vs Stock strb r6, [r1, #0x1d]",
        ),
        (
            0x10197874,
            "m18_astro_gate_spatial17_neutral",
            "006940784877",
            _b_nop(0x10197874, syms["tramp_197874"], 6, link=False),
            "Gate 0x10197874: movs r0, #0 -> [r1, #0x1d] in Astro mode vs Stock ldrb r0, [r0, #1]",
        ),
        (
            0x1040AD00,
            "m18_color_space_lock_srgb",
            "10b5002440f2",
            bytes.fromhex("0120704700bf"),
            "Lock IsColorSpace_sRGB() to 1 (movs r0, #1; bx lr) so EXIF ColorSpace and file prefix DSC_xxxx remain standard sRGB",
        ),
        (
            0x104C0134,
            "m18_ui_string_override",
            "1a183260081a2860",
            _b_nop(0x104C0134, syms["tramp_4c0134"], 8, link=False),
            "Override localized UI string IDs 0x03B5 ('Astro RAW'/'天文直通') & 0x082C (? help text) across all 36 languages",
        ),
    ]

    spans: list[tuple[int, str, bytes, str]] = []
    for addr, grp, expected_hex, new_bytes, desc in expected_anchors:
        off = addr - BASE
        expected_bytes = bytes.fromhex(expected_hex)
        actual_bytes = stock[off : off + len(expected_bytes)]
        assert actual_bytes == expected_bytes, (
            f"Anchor mismatch at 0x{addr:08x} ({grp}): expected {expected_hex}, found {actual_bytes.hex()}"
        )
        spans.append((addr, grp, new_bytes, desc))

    spans.sort(key=lambda s: s[0])
    return spans, syms

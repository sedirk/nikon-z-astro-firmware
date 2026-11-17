"""Modified15 (v2) 30-600s M-still extension preserving Stock <=109-entry 0x204 invariant.

Fixes Modified14's physical-hardware T-mode lock (caused by duplicate 0x204 insertion in
0x114D3510's 46-entry dependency list + 0x204's hard 109-entry ceiling) and resolves all
adversarial review findings without altering historical Modified14 builders:
  1. Distinguishes active-display shutter state (0x1319 == 0 at 0xC24CC790) from destination
     timed-shutter eligibility (0x136F == 3 M-mode at 0xC24CC8FC and 0x138D == 0 still at
     0xC24CC980, plus 30s = -120 present in 0x204), enabling Time -> Bulb -> 600s..30s and
     PTP 60s..600s transitions from Time/Bulb/x200.
  2. Preserves Stock's 16-byte pre-table string pointers at [ADDR_STR_PTR_TBL - 16 .. -4]
     (so ui_id == -1 reads Stock 0x11BA8D58 instead of NULL) and checks r4 == -1 + unsigned
     COND_HI in ADDR_RANGE_3.
  3. Uses unsigned COND_HI in ADDR_PTP_GATE so special uint32 codes (0xFFFFFFFF Bulb,
     0xFFFFFFFD Time, 0xFFFFFFFE x200) pass through untouched in both directions.
  4. Tracks [0xC1815D9C] (active M-table index) in ADDR_DIAL_BURST so both faster and slower
     multi-click Fn bursts stop cleanly at 30", 60", 600", Bulb, and Time across all EV grids.
"""
from __future__ import annotations
import struct

from z6_m600_core import build_core_routines
from z6_m600_dial import (
    emit_dial_prerefresh,
    emit_mtbl_refresh,
)
from z6_m600_tables import (
    ADDR_ACTIVE_UI,
    ADDR_BOOT_ALLOC,
    ADDR_DIAL_BURST,
    ADDR_DIAL_PREREF,
    ADDR_EXIF_RAT,
    ADDR_EXT_LOOKUP,
    ADDR_EXT_STRS,
    ADDR_GET_MTBL,
    ADDR_LOOKUP_RAT,
    ADDR_LOOKUP_TV,
    ADDR_MIN_TV8,
    ADDR_MTBL_REF,
    ADDR_M_FALLBACK,
    ADDR_NS_TIMER,
    ADDR_POOL_RESET,
    ADDR_PTP_GATE,
    ADDR_PTP_HDR,
    ADDR_PTP_TBL,
    ADDR_RANGE_1,
    ADDR_RANGE_2,
    ADDR_RANGE_3,
    ADDR_RANGE_4,
    ADDR_ROM_MTBL,
    ADDR_STR_PTR_TBL,
    ADDR_TOP_OLED,
    ADDR_TV_UI_TBL,
    ADDR_UI_CLS_TBL1,
    ADDR_UI_CLS_TBL2,
    ADDR_UI_R7,
    ADDR_UI_R8,
    ADDR_UI_RAT,
    ADDR_UI_SP8,
    ADDR_US_TIMER,
    BASE,
    EXT_SLOW_TO_FAST,
    EXT_STEPS,
    IDX_30S,
    IDX_600S,
    IDX_60S,
    M_COUNT,
    N_EXT,
    STOCK_M_COUNT,
    STOCK_TV_COUNT,
    STOCK_UI_COUNT,
    TV_COUNT,
    UI_COUNT,
    UI_FIRST,
    UI_LAST,
)
from z6_m600_ui import (
    emit_top_oled,
    emit_ui_r7,
    emit_ui_r8,
    emit_ui_sp8,
)
from z6_thumb_emit import (
    COND_CC,
    COND_CS,
    COND_EQ,
    COND_GE,
    COND_LS,
    COND_LT,
    COND_NE,
    IP,
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
    R8,
    R9,
    R10,
    R11,
    SP,
    ThumbEmitter,
    encode_branch32,
)

COND_HI = 0x8  # unsigned >

ADDR_PROP_ALLOW = 0x1002F5F4
ADDR_MTBL_TV_GATE = 0x1002F7C0
ADDR_PTP_ENUM = 0x1002FE00
ADDR_DIAL_STEP_V2 = 0x1002FEA0


def _jmp4(src: int, dst: int) -> bytes:
    return encode_branch32(src, dst, link=False)


def _call4(src: int, dst: int) -> bytes:
    return encode_branch32(src, dst, link=True)


def _jmp6(src: int, dst: int) -> bytes:
    return encode_branch32(src, dst, link=False) + b"\x00\xbf"


def _jmp8(src: int, dst: int) -> bytes:
    return encode_branch32(src, dst, link=False) + b"\x00\xbf\x00\xbf"


def _u32(val: int) -> bytes:
    return struct.pack("<I", val)


def build_rom_tables_v2(stock: bytes) -> list[tuple[int, str, bytes, str]]:
    """Build ROM tables for Modified15 without overriding Stock 0x204 109-entry descriptors."""
    out: list[tuple[int, str, bytes, str]] = []

    # 1. PTP 0x500D / 0xD100 16-byte prefix ({3, 2, 0x20D, 0x204}) + header + 117-entry Tv table
    ptp_prefix_addr = ADDR_PTP_HDR - 0x10
    ptp_hdr = stock[0x115520DC - BASE : 0x11552158 - BASE]
    assert len(ptp_hdr) == 0x7C and ptp_prefix_addr + len(ptp_hdr) == ADDR_PTP_TBL
    assert struct.unpack_from("<4I", ptp_hdr, 0) == (3, 2, 0x20D, 0x204)
    out.append((ptp_prefix_addr, "m600_rom_tables", ptp_hdr, "PTP 0x500D/0xD100 property prefix {0x20D,0x204} + descriptor header"))

    ptp_tbl = bytearray(stock[0x11552158 - BASE : 0x11552158 - BASE + STOCK_TV_COUNT * 12])
    for tv, _, sec, _ in EXT_STEPS:
        ptp_tbl += struct.pack("<hhII", tv, 0, sec * 10000, (sec << 16) | 1)
    assert len(ptp_tbl) == TV_COUNT * 12
    out.append((ADDR_PTP_TBL, "m600_rom_tables", bytes(ptp_tbl), "117-entry PTP ExposureTime table (up to 600s)"))

    # 2. 120-entry M-mode step table template in ROM
    rom_mtbl_off = 0x11E94DD4 + 0x16920 - BASE
    first4 = [struct.unpack_from("<4i", stock, rom_mtbl_off + k * 16) for k in range(4)]
    assert first4[0][0] == 3 and first4[1][0] == 2 and first4[2][0] == 1 and first4[3][:2] == (0, -120)
    mtbl = bytearray(stock[rom_mtbl_off : rom_mtbl_off + 3 * 16])
    for tv, _, _, _ in EXT_SLOW_TO_FAST:
        mtbl += struct.pack("<4i", 0, tv, 0x7FFFFFFF, 0)
    mtbl += stock[rom_mtbl_off + 3 * 16 : rom_mtbl_off + STOCK_M_COUNT * 16]
    assert len(mtbl) == M_COUNT * 16
    out.append((ADDR_ROM_MTBL, "m600_rom_tables", bytes(mtbl), "120-entry M-mode step table ROM template (600s..1/8000s)"))

    # 3. 117-entry (tv, ui_id) pure-ROM mapping table
    tv_ui = bytearray(stock[0x11471A0C - BASE : 0x11471A0C - BASE + STOCK_TV_COUNT * 8])
    for tv, ui_id, _, _ in EXT_STEPS:
        tv_ui += struct.pack("<ii", tv, ui_id)
    assert len(tv_ui) == TV_COUNT * 8
    out.append((ADDR_TV_UI_TBL, "m600_rom_tables", bytes(tv_ui), "117-entry Tv-to-UI-ID table (IDs 67..74)"))

    # 4. Extended strings + 16-byte Stock pre-table prefix ([ADDR_STR_PTR_TBL - 4] = 0x11BA8D58 for ui_id == -1) + 76-entry table
    str_prefix = stock[0x10657B70 - BASE : 0x10657B80 - BASE]
    assert len(str_prefix) == 16 and struct.unpack_from("<I", str_prefix, 12)[0] == 0x11BA8D58
    str_buf = bytearray()
    str_ptrs = list(struct.unpack_from("<67I", stock, 0x10657B80 - BASE))
    for _, _, _, label in EXT_STEPS:
        str_ptrs.append(ADDR_EXT_STRS + len(str_buf))
        str_buf += label.encode("ascii") + b"\x00"
    str_ptrs.append(0)
    out.append((ADDR_EXT_STRS, "m600_rom_tables", bytes(str_buf), 'Null-terminated shutter labels 60"..600"'))
    out.append(
        (
            ADDR_STR_PTR_TBL - 16,
            "m600_rom_tables",
            str_prefix + struct.pack("<76I", *str_ptrs),
            "Stock -4..-1 pre-table string pointers + 76-entry UI shutter string pointer table",
        )
    )

    # 5. UI formatting class tables 1 & 2
    ext_cls = b"".join(struct.pack("<ii", ui_id, 21) for _, ui_id, _, _ in EXT_STEPS) + struct.pack("<ii", 0, 0)
    cls1 = stock[0x10653810 - BASE : 0x10653810 - BASE + STOCK_UI_COUNT * 8] + ext_cls
    cls2 = stock[0x10656F68 - BASE : 0x10656F68 - BASE + STOCK_UI_COUNT * 8] + ext_cls
    out.append((ADDR_UI_CLS_TBL1, "m600_rom_tables", cls1, "76-entry UI display class table 1"))
    out.append((ADDR_UI_CLS_TBL2, "m600_rom_tables", cls2, "76-entry UI display class table 2"))

    # 6. 8-entry lookup table (tv_s24, ui_id, seconds)
    ext_lu = b"".join(struct.pack("<iII", tv, ui_id, sec) for tv, ui_id, sec, _ in EXT_STEPS)
    out.append((ADDR_EXT_LOOKUP, "m600_rom_tables", ext_lu, "8-entry (tv_s24, ui_id, seconds) lookup table"))

    return out


def emit_mtbl_ext_tv_gate() -> bytes:
    """Gate mtbl[3..10] (600s..60s) in 0x1012D464 on M-still mode and 30s (-120) availability.

    Does NOT gate on 0x1319 (0xC24CC790 current shutter mode) so mtbl[3..10] stay enabled while
    currently in Time (2), Bulb (1), or x200 (3); 0x1012D464 has already verified mode 0 is in 0x20D.
    """
    e = ThumbEmitter(ADDR_MTBL_TV_GATE)
    e.ldr_u32(IP, R3, 4)
    e.cmp_u8(R1, M_COUNT)
    e.j_cond(COND_NE, "cont")
    e.cmp_u8(R4, IDX_600S)
    e.j_cond(COND_CC, "cont")
    e.cmp_u8(R4, IDX_30S)
    e.j_cond(COND_CS, "cont")
    e.set_u32(R5, 0xC24CC8FC)
    e.ldr_u32(R5, R5, 0)
    e.cmp_u8(R5, 3)
    e.j_cond(COND_NE, "disable")
    e.set_u32(R5, 0xC24CC980)
    e.ldr_u32(R5, R5, 0)
    e.cmp_u8(R5, 0)
    e.j_cond(COND_NE, "disable")
    e.mov_u16(R5, 120)
    e.neg_reg(IP, R5)
    e.label("cont")
    e.jump_abs(0x1012D4B4)
    e.label("disable")
    e.jump_abs(0x1012D4FE)
    return e.finish()


def emit_prop_204_allow() -> bytes:
    """Allow 0x204=-144..-224 in 0x10209636 iff M-still mode is active and 30s (-120) is allowed."""
    e = ThumbEmitter(ADDR_PROP_ALLOW)
    e.push(R3, R4, R5, R6, R7, LR)
    e.mov_reg(R5, R1)
    e.mov_reg(R4, R2)
    e.mov_u16(R3, 0x204)
    e.cmp_reg(R0, R3)
    e.j_cond(COND_NE, "orig")
    e.mov_reg(R0, R5)
    e.call_abs(ADDR_LOOKUP_TV)
    e.cmp_u8(R0, 0)
    e.j_cond(COND_EQ, "restore_204")
    e.set_u32(R3, 0xC24CC8FC)
    e.ldr_u32(R3, R3, 0)
    e.cmp_u8(R3, 3)
    e.j_cond(COND_NE, "disallow")
    e.set_u32(R3, 0xC24CC980)
    e.ldr_u32(R3, R3, 0)
    e.cmp_u8(R3, 0)
    e.j_cond(COND_NE, "disallow")
    e.mov_u16(R5, 120)
    e.neg_reg(R5, R5)
    e.j_local("restore_204")
    e.label("disallow")
    e.mov_u16(R1, 0)
    e.str_u32(R1, R4, 0)
    e.mov_u16(R0, 1)
    e.pop(R3, R4, R5, R6, R7, PC)
    e.label("restore_204")
    e.mov_u16(R0, 0x204)
    e.mov_reg(R2, R4)
    e.label("orig")
    e.jump_abs(0x1020963C)
    return e.finish()


def emit_ptp_enum_204() -> bytes:
    """Append 60s..600s into PTP 0x200-byte enum buffer in M-still mode while keeping 0x204 <=109."""
    e = ThumbEmitter(ADDR_PTP_ENUM)
    e.push(R4, R5, R6, LR)
    e.mov_reg(R4, R1)
    e.mov_reg(R5, R2)
    e.call_abs(0x10401668)
    e.cmp_u8(R0, 0)
    e.j_cond(COND_EQ, "ret")
    e.ldr_u8(R1, R4, 4)
    e.cmp_u8(R1, 0)
    e.j_cond(COND_NE, "ret")
    e.set_u32(R1, 0xC24CC8FC)
    e.ldr_u32(R1, R1, 0)
    e.cmp_u8(R1, 3)
    e.j_cond(COND_NE, "ret")
    e.set_u32(R1, 0xC24CC980)
    e.ldr_u32(R1, R1, 0)
    e.cmp_u8(R1, 0)
    e.j_cond(COND_NE, "ret")
    e.ldr_u32(R1, R4, 8)
    e.cmp_u8(R1, 0)
    e.j_cond(COND_EQ, "ret")
    e.add_u12(R2, R1, N_EXT)
    e.lsl_imm(R3, R2, 2)
    e.cmp_reg(R5, R3)
    e.j_cond(COND_CC, "ret")
    e.ldr_u32(R3, R4, 0x0C)
    e.ldr_u32(R6, R3, 0)
    e.mov_u16(R5, 120)
    e.neg_reg(R5, R5)
    e.cmp_reg(R6, R5)
    e.j_cond(COND_NE, "ret")
    e.add_lsl(R3, R3, R1, 2)
    e.set_u32(R5, ADDR_EXT_LOOKUP)
    e.mov_u16(R6, N_EXT)
    e.label("loop")
    e.ldr_u32(R1, R5, 0)
    e.str_post4(R1, R3)
    e.add_u12(R5, R5, 12)
    e.subs_u8(R6, 1)
    e.j_cond(COND_NE, "loop")
    e.str_u32(R2, R4, 8)
    e.label("ret")
    e.pop(R4, R5, R6, PC)
    return e.finish()


def emit_dial_single_step_v2() -> bytes:
    """Single-step dial transitions across Time/Bulb <-> 600s..60s <-> 30s respecting Bulb enable."""
    e = ThumbEmitter(ADDR_DIAL_STEP_V2)
    e.push(R1, R2)
    e.ldr_u32(R1, SP, 0x1C)
    e.cmp_u8(R1, M_COUNT)
    e.j_cond(COND_NE, "done")
    e.ldr_u32(R1, R6, 0x3C)
    e.cmp_u8(R1, 0)
    e.j_cond(COND_EQ, "done")
    e.cmp_u8(R8, IDX_30S)
    e.j_cond(COND_EQ, "at_30s")
    e.j_cond(COND_CS, "above_30s")
    e.cmp_u8(R8, IDX_600S)
    e.j_cond(COND_CC, "below_600s")
    e.cmp_reg(R0, R8)
    e.j_cond(COND_EQ, "done")
    e.j_cond(COND_CC, "step_slower")
    e.add_u12(R0, R8, 1)
    e.j_local("done")
    e.label("step_slower")
    e.cmp_u8(R8, IDX_600S)
    e.j_cond(COND_NE, "dec_one")
    e.ldr_u32(R1, R6, 0x2C)
    e.cmp_u8(R1, 0)
    e.j_cond(COND_EQ, "done")
    e.label("dec_one")
    e.sub_u12(R0, R8, 1)
    e.j_local("done")
    e.label("below_600s")
    e.cmp_u8(R0, IDX_600S)
    e.j_cond(COND_CC, "done")
    e.mov_u16(R0, IDX_600S)
    e.j_local("done")
    e.label("at_30s")
    e.cmp_u8(R0, IDX_30S)
    e.j_cond(COND_CS, "done")
    e.mov_u16(R0, IDX_60S)
    e.j_local("done")
    e.label("above_30s")
    e.cmp_u8(R0, IDX_30S)
    e.j_cond(COND_CS, "done")
    e.mov_u16(R0, IDX_30S)
    e.label("done")
    e.pop(R1, R2)
    e.cmp_u8(R9, 0)
    e.j_cond(COND_NE, "sb_nonzero")
    e.jump_abs(0x1012A6D2)
    e.label("sb_nonzero")
    e.jump_abs(0x1012A6E2)
    return e.finish()


def emit_dial_multiclick_stop_v2() -> bytes:
    """Stop both faster and slower multi-click Fn dial bursts at 30", 60", 600", Bulb, and Time."""
    e = ThumbEmitter(ADDR_DIAL_BURST)
    e.cmp_u8(R7, 0)
    e.j_cond(COND_NE, "plain")
    e.push(R0, R1, R7, LR)
    e.sp_sub(8)
    e.mov_reg(R0, SP)
    e.call_abs(0x10090102)
    e.ldr_u32(R1, SP, 0)
    e.cmp_u8(R1, M_COUNT)
    e.j_cond(COND_NE, "pop_plain")
    e.ldr_u32(R1, R0, 0x3C)
    e.cmp_u8(R1, 0)
    e.j_cond(COND_EQ, "pop_plain")
    e.sp_add(8)
    e.set_u32(R2, 0xC1815D9C)
    e.ldr_u32(R7, R2, 0)
    e.pop(R0, R1)
    e.call_abs(0x1012A68C)
    e.set_u32(R2, 0xC1815D9C)
    e.ldr_u32(R0, R2, 0)
    e.cmp_u8(R0, IDX_30S)
    e.j_cond(COND_EQ, "stop")
    e.cmp_u8(R0, IDX_600S)
    e.j_cond(COND_LS, "stop")
    e.cmp_u8(R7, IDX_30S)
    e.j_cond(COND_NE, "cont")
    e.cmp_u8(R0, IDX_60S)
    e.j_cond(COND_EQ, "stop")
    e.label("cont")
    e.pop(R7, LR)
    e.jump_abs(0x1012A878)
    e.label("stop")
    e.pop(R7, LR)
    e.jump_abs(0x1012A880)
    e.label("pop_plain")
    e.sp_add(8)
    e.pop(R0, R1, R7, LR)
    e.label("plain")
    e.call_abs(0x1012A68C)
    e.jump_abs(0x1012A878)
    return e.finish()


def emit_min_tv8_clamp_v2() -> bytes:
    """Allow Tv*8 below -960 (30s) strictly when an extended M-still timed speed is active."""
    e = ThumbEmitter(ADDR_MIN_TV8)
    e.push(R0, R1, R2, R3, IP, LR)
    e.save_flags(R0)
    e.push(R0, R1)
    e.set_u32(R0, 0xC24CD9C0)
    e.ldr_u32(R0, R0, 0)
    e.lsl_imm(R0, R0, 3)
    e.cmp_reg(R7, R0)
    e.j_cond(COND_NE, "done")
    e.mov_u16(R1, 0x3C0)
    e.neg_reg(R1, R1)
    e.cmp_reg(R5, R1)
    e.j_cond(COND_NE, "done")
    e.ldr_u8(R0, R6, 0)
    e.cmp_u8(R0, 3)
    e.j_cond(COND_NE, "done")
    e.call_abs(ADDR_ACTIVE_UI)
    e.cmp_u8(R0, 0)
    e.j_cond(COND_EQ, "done")
    e.mov_reg(R5, R7)
    e.label("done")
    e.pop(R0, R1)
    e.restore_flags(R0)
    e.pop(R0, R1, R2, R3, IP, LR)
    e.cmp_reg(R7, R5)
    e.j_cond(COND_GE, "skip_clamp")
    e.jump_abs(0x100DAD6A)
    e.label("skip_clamp")
    e.jump_abs(0x100DAD6C)
    return e.finish()


def emit_active_ui_v2() -> bytes:
    """Return (ui_id, seconds) iff camera is actively in M-still timed shutter mode (0x1319 == 0)."""
    e = ThumbEmitter(ADDR_ACTIVE_UI)
    e.push(R4, LR)
    e.set_u32(R0, 0xC24CD9C0)
    e.ldr_u32(R0, R0, 0)
    e.call_abs(ADDR_LOOKUP_TV)
    e.cmp_u8(R0, 0)
    e.j_cond(COND_EQ, "no")
    e.mov_reg(R2, R0)
    e.mov_reg(R4, R1)
    e.set_u32(R3, 0xC24CC8FC)
    e.ldr_u32(R3, R3, 0)
    e.cmp_u8(R3, 3)
    e.j_cond(COND_NE, "no")
    e.set_u32(R3, 0xC24CC980)
    e.ldr_u32(R3, R3, 0)
    e.cmp_u8(R3, 0)
    e.j_cond(COND_NE, "no")
    e.set_u32(R3, 0xC24CC790)
    e.ldr_u32(R3, R3, 0)
    e.cmp_u8(R3, 0)
    e.j_cond(COND_NE, "no")
    e.mov_reg(R0, R2)
    e.mov_reg(R1, R4)
    e.pop(R4, PC)
    e.label("no")
    e.mov_u16(R0, 0)
    e.pop(R4, PC)
    return e.finish()


def emit_ui_rat_v2() -> bytes:
    e = ThumbEmitter(ADDR_UI_RAT)
    e.push(R0, R1, R2, R3, IP, LR)
    e.add_u12(R0, SP, 0x18 + 0x1C4)
    e.call_abs(ADDR_LOOKUP_RAT)
    e.cmp_u8(R0, 0)
    e.j_cond(COND_EQ, "orig")
    e.cmp_u8(R5, 0)
    e.j_cond(COND_NE, "orig")
    e.set_u32(R3, 0xC24CC8FC)
    e.ldr_u32(R3, R3, 0)
    e.cmp_u8(R3, 3)
    e.j_cond(COND_NE, "orig")
    e.set_u32(R3, 0xC24CC980)
    e.ldr_u32(R3, R3, 0)
    e.cmp_u8(R3, 0)
    e.j_cond(COND_NE, "orig")
    e.str_u32(R1, SP, 0)
    e.pop(R0, R1, R2, R3, IP, LR)
    e.ldr_u32(R1, R4, 0x30)
    e.jump_abs(0x10473828)
    e.label("orig")
    e.pop(R0, R1, R2, R3, IP, LR)
    e.ldr_u32(R0, SP, 0x1B8)
    e.cmp_reg(R0, R7)
    e.jump_abs(0x10473814)
    return e.finish()


def emit_range_adapters_v2() -> list[tuple[int, str, bytes, str]]:
    out: list[tuple[int, str, bytes, str]] = []

    e1 = ThumbEmitter(ADDR_RANGE_1)
    e1.cmp_u8(R4, UI_FIRST)
    e1.j_cond(COND_CC, "std")
    e1.cmp_u8(R4, UI_LAST)
    e1.j_cond(COND_LS, "hit")
    e1.label("std")
    e1.cmp_u8(R4, 0x12)
    e1.j_cond(COND_LS, "hit")
    e1.jump_abs(0x102F9E98)
    e1.label("hit")
    e1.jump_abs(0x102F9EB2)
    out.append((ADDR_RANGE_1, "m600_ui_display", e1.finish(), "UI seconds-style range check 1"))

    e2 = ThumbEmitter(ADDR_RANGE_2)
    e2.cmp_u8(R1, UI_FIRST)
    e2.j_cond(COND_CC, "std")
    e2.cmp_u8(R1, UI_LAST)
    e2.j_cond(COND_LS, "hit")
    e2.label("std")
    e2.cmp_u8(R1, 0x13)
    e2.j_cond(COND_CC, "hit")
    e2.jump_abs(0x102F9EC0)
    e2.label("hit")
    e2.jump_abs(0x102F9ECC)
    out.append((ADDR_RANGE_2, "m600_ui_display", e2.finish(), "UI seconds-style range check 2"))

    # Handle r4 == -1 sentinel FIRST and use unsigned COND_HI so negative IDs never enter 0x1041E554
    e3 = ThumbEmitter(ADDR_RANGE_3)
    e3.adds_u3(R0, R4, 1)
    e3.j_cond(COND_EQ, "eq84")
    e3.cmp_u8(R4, UI_FIRST)
    e3.j_cond(COND_CC, "std")
    e3.cmp_u8(R4, UI_LAST)
    e3.j_cond(COND_HI, "std")
    e3.jump_abs(0x1041E554)
    e3.label("std")
    e3.jump_abs(0x1041E54A)
    e3.label("eq84")
    e3.jump_abs(0x1041E584)
    out.append((ADDR_RANGE_3, "m600_ui_display", e3.finish(), "LV/EVF shutter formatter range check 1 (sentinel-safe)"))

    e4 = ThumbEmitter(ADDR_RANGE_4)
    e4.cmp_u8(R4, UI_FIRST)
    e4.j_cond(COND_CC, "std")
    e4.cmp_u8(R4, UI_LAST)
    e4.j_cond(COND_LS, "hit")
    e4.label("std")
    e4.cmp_u8(R4, 0x13)
    e4.j_cond(COND_LT, "hit")
    e4.jump_abs(0x1041E734)
    e4.label("hit")
    e4.jump_abs(0x1041E766)
    out.append((ADDR_RANGE_4, "m600_ui_display", e4.finish(), "LV/EVF shutter formatter range check 2"))
    return out


def emit_ptp_gate_v2() -> bytes:
    """Gate PTP 0x500D unsigned 300_000 < val <= 6_000_000 to M-still without blocking Bulb/Time."""
    e = ThumbEmitter(ADDR_PTP_GATE)
    e.push(R0, R1, R2, R3, IP, LR)
    e.set_u32(R1, 300_000)
    e.cmp_reg(R0, R1)
    e.j_cond(COND_LS, "pass")
    e.set_u32(R1, 6_000_000)
    e.cmp_reg(R0, R1)
    e.j_cond(COND_HI, "pass")
    e.set_u32(R2, 0xC24CC8FC)
    e.ldr_u32(R2, R2, 0)
    e.cmp_u8(R2, 3)
    e.j_cond(COND_NE, "reject")
    e.set_u32(R2, 0xC24CC980)
    e.ldr_u32(R2, R2, 0)
    e.cmp_u8(R2, 0)
    e.j_cond(COND_EQ, "pass")
    e.label("reject")
    e.pop(R0, R1, R2, R3, IP, LR)
    e.mov_u16(R0, 0x201C)
    e.ret_lr()
    e.label("pass")
    e.pop(R0, R1, R2, R3, IP, LR)
    e.push(R4, R5, R6, R7, R8, R9, R10, R11, IP, LR)
    e.jump_abs(0x10331644)
    return e.finish()


def build_ui_routines_v2() -> list[tuple[int, str, bytes, str]]:
    out = [
        (ADDR_ACTIVE_UI, "m600_ui_display", emit_active_ui_v2(), "Active M-still extended shutter UI-ID resolver (32-bit scalar loads)"),
        (ADDR_UI_R8, "m600_ui_display", emit_ui_r8(), "Extended shutter UI-ID adapter at 0x1036a7cc"),
        (ADDR_UI_R7, "m600_ui_display", emit_ui_r7(), "Extended shutter UI-ID adapter at 0x1037a8bc"),
        (ADDR_UI_SP8, "m600_ui_display", emit_ui_sp8(), "Extended shutter UI-ID adapter at 0x1041e71a"),
        (ADDR_UI_RAT, "m600_ui_display", emit_ui_rat_v2(), "Extended shutter rational-to-UI adapter at 0x10473810"),
    ]
    out.extend(emit_range_adapters_v2())
    out.append((ADDR_TOP_OLED, "m600_top_oled", emit_top_oled(), "Top-OLED 3-digit seconds BCD formatter for 60s-600s"))
    out.append((ADDR_PTP_GATE, "m600_ptp_tables", emit_ptp_gate_v2(), "PTP 0x500D unsigned mode gate preserving Bulb/Time and gating 60s-600s to M still"))
    return out


def build_dial_and_prop_routines_v2() -> list[tuple[int, str, bytes, str]]:
    return [
        (ADDR_PROP_ALLOW, "m600_prop_gate", emit_prop_204_allow(), "Allow 0x204 extended Tv in 0x10209636 strictly in M-still when 30s is allowed"),
        (ADDR_DIAL_PREREF, "m600_dial_control", emit_dial_prerefresh(), "Refresh M-mode step enable flags prior to dial step"),
        (ADDR_MTBL_REF, "m600_dial_control", emit_mtbl_refresh(), "Refresh M-mode step enable flags prior to M-table query"),
        (ADDR_MTBL_TV_GATE, "m600_dial_control", emit_mtbl_ext_tv_gate(), "Enable mtbl[3..10] (600s..60s) in M-still when 30s (-120) is allowed in 0x204"),
        (ADDR_DIAL_BURST, "m600_dial_control", emit_dial_multiclick_stop_v2(), "Stop both faster and slower multi-click Fn dial bursts at 30s/60s/600s/Bulb/Time boundaries"),
        (ADDR_MIN_TV8, "m600_dial_control", emit_min_tv8_clamp_v2(), "Allow Tv*8 below -960 (30s) when an extended M-still speed is active"),
        (ADDR_PTP_ENUM, "m600_ptp_tables", emit_ptp_enum_204(), "Append 60s..600s to PTP 0x500D/0xD100 0x200-byte enum list in M-still mode"),
        (ADDR_DIAL_STEP_V2, "m600_dial_control", emit_dial_single_step_v2(), "Single-step command dial transitions across Time/Bulb..600s..60s..30s"),
    ]


def build_site_patches_v2() -> list[tuple[int, str, bytes, str]]:
    return [
        # Pool allocation, reset, and dynamic M-table lookup
        (0x101120E2, "m600_pool_runtime", _call4(0x101120E2, ADDR_BOOT_ALLOC), "Redirect boot pool allocation to allocate extended M-table"),
        (0x101E5BA8, "m600_pool_runtime", _jmp6(0x101E5BA8, ADDR_POOL_RESET), "Invalidate extended M-table block when pool resets"),
        (0x10090102, "m600_pool_runtime", _jmp6(0x10090102, ADDR_GET_MTBL), "Route M-mode shutter table getter to 120-entry table"),
        (0x1012ED8E, "m600_pool_runtime", _jmp6(0x1012ED8E, ADDR_M_FALLBACK), "Clamp M-table sentinel index fallback for 112/120 entries"),
        # Exposure timing and EXIF ExposureTime rational
        (0x1011C14A, "m600_exposure_timing", _jmp6(0x1011C14A, ADDR_NS_TIMER), "Compute exact 64-bit nanosecond exposure duration for 60s-600s"),
        (0x101C486E, "m600_exposure_timing", _jmp6(0x101C486E, ADDR_US_TIMER), "Compute exact microsecond exposure duration for 60s-600s"),
        (0x101C4790, "m600_exposure_timing", _jmp6(0x101C4790, ADDR_EXIF_RAT), "Write exact EXIF ExposureTime rational (seconds*10 / 10) for 60s-600s"),
        # Property 0x204 allowlist check & M-table Tv flag gate (NO edits to 0x101508FD, 0x1015093E, or 0x114D3518!)
        (0x10209636, "m600_prop_gate", _jmp6(0x10209636, ADDR_PROP_ALLOW), "Accept -144..-224 in 0x10209636 allowlist check strictly in M-still mode"),
        (0x1012D4B0, "m600_dial_control", _jmp4(0x1012D4B0, ADDR_MTBL_TV_GATE), "Enable mtbl[3..10] (600s..60s) via 30s (-120) gate in M-still mode"),
        # Dial stepping and min-Tv*8 clamp
        (0x100DAD66, "m600_dial_control", _jmp4(0x100DAD66, ADDR_MIN_TV8), "Extend M-still minimum Tv*8 lower bound to -224*8 (-1792 / -960 floor)"),
        (0x1012A696, "m600_dial_control", _jmp4(0x1012A696, ADDR_DIAL_PREREF), "Refresh M-table entry flags before dial evaluation"),
        (0x1012A6CC, "m600_dial_control", _jmp4(0x1012A6CC, ADDR_DIAL_STEP_V2), "Map Time/Bulb..600s..60s..30s dial steps across 1/3, 1/2, and 1 EV grids"),
        (0x1012A786, "m600_dial_control", _jmp4(0x1012A786, ADDR_MTBL_REF), "Recompute 120-entry M-table flags on active table"),
        (0x1012A874, "m600_dial_control", _jmp4(0x1012A874, ADDR_DIAL_BURST), "Stop multi-click dial burst cleanly at 30s/60s/600s/Bulb/Time boundaries"),
        # PTP 0x500D / 0xD100 enum extensions & write gate
        (0x10331640, "m600_ptp_tables", _jmp4(0x10331640, ADDR_PTP_GATE), "Gate PTP 0x500D 60s-600s writes to M still mode while preserving Bulb/Time"),
        (0x10331D2A, "m600_ptp_tables", _call4(0x10331D2A, ADDR_PTP_ENUM), "Include 60s-600s in PTP 0x500D ExposureTime GetDevicePropDesc enum"),
        (0x10331DAA, "m600_ptp_tables", _call4(0x10331DAA, ADDR_PTP_ENUM), "Include 60s-600s in PTP 0xD100 ShutterSpeed GetDevicePropDesc enum"),
        # UI adapters, range checks, and top OLED
        (0x102F9E94, "m600_ui_display", _jmp4(0x102F9E94, ADDR_RANGE_1), "Include UI IDs 67..74 in seconds display group 1"),
        (0x102F9EBC, "m600_ui_display", _jmp4(0x102F9EBC, ADDR_RANGE_2), "Include UI IDs 67..74 in seconds display group 2"),
        (0x1036A7CC, "m600_ui_display", _jmp8(0x1036A7CC, ADDR_UI_R8), "Resolve extended UI ID 67..74 at 0x1036a7cc"),
        (0x1037A8BC, "m600_ui_display", _jmp4(0x1037A8BC, ADDR_UI_R7), "Resolve extended UI ID 67..74 at 0x1037a8bc"),
        (0x1041E546, "m600_ui_display", _jmp4(0x1041E546, ADDR_RANGE_3), "Include UI IDs 67..74 in LV/EVF shutter formatter 1 (sentinel-safe)"),
        (0x1041E71A, "m600_ui_display", _jmp4(0x1041E71A, ADDR_UI_SP8), "Resolve extended UI ID 67..74 at 0x1041e71a"),
        (0x1041E730, "m600_ui_display", _jmp4(0x1041E730, ADDR_RANGE_4), "Include UI IDs 67..74 in LV/EVF shutter formatter 2"),
        (0x10473810, "m600_ui_display", _jmp4(0x10473810, ADDR_UI_RAT), "Resolve extended shutter rational to UI ID 67..74"),
        (0x1053B16E, "m600_top_oled", _jmp4(0x1053B16E, ADDR_TOP_OLED), "Format 3-digit 60s-600s shutter label on top OLED"),
        # Pure-ROM table count scalars
        (0x102F5A36, "m600_table_bounds", bytes([UI_COUNT]), "UI shutter ID upper bound 67 -> 75 (site 1)"),
        (0x102FE7E6, "m600_table_bounds", bytes([TV_COUNT]), "Tv-to-UI table count 109 -> 117 (site 1)"),
        (0x102FE7F8, "m600_table_bounds", bytes([TV_COUNT]), "Tv-to-UI table count 109 -> 117 (site 2)"),
        (0x102FE8AE, "m600_table_bounds", bytes([UI_COUNT]), "UI shutter ID upper bound 67 -> 75 (site 2)"),
        (0x103316A6, "m600_table_bounds", bytes([TV_COUNT, 0x2E, 0xE4, 0xD3, TV_COUNT]), "PTP ExposureTime table loop & sentinel bound 109 -> 117"),
        (0x1033192E, "m600_table_bounds", bytes([TV_COUNT]), "PTP ShutterSpeed 0xD100 table loop bound 109 -> 117"),
        (0x10331CCA, "m600_table_bounds", bytes([TV_COUNT]), "PTP Tv binary-search count 109 -> 117"),
        (0x1036A89C, "m600_table_bounds", bytes([UI_COUNT]), "Rear monitor UI shutter ID bound 67 -> 75"),
        (0x1037A8F6, "m600_table_bounds", bytes([UI_COUNT]), "Info display UI shutter ID bound 67 -> 75"),
        (0x1037B238, "m600_table_bounds", bytes([TV_COUNT]), "Tv-to-UI table count 109 -> 117 (site 3)"),
        # Relocated ROM table literal pointers
        (0x102FA09C, "m600_table_ptrs", _u32(ADDR_STR_PTR_TBL), "Point UI string table ref 1 to 76-entry table"),
        (0x102FEA48, "m600_table_ptrs", _u32(ADDR_TV_UI_TBL), "Point Tv-to-UI table ref 1 to 117-entry table"),
        (0x102FEA50, "m600_table_ptrs", _u32(ADDR_UI_CLS_TBL1), "Point UI class table 1 ref to 76-entry table"),
        (0x102FEA5C, "m600_table_ptrs", _u32(ADDR_STR_PTR_TBL), "Point UI string table ref 2 to 76-entry table"),
        (0x1033173C, "m600_table_ptrs", _u32(ADDR_PTP_HDR), "Point PTP 0x500D descriptor header ref to extended table"),
        (0x10331BAC, "m600_table_ptrs", _u32(ADDR_PTP_TBL), "Point PTP 0xD100 table ref 1 to 117-entry table"),
        (0x10331E74, "m600_table_ptrs", _u32(ADDR_PTP_TBL), "Point PTP Tv lookup ref 2 to 117-entry table"),
        (0x1037AB30, "m600_table_ptrs", _u32(ADDR_UI_CLS_TBL2) + _u32(ADDR_STR_PTR_TBL), "Point UI class table 2 & string table ref 3 to 76-entry tables"),
        (0x1037B3BC, "m600_table_ptrs", _u32(ADDR_TV_UI_TBL), "Point Tv-to-UI table ref 2 to 117-entry table"),
        (0x1041E6D4, "m600_table_ptrs", _u32(ADDR_STR_PTR_TBL), "Point LV/EVF UI string table ref 4 to 76-entry table"),
    ]


def build_all_m600_v2_spans(stock: bytes) -> list[tuple[int, str, bytes, str]]:
    return (
        build_rom_tables_v2(stock)
        + build_core_routines()
        + build_dial_and_prop_routines_v2()
        + build_ui_routines_v2()
        + build_site_patches_v2()
    )

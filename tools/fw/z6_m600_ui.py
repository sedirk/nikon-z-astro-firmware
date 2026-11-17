"""UI, top-OLED, and PTP gate routines for Nikon Z6 C3.80 30-600s extension."""
from __future__ import annotations

from z6_m600_tables import (
    ADDR_ACTIVE_UI,
    ADDR_LOOKUP_RAT,
    ADDR_LOOKUP_TV,
    ADDR_PTP_GATE,
    ADDR_RANGE_1,
    ADDR_RANGE_2,
    ADDR_RANGE_3,
    ADDR_RANGE_4,
    ADDR_TOP_OLED,
    ADDR_UI_R7,
    ADDR_UI_R8,
    ADDR_UI_RAT,
    ADDR_UI_SP8,
    UI_FIRST,
    UI_LAST,
)
from z6_thumb_emit import (
    COND_CC,
    COND_EQ,
    COND_GT,
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
)


def emit_active_ui() -> bytes:
    e = ThumbEmitter(ADDR_ACTIVE_UI)
    e.push(R4, LR)
    e.set_u32(R0, 0xC24CD9C0)
    e.ldr_s16(R0, R0, 0)
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
    e.ldr_u8(R3, R3, 0)
    e.cmp_u8(R3, 0)
    e.j_cond(COND_NE, "no")
    e.set_u32(R3, 0xC24CC790)
    e.ldr_u8(R3, R3, 0)
    e.cmp_u8(R3, 0)
    e.j_cond(COND_NE, "no")
    e.mov_reg(R0, R2)
    e.mov_reg(R1, R4)
    e.pop(R4, PC)
    e.label("no")
    e.mov_u16(R0, 0)
    e.pop(R4, PC)
    return e.finish()


def emit_ui_r8() -> bytes:
    e = ThumbEmitter(ADDR_UI_R8)
    e.push(R0, R1, R2, R3, IP, LR)
    e.save_flags(R3)
    e.push(R3, R4)
    e.call_abs(ADDR_ACTIVE_UI)
    e.cmp_u8(R0, 0)
    e.j_cond(COND_NE, "got")
    e.ldr_u8(R0, R8, 0)
    e.sxtb(R0, R0)
    e.label("got")
    e.str_u32(R0, R6, 0x18)
    e.str_u32(R0, SP, 8)
    e.pop(R3, R4)
    e.restore_flags(R3)
    e.pop(R0, R1, R2, R3, IP, LR)
    e.jump_abs(0x1036A7D4)
    return e.finish()


def emit_ui_r7() -> bytes:
    e = ThumbEmitter(ADDR_UI_R7)
    e.push(R0, R1, R2, R3, IP, LR)
    e.save_flags(R3)
    e.push(R3, R4)
    e.call_abs(ADDR_ACTIVE_UI)
    e.cmp_u8(R0, 0)
    e.j_cond(COND_EQ, "std")
    e.mov_reg(R5, R0)
    e.j_local("done")
    e.label("std")
    e.ldr_s8(R5, R7, 3)
    e.label("done")
    e.pop(R3, R4)
    e.restore_flags(R3)
    e.pop(R0, R1, R2, R3, IP, LR)
    e.jump_abs(0x1037A8C0)
    return e.finish()


def emit_ui_sp8() -> bytes:
    e = ThumbEmitter(ADDR_UI_SP8)
    e.push(R0, R1, R2, R3, IP, LR)
    e.save_flags(R3)
    e.push(R3, R5)
    e.call_abs(ADDR_ACTIVE_UI)
    e.cmp_u8(R0, 0)
    e.j_cond(COND_EQ, "std")
    e.mov_reg(R4, R0)
    e.j_local("done")
    e.label("std")
    e.ldr_u32(R0, SP, 8)
    e.ldr_s8(R4, R0, 3)
    e.label("done")
    e.pop(R3, R5)
    e.restore_flags(R3)
    e.pop(R0, R1, R2, R3, IP, LR)
    e.jump_abs(0x1041E71E)
    return e.finish()


def emit_ui_rat() -> bytes:
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
    e.ldr_u8(R3, R3, 0)
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


def emit_range_adapters() -> list[tuple[int, str, bytes, str]]:
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

    e3 = ThumbEmitter(ADDR_RANGE_3)
    e3.cmp_u8(R4, UI_FIRST)
    e3.j_cond(COND_CC, "std")
    e3.cmp_u8(R4, UI_LAST)
    e3.j_cond(COND_GT, "std")
    e3.adds_u3(R0, R4, 1)
    e3.jump_abs(0x1041E554)
    e3.label("std")
    e3.adds_u3(R0, R4, 1)
    e3.j_cond(COND_EQ, "eq84")
    e3.jump_abs(0x1041E54A)
    e3.label("eq84")
    e3.jump_abs(0x1041E584)
    out.append((ADDR_RANGE_3, "m600_ui_display", e3.finish(), "LV/EVF shutter formatter range check 1"))

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


def emit_top_oled() -> bytes:
    e = ThumbEmitter(ADDR_TOP_OLED)
    e.push(R0, R1, R2, R3, R4, R5, R6, R7, IP, LR)
    e.set_u32(R0, 0xC24CCA14)
    e.ldr_u32(R0, R0, 0)
    e.cmp_u8(R0, 1)
    e.j_cond(COND_LS, "orig")
    e.call_abs(ADDR_ACTIVE_UI)
    e.cmp_u8(R0, 0)
    e.j_cond(COND_EQ, "orig")
    e.mov_reg(R3, R1)
    e.mov_u16(R0, 1)
    e.str_u8(R0, R4, 7)
    e.mov_u16(R0, 0)
    e.str_u8(R0, R4, 8)
    e.mov_u16(R1, 0)
    e.label("h_loop")
    e.cmp_u8(R3, 100)
    e.j_cond(COND_CC, "h_done")
    e.subs_u8(R3, 100)
    e.adds_u3(R1, R1, 1)
    e.j_local("h_loop")
    e.label("h_done")
    e.cmp_u8(R1, 0)
    e.j_cond(COND_NE, "h_store")
    e.mov_u16(R1, 0xFF)
    e.label("h_store")
    e.str_u8(R1, R4, 9)
    e.mov_u16(R1, 0)
    e.label("t_loop")
    e.cmp_u8(R3, 10)
    e.j_cond(COND_CC, "t_done")
    e.subs_u8(R3, 10)
    e.adds_u3(R1, R1, 1)
    e.j_local("t_loop")
    e.label("t_done")
    e.str_u8(R1, R4, 10)
    e.str_u8(R3, R4, 11)
    e.mov_u16(R0, 0x0B)
    e.str_u8(R0, R4, 12)
    e.mov_u16(R0, 0)
    e.str_u8(R0, R4, 13)
    e.mov_u16(R0, 2)
    e.call_abs(0x1053BBCE)
    e.adds_u3(R1, R0, 1)
    e.j_cond(COND_EQ, "chk3")
    e.cmp_u8(R0, 0)
    e.j_cond(COND_EQ, "chk3")
    e.mov_u16(R0, 1)
    e.str_u8(R0, R4, 5)
    e.label("chk3")
    e.mov_u16(R0, 3)
    e.call_abs(0x1053BBCE)
    e.adds_u3(R1, R0, 1)
    e.j_cond(COND_EQ, "finish_ext")
    e.cmp_u8(R0, 0)
    e.j_cond(COND_EQ, "finish_ext")
    e.mov_u16(R0, 1)
    e.str_u8(R0, R4, 6)
    e.label("finish_ext")
    e.pop(R0, R1, R2, R3, R4, R5, R6, R7, IP, LR)
    e.mov_u16(R8, 1)
    e.jump_abs(0x1053B1C6)
    e.label("orig")
    e.pop(R0, R1, R2, R3, R4, R5, R6, R7, IP, LR)
    e.call_abs(0x1053BBCE)
    e.jump_abs(0x1053B172)
    return e.finish()


def emit_ptp_gate() -> bytes:
    e = ThumbEmitter(ADDR_PTP_GATE)
    e.push(R0, R1, R2, R3, IP, LR)
    e.set_u32(R1, 300_000)
    e.cmp_reg(R0, R1)
    e.j_cond(COND_LS, "pass")
    e.set_u32(R1, 6_000_000)
    e.cmp_reg(R0, R1)
    e.j_cond(COND_GT, "pass")
    e.set_u32(R2, 0xC24CC8FC)
    e.ldr_u32(R2, R2, 0)
    e.cmp_u8(R2, 3)
    e.j_cond(COND_NE, "reject")
    e.set_u32(R2, 0xC24CC980)
    e.ldr_u8(R2, R2, 0)
    e.cmp_u8(R2, 0)
    e.j_cond(COND_NE, "reject")
    e.set_u32(R2, 0xC24CC790)
    e.ldr_u8(R2, R2, 0)
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


def build_ui_routines() -> list[tuple[int, str, bytes, str]]:
    out = [
        (ADDR_ACTIVE_UI, "m600_ui_display", emit_active_ui(), "Active M-still extended shutter UI-ID resolver"),
        (ADDR_UI_R8, "m600_ui_display", emit_ui_r8(), "Extended shutter UI-ID adapter at 0x1036a7cc"),
        (ADDR_UI_R7, "m600_ui_display", emit_ui_r7(), "Extended shutter UI-ID adapter at 0x1037a8bc"),
        (ADDR_UI_SP8, "m600_ui_display", emit_ui_sp8(), "Extended shutter UI-ID adapter at 0x1041e71a"),
        (ADDR_UI_RAT, "m600_ui_display", emit_ui_rat(), "Extended shutter rational-to-UI adapter at 0x10473810"),
    ]
    out.extend(emit_range_adapters())
    out.append((ADDR_TOP_OLED, "m600_top_oled", emit_top_oled(), "Top-OLED 3-digit seconds BCD formatter for 60s-600s"))
    out.append((ADDR_PTP_GATE, "m600_ptp_tables", emit_ptp_gate(), "PTP 0x500D mode gate rejecting 60s-600s outside M still"))
    return out

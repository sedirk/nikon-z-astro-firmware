"""Unicorn ARM/Thumb native execution suite for Nikon Z6 C3.80 30-600s extension."""
from __future__ import annotations
import gc
import struct
import unicorn as un
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_SB,
    UC_ARM_REG_SP,
)

from z6_m600_emu_extra import run_extra_m600_tests
from z6_m600_tables import (
    ADDR_ACTIVE_UI,
    ADDR_ALLOWED_TV,
    ADDR_DIAL_BURST,
    ADDR_DIAL_STEP,
    ADDR_MIN_TV8,
    ADDR_RANGE_1,
    ADDR_RANGE_2,
    ADDR_RANGE_3,
    ADDR_RANGE_4,
    ADDR_TOP_OLED,
    ADDR_UI_R7,
    ADDR_UI_R8,
    ADDR_UI_RAT,
    ADDR_UI_SP8,
    BASE,
    EXT_SLOW_TO_FAST,
    EXT_STEPS,
    IDX_30S,
    IDX_600S,
    IDX_60S,
    M_COUNT,
    STOCK_M_COUNT,
)

STOP_PC = 0x1FFE0000
SCRATCH = 0x20000000
STACK_TOP = 0x2005F000
POOL_RAM = 0xC9700000


class M600Harness:
    def __init__(self, blob: bytes) -> None:
        self.uc = un.Uc(un.UC_ARCH_ARM, un.UC_MODE_THUMB)
        rom_sz = (len(blob) + 4095) & ~4095
        self.uc.mem_map(BASE, rom_sz)
        self.uc.mem_write(BASE, blob)
        self.uc.mem_map(STOP_PC, 0x1000)
        self.uc.mem_map(SCRATCH, 0x60000)
        self.uc.mem_map(0xC1800000, 0x1800000)
        self.uc.mem_map(POOL_RAM, 0x100000)
        scatter_off = 0x11E94DD4 - BASE
        self.uc.mem_write(0xC1800000, blob[scatter_off : scatter_off + 0x101400])
        self.uc.mem_write(0xC18FD938, struct.pack("<I", POOL_RAM))
        self.stubs: dict[int, callable] = {
            0x10170DF0: lambda u: None,
            0x10170DEA: lambda u: None,
            0x10170D48: lambda u: None,
        }
        self.uc.hook_add(un.UC_HOOK_CODE, self._on_code)

    def _on_code(self, uc: un.Uc, addr: int, size: int, data: object) -> None:
        fn = self.stubs.get(addr)
        if fn is not None:
            fn(uc)
            lr = uc.reg_read(UC_ARM_REG_LR)
            uc.reg_write(UC_ARM_REG_PC, lr)

    def set_camera_mode(self, exp_mode: int = 3, movie: int = 0, sub: int = 0, tv_s24: int = -144) -> None:
        self.uc.mem_write(0xC24CC8FC, struct.pack("<I", exp_mode))
        self.uc.mem_write(0xC24CC980, struct.pack("B", movie))
        self.uc.mem_write(0xC24CC790, struct.pack("B", sub))
        self.uc.mem_write(0xC24CD9C0, struct.pack("<h", tv_s24))

    def call(self, addr: int, r0: int = 0, r1: int = 0, r2: int = 0, r3: int = 0, until: int = STOP_PC) -> tuple[int, int]:
        u = self.uc
        u.reg_write(UC_ARM_REG_SP, STACK_TOP)
        u.reg_write(UC_ARM_REG_LR, STOP_PC | 1)
        u.reg_write(UC_ARM_REG_R0, r0 & 0xFFFFFFFF)
        u.reg_write(UC_ARM_REG_R1, r1 & 0xFFFFFFFF)
        u.reg_write(UC_ARM_REG_R2, r2 & 0xFFFFFFFF)
        u.reg_write(UC_ARM_REG_R3, r3 & 0xFFFFFFFF)
        u.emu_start(addr | 1, until)
        return u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)


def run_all_m600_tests(blob: bytes) -> dict:
    h = M600Harness(blob)
    u = h.uc

    # 1. Boot pool alloc + M-table getter + pool reset invalidation + sentinel fallback
    h.call(0x101120DC)
    base_ptr, req_sz = struct.unpack("<II", u.mem_read(0xC1F88798, 8))
    bump_after = struct.unpack("<I", u.mem_read(0xC18FD938, 4))[0]
    assert base_ptr == POOL_RAM and req_sz == 0x754E0 and bump_after == POOL_RAM + 0x75D80

    cnt_box = SCRATCH + 0x100
    mtbl_ptr, _ = h.call(0x10090102, cnt_box)
    cnt_val = struct.unpack("<I", u.mem_read(cnt_box, 4))[0]
    assert cnt_val == M_COUNT and mtbl_ptr == POOL_RAM + 0x75540
    entries = [struct.unpack("<4i", u.mem_read(mtbl_ptr + i * 16, 16)) for i in range(15)]
    assert [e[1] for e in entries[3:11]] == [t[0] for t in EXT_SLOW_TO_FAST]
    assert entries[11][1] == -120

    # Pool reset must invalidate dynamic M-table and fall back cleanly to stock 112-entry RAM table
    h.stubs[0x101E59BC] = lambda uc: None
    h.call(0x101E5B98)
    mtbl_after_reset, _ = h.call(0x10090102, cnt_box)
    cnt_after_reset = struct.unpack("<I", u.mem_read(cnt_box, 4))[0]
    assert cnt_after_reset == STOCK_M_COUNT and mtbl_after_reset == 0xC1816920

    # Re-allocate for subsequent tests
    h.call(0x101120DC)

    # Sentinel 0x7FFFFFFF index clamp check
    out_idx = SCRATCH + 0x200
    for tbl_len, expected_idx in ((M_COUNT, IDX_30S), (STOCK_M_COUNT, 3)):
        u.reg_write(UC_ARM_REG_SP, STACK_TOP)
        u.mem_write(STACK_TOP + 0x1F0, struct.pack("<I", tbl_len))
        u.mem_write(STACK_TOP + 0x1F8, struct.pack("<I", 0))
        u.mem_write(STACK_TOP + 0x1FC, struct.pack("<i", -180))
        u.reg_write(UC_ARM_REG_R0, 0x7FFFFFFF)
        u.reg_write(UC_ARM_REG_R4, mtbl_ptr)
        u.reg_write(UC_ARM_REG_R5, out_idx)
        u.emu_start(0x1012ED8E | 1, 0x1012ED94)
        assert struct.unpack("<I", u.mem_read(out_idx, 4))[0] == expected_idx

    # 2. Exposure timers (us & 64-bit ns) and EXIF rational across all 8 steps + stock 30s
    rat_box = SCRATCH + 0x300
    exif_box = SCRATCH + 0x320
    timer_rows = []
    for tv, ui_id, sec, label in EXT_STEPS:
        # Deliberately include non-zero upper halfword on scale to verify s16 load safety
        u.mem_write(rat_box, struct.pack("<hHi", 24, 0xBEEF, tv))
        us_lo, us_hi = h.call(0x101C486E, rat_box)
        ns_lo, ns_hi = h.call(0x1011C14A, rat_box)
        h.call(0x101C4790, rat_box, exif_box)
        exif_num, exif_den = struct.unpack("<II", u.mem_read(exif_box, 8))
        ns_64 = (ns_hi << 32) | ns_lo
        assert us_lo == sec * 1_000_000 and us_hi == 0
        assert ns_64 == sec * 1_000_000_000
        assert (exif_num, exif_den) == (sec * 10, 10)
        timer_rows.append({"label": label, "seconds": sec, "us": us_lo, "ns": ns_64, "exif": [exif_num, exif_den]})

    # Stock 30" (-5 EV = 2^5 = 32,000,000 us) exact passthrough check
    u.mem_write(rat_box, struct.pack("<ii", 24, -120))
    us_30s, us_30s_hi = h.call(0x101C486E, rat_box)
    ns_30s_lo, ns_30s_hi = h.call(0x1011C14A, rat_box)
    assert (us_30s, us_30s_hi) == (32_000_000, 0)
    assert ((ns_30s_hi << 32) | ns_30s_lo) == 32_000_000_000

    # 3. Single-step dial mapping, burst stop, allowed-Tv filter, and min-Tv*8 clamp
    u.reg_write(UC_ARM_REG_SP, STACK_TOP)
    u.mem_write(STACK_TOP + 0x14, struct.pack("<I", M_COUNT))
    u.mem_write(mtbl_ptr + 3 * 16 + 0x0C, struct.pack("<I", 1))
    dial_chain_down = []
    cur = IDX_30S
    for _ in range(9):
        u.reg_write(UC_ARM_REG_SP, STACK_TOP)
        u.reg_write(UC_ARM_REG_R6, mtbl_ptr)
        u.reg_write(UC_ARM_REG_R8, cur)
        u.reg_write(UC_ARM_REG_R0, cur - 1)
        u.reg_write(UC_ARM_REG_SB, 0)
        u.emu_start(ADDR_DIAL_STEP | 1, 0x1012A6D2)
        cur = u.reg_read(UC_ARM_REG_R0)
        dial_chain_down.append(cur)
    assert dial_chain_down == [10, 9, 8, 7, 6, 5, 4, 3, 2]
    # Verify stepping back up from Bulb/Time (idx 2) lands on 600" (idx 3) even on multi-step jump
    u.reg_write(UC_ARM_REG_SP, STACK_TOP)
    u.reg_write(UC_ARM_REG_R6, mtbl_ptr)
    u.reg_write(UC_ARM_REG_R8, 2)
    u.reg_write(UC_ARM_REG_R0, 5)
    u.reg_write(UC_ARM_REG_SB, 1)
    u.emu_start(ADDR_DIAL_STEP | 1, 0x1012A6E2)
    assert u.reg_read(UC_ARM_REG_R0) == IDX_600S

    # Min Tv*8 clamp at 0x100dad66..0x100dad6c: preserves -1792 in M still, clamps to -960 in A mode
    r6_box = SCRATCH + 0x400
    for exp_m, want_tv8 in ((3, -1792), (2, -960)):
        h.set_camera_mode(exp_mode=exp_m, movie=0, sub=0, tv_s24=-224)
        u.mem_write(r6_box, struct.pack("B", exp_m))
        u.reg_write(UC_ARM_REG_SP, STACK_TOP)
        u.reg_write(UC_ARM_REG_R6, r6_box)
        u.reg_write(UC_ARM_REG_R4, (-1792) & 0xFFFFFFFF)
        u.reg_write(UC_ARM_REG_R7, (-1792) & 0xFFFFFFFF)
        u.reg_write(UC_ARM_REG_R5, (-960) & 0xFFFFFFFF)
        u.emu_start(0x100DAD66 | 1, 0x100DAD6C)
        got = u.reg_read(UC_ARM_REG_R4)
        if got >= 0x80000000:
            got -= 0x100000000
        assert got == want_tv8

    # 4. UI IDs, Top-OLED 3-digit BCD, and PTP 0x500D mode gate
    h.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=-224)
    ui_id, sec_val = h.call(ADDR_ACTIVE_UI)
    assert (ui_id, sec_val) == (74, 600)

    h.set_camera_mode(exp_mode=2, movie=0, sub=0, tv_s24=-224)
    ui_non_m, _ = h.call(ADDR_ACTIVE_UI)
    assert ui_non_m == 0

    # Top OLED formatting for 60" and 600"
    oled_buf = SCRATCH + 0x500
    u.mem_write(0xC24CCA14, struct.pack("<I", 2))
    h.stubs[0x1053BBCE] = lambda uc: uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFFF)
    for tv, want_digits in ((-144, (0xFF, 6, 0, 0x0B, 0)), (-224, (6, 0, 0, 0x0B, 0))):
        h.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=tv)
        u.mem_write(oled_buf, b"\x00" * 32)
        u.reg_write(UC_ARM_REG_SP, STACK_TOP)
        u.reg_write(UC_ARM_REG_R4, oled_buf)
        u.reg_write(UC_ARM_REG_R0, 1)
        u.emu_start(ADDR_TOP_OLED | 1, 0x1053B1C6)
        digits = tuple(u.mem_read(oled_buf + 9, 5))
        assert digits == want_digits and u.reg_read(UC_ARM_REG_R8) == 1

    # PTP 0x500D validator (0x10331640) in M-still vs non-M-still
    h.stubs[0x104014DE] = lambda uc: uc.reg_write(UC_ARM_REG_R0, (-120) & 0xFFFFFFFF)
    h.stubs[0x1034037C] = lambda uc: uc.reg_write(UC_ARM_REG_R0, 0x2001)
    out_m, out_tv = SCRATCH + 0x600, SCRATCH + 0x604
    h.set_camera_mode(exp_mode=3, movie=0, sub=0)
    rc_ok, _ = h.call(0x10331640, 6_000_000, out_m, out_tv)
    got_tv = struct.unpack("<i", u.mem_read(out_tv, 4))[0]
    assert rc_ok == 0x2001 and got_tv == -224

    h.set_camera_mode(exp_mode=2, movie=0, sub=0)
    rc_rej, _ = h.call(0x10331640, 6_000_000, out_m, out_tv)
    assert rc_rej == 0x201C

    extra = run_extra_m600_tests(h, mtbl_ptr)

    h.uc = None
    del h
    gc.collect()
    return {
        "pool_and_mtbl_ok": True,
        "pool_reset_invalidation_ok": True,
        "sentinel_fallback_ok": True,
        "timers_and_exif": timer_rows,
        "dial_chain_30s_to_600s": dial_chain_down,
        "min_tv8_clamp_ok": True,
        "top_oled_bcd_ok": True,
        "ptp_500d_mode_gate_ok": True,
        **extra,
    }

"""Unicorn ARM/Thumb execution harness for Nikon Z6 C3.80 Modified15 (30-600s v2).

Modeled vs Native Boundaries:
  - ROM (0x10020000..+33.5MB) is mapped strictly UC_PROT_READ | UC_PROT_EXEC; page 0 is unmapped.
  - Scalar property storage at 0xC24C0000.. is initialized from ROM's 0x114D4FF8 table, and scalar
    property getters (0x1015BEBE / 0x104014DE / 0x1017039E -> 0x100700A0) execute NATIVELY from ROM
    (no Python getter dictionary).
  - Property list publisher (0x1020931C), getter (0x102090DA / 0x1015BEDA / 0x10401668), allowlist
    validator (0x10209636 / 0x10401670 / 0x1034037C), snap-to-nearest (0x10401684), M-table refresh
    (0x1012EC70 / 0x1012D464), command-dial handlers (0x1012A752 / 0x1012A68C), and ARM libc strncpy
    (0x1023B50C) execute natively from ROM.
  - RTOS primitives (mutexes, task sleep, heap alloc/free), asynchronous IPC scalar commit
    (0x1015BEB6 / 0x10401630, modeled synchronously by writing 32-bit registered RAM slots and
    updating 0x1319 at 0xC24CC790, cross-checked against native 0x10070366 + 0x1014CD5A), dial
    permission gate (0x101308C2), and PTP hardware readback polling are explicitly stubbed.
"""
from __future__ import annotations
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

from z6_m600_tables import (
    ADDR_ACTIVE_UI,
    ADDR_STR_PTR_TBL,
    ADDR_TOP_OLED,
    BASE,
    EXT_SLOW_TO_FAST,
    EXT_STEPS,
    IDX_30S,
    IDX_600S,
    M_COUNT,
    STOCK_M_COUNT,
    UI_FIRST,
    UI_LAST,
)
from z6_m600_v2 import ADDR_DIAL_STEP_V2

STOP_PC = 0x1FFE0000
SCRATCH = 0x20000000
HEAP_BASE = 0x20030000
STACK_TOP = 0x2005F000
POOL_RAM = 0xC9700000

EXP_MODE_TO_PROP_0002 = {0: 0x1D, 1: 0x1F, 2: 0x21, 3: 0x20}


def _load_scalar_ram_map(blob: bytes) -> dict[int, tuple[int, int, int]]:
    """Parse ROM's 0x114D4FF8 scalar property table -> {pid: (type_id, ram_addr, default_i32)}."""
    grp_tbl = struct.unpack_from("<I", blob, ((0x10070082 + 4) & ~3) + 0x3F0 - BASE)[0]
    ent_tbl = struct.unpack_from("<I", blob, 0x10070478 - BASE)[0]
    out: dict[int, tuple[int, int, int]] = {}
    for hi in range(0x20):
        base_idx, cnt = struct.unpack_from("<HH", blob, grp_tbl + hi * 28 - BASE + 0x0C)
        for lo in range(cnt):
            eoff = ent_tbl + (base_idx + lo) * 16 - BASE
            tp, _, ram_addr, dflt_ptr = struct.unpack_from("<IIII", blob, eoff)
            tp_lo = tp & 0xFF
            if 0xC1800000 <= ram_addr < 0xC3000000 and tp_lo < 8:
                dval = 0
                if BASE <= dflt_ptr <= BASE + len(blob) - 4:
                    dval = struct.unpack_from("<i", blob, dflt_ptr - BASE)[0]
                out[(hi << 8) | lo] = (tp_lo, ram_addr, dval)
    return out


class M600V2Harness:
    """Unicorn harness with READ|EXEC ROM and native ROM scalar property getters."""

    def __init__(self, blob: bytes) -> None:
        self.uc = un.Uc(un.UC_ARCH_ARM, un.UC_MODE_THUMB)
        rom_sz = (len(blob) + 4095) & ~4095
        self.uc.mem_map(BASE, rom_sz, un.UC_PROT_READ | un.UC_PROT_EXEC)
        self.uc.mem_write(BASE, blob)
        self.uc.mem_map(STOP_PC, 0x1000, un.UC_PROT_READ | un.UC_PROT_EXEC)
        self.uc.mem_map(SCRATCH, 0x60000)
        self.uc.mem_map(0xC1800000, 0x1800000)
        self.uc.mem_map(POOL_RAM, 0x100000)
        scatter_off = 0x11E94DD4 - BASE
        self.uc.mem_write(0xC1800000, blob[scatter_off : scatter_off + 0x101400])
        self.uc.mem_write(0xC18FD938, struct.pack("<I", POOL_RAM))

        self.scalar_map = _load_scalar_ram_map(blob)
        for _pid, (_tp, ram_addr, dval) in self.scalar_map.items():
            self.uc.mem_write(ram_addr, struct.pack("<i", dval))

        self.heap_ptr = HEAP_BASE
        self.prop_notify_count = 0
        self.lv_draw_calls: list[tuple[int, int, int, str]] = []
        self.committed_batches: list[tuple[tuple[int, ...], tuple[int, ...]]] = []

        # Default camera scalars in native 32-bit RAM slots
        self.set_scalar(0x1034, -120)
        self.set_scalar(0x1035, 312)
        self.set_scalar(0x1013, 2)
        self.set_scalar(0x1066, 0)
        self.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=-120)

        def _heap_alloc(u: un.Uc) -> None:
            sz = (u.reg_read(UC_ARM_REG_R0) + 15) & ~15
            ptr = self.heap_ptr
            self.heap_ptr += max(sz, 16)
            u.reg_write(UC_ARM_REG_R0, ptr)

        def _commit_scalars(u: un.Uc) -> None:
            p_ids = u.reg_read(UC_ARM_REG_R0)
            p_vals = u.reg_read(UC_ARM_REG_R1)
            cnt = u.reg_read(UC_ARM_REG_R2)
            ids = struct.unpack(f"<{cnt}I", u.mem_read(p_ids, cnt * 4))
            vals = struct.unpack(f"<{cnt}i", u.mem_read(p_vals, cnt * 4))
            for pid, val in zip(ids, vals):
                self.set_scalar(pid & 0xFFFF, val)
            self._sync_derived_1319()
            self.committed_batches.append((ids, vals))
            u.reg_write(UC_ARM_REG_R0, 0)

        def _prop_notify(_u: un.Uc) -> None:
            self.prop_notify_count += 1

        def _lv_draw(u: un.Uc) -> None:
            r0 = u.reg_read(UC_ARM_REG_R0)
            r1 = u.reg_read(UC_ARM_REG_R1)
            r2 = u.reg_read(UC_ARM_REG_R2)
            r3 = u.reg_read(UC_ARM_REG_R3)
            raw = bytes(u.mem_read(r3, 8)).split(b"\x00", 1)[0].decode("latin1")
            self.lv_draw_calls.append((r0, r1, r2, raw))

        self.stubs: dict[int, object] = {
            0x10170DF0: lambda u: None,
            0x10170DEA: lambda u: None,
            0x10170D48: lambda u: None,
            0x10170CCA: lambda u: None,
            0x10164A44: _heap_alloc,
            0x10164A56: lambda u: None,
            0x10117CDA: _prop_notify,
            0x10117CD2: _prop_notify,
            0x1015BEB6: _commit_scalars,
            0x10401630: _commit_scalars,
            0x101308C2: lambda u: u.reg_write(UC_ARM_REG_R0, 1),
            0x10330752: lambda u: u.reg_write(UC_ARM_REG_R0, 0),
            0x103307E8: lambda u: u.reg_write(UC_ARM_REG_R0, 0),
            0x10340404: lambda u: None,
            0x103AD7B4: lambda u: u.reg_write(UC_ARM_REG_R0, 1),
            0x1040E7BC: lambda u: u.reg_write(UC_ARM_REG_R0, 0),
            0x1041DF0C: _lv_draw,
        }
        self.uc.hook_add(un.UC_HOOK_CODE, self._on_code)

    def _on_code(self, uc: un.Uc, addr: int, _size: int, _data: object) -> None:
        fn = self.stubs.get(addr)
        if fn is not None:
            fn(uc)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def set_scalar(self, pid: int, val: int) -> None:
        _tp, ram_addr, _dflt = self.scalar_map[pid]
        self.uc.mem_write(ram_addr, struct.pack("<i", val))

    def get_scalar(self, pid: int) -> int:
        _tp, ram_addr, _dflt = self.scalar_map[pid]
        return struct.unpack("<i", self.uc.mem_read(ram_addr, 4))[0]

    def _sync_derived_1319(self) -> None:
        exp_m = self.get_scalar(0x136F)
        mov = self.get_scalar(0x138D)
        mode_20d = self.get_scalar(0x020D)
        derived = mode_20d if (exp_m == 3 and mov == 0) else 0
        self.set_scalar(0x1319, derived)

    def set_camera_mode(self, exp_mode: int = 3, movie: int = 0, sub: int = 0, tv_s24: int = -144) -> None:
        self.set_scalar(0x136F, exp_mode)
        self.set_scalar(0x0002, EXP_MODE_TO_PROP_0002.get(exp_mode, 0))
        self.set_scalar(0x138D, movie)
        self.set_scalar(0x020D, sub)
        self.set_scalar(0x0204, tv_s24)
        self._sync_derived_1319()

    def call(
        self, addr: int, r0: int = 0, r1: int = 0, r2: int = 0, r3: int = 0, until: int = STOP_PC
    ) -> tuple[int, int]:
        u = self.uc
        u.reg_write(UC_ARM_REG_SP, STACK_TOP)
        u.reg_write(UC_ARM_REG_LR, STOP_PC | 1)
        u.reg_write(UC_ARM_REG_R0, r0 & 0xFFFFFFFF)
        u.reg_write(UC_ARM_REG_R1, r1 & 0xFFFFFFFF)
        u.reg_write(UC_ARM_REG_R2, r2 & 0xFFFFFFFF)
        u.reg_write(UC_ARM_REG_R3, r3 & 0xFFFFFFFF)
        u.emu_start(addr | 1, until)
        return u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)


def run_core_and_ui_tests(h: M600V2Harness) -> dict:
    u = h.uc

    # 0. Cross-verify native ROM scalar setter (0x10070366), getter (0x1015BEBE / 0x104014DE),
    #    and native 0x1319 builder (0x1014CD5A) against _sync_derived_1319!
    chg_box = SCRATCH + 0x80
    ctx_1319 = SCRATCH + 0x900
    q_1319 = SCRATCH + 0xA00
    q_ids = SCRATCH + 0xAC0
    q_vals = SCRATCH + 0xAE0
    q_sub = SCRATCH + 0xAF0
    u.mem_write(q_sub, struct.pack("<II", 0, 0))
    for exp_m, mov, m20d, want_1319 in (
        (3, 0, 0, 0),
        (3, 0, 1, 1),
        (3, 0, 2, 2),
        (3, 0, 3, 3),
        (2, 0, 2, 0),
        (1, 0, 1, 0),
        (0, 0, 2, 0),
        (3, 1, 2, 0),
    ):
        assert h.call(0x10070366, 0x020D, m20d, chg_box)[0] == 1
        assert h.call(0x1015BEBE, 0x020D)[0] == m20d
        u.mem_write(ctx_1319, b"\x00" * 0x40)
        u.mem_write(ctx_1319 + 0x04, struct.pack("<i", m20d))
        u.mem_write(ctx_1319 + 0x08, struct.pack("<i", -1))
        u.mem_write(ctx_1319 + 0x0C, struct.pack("<i", EXP_MODE_TO_PROP_0002[exp_m]))
        u.mem_write(ctx_1319 + 0x18, struct.pack("<i", mov))
        u.mem_write(ctx_1319 + 0x28, struct.pack("<i", mov))
        u.mem_write(q_1319, b"\x00" * 0xB0)
        u.mem_write(q_1319, struct.pack("<IIII", 4, 0, q_ids, q_vals))
        u.mem_write(q_1319 + 0xA0, struct.pack("<I", q_sub))
        assert h.call(0x1014CD5A, 0, ctx_1319, q_1319)[0] == 1
        got_1319 = struct.unpack("<i", u.mem_read(q_vals, 4))[0]
        assert got_1319 == want_1319
        h.set_camera_mode(exp_mode=exp_m, movie=mov, sub=m20d, tv_s24=-224)
        assert h.call(0x1015BEBE, 0x1319)[0] == want_1319
        res_204 = h.call(0x104014DE, 0x0204)[0]
        assert (res_204 - 0x100000000 if res_204 >= 0x80000000 else res_204) == -224

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

    h.stubs[0x101E59BC] = lambda _uc: None
    h.call(0x101E5B98)
    mtbl_after_reset, _ = h.call(0x10090102, cnt_box)
    cnt_after_reset = struct.unpack("<I", u.mem_read(cnt_box, 4))[0]
    assert cnt_after_reset == STOCK_M_COUNT and mtbl_after_reset == 0xC1816920

    h.call(0x101120DC)

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

    # 2. Exposure timers (us & 64-bit ns) and EXIF rational across all 8 extended steps + stock 30"
    rat_box = SCRATCH + 0x300
    exif_box = SCRATCH + 0x320
    timer_rows = []
    for tv, _ui_id, sec, label in EXT_STEPS:
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

    u.mem_write(rat_box, struct.pack("<ii", 24, -120))
    us_30s, us_30s_hi = h.call(0x101C486E, rat_box)
    ns_30s_lo, ns_30s_hi = h.call(0x1011C14A, rat_box)
    assert (us_30s, us_30s_hi) == (32_000_000, 0)
    assert ((ns_30s_hi << 32) | ns_30s_lo) == 32_000_000_000

    # 3. Min Tv*8 clamp (0x100dad66) & ADDR_ACTIVE_UI across Timed (0) vs Bulb (1) / Time (2) / x200 (3) / A-mode
    r6_box = SCRATCH + 0x400
    for exp_m, sub_m, want_tv8, want_ui in (
        (3, 0, -1792, 74),
        (3, 1, -960, 0),
        (3, 2, -960, 0),
        (3, 3, -960, 0),
        (2, 0, -960, 0),
    ):
        h.set_camera_mode(exp_mode=exp_m, movie=0, sub=sub_m, tv_s24=-224)
        assert h.call(ADDR_ACTIVE_UI)[0] == want_ui
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

    # Verify ADDR_DIAL_STEP_V2 preserves R0=1 (Time) when Bulb (mtbl[2]) is disabled
    u.mem_write(STACK_TOP + 0x14, struct.pack("<I", M_COUNT))
    u.mem_write(mtbl_ptr + 1 * 16 + 0x0C, struct.pack("<I", 1))
    u.mem_write(mtbl_ptr + 2 * 16 + 0x0C, struct.pack("<I", 0))
    u.mem_write(mtbl_ptr + 3 * 16 + 0x0C, struct.pack("<I", 1))
    u.reg_write(UC_ARM_REG_SP, STACK_TOP)
    u.reg_write(UC_ARM_REG_R6, mtbl_ptr)
    u.reg_write(UC_ARM_REG_R8, IDX_600S)
    u.reg_write(UC_ARM_REG_R0, 1)
    u.reg_write(UC_ARM_REG_SB, 1)
    u.emu_start(ADDR_DIAL_STEP_V2 | 1, 0x1012A6E2)
    assert u.reg_read(UC_ARM_REG_R0) == 1

    # 4. UI adapters, 4 UI range checks (including negative IDs), and Top-OLED 3-digit BCD
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
        assert tuple(u.mem_read(oled_buf + 9, 5)) == want_digits and u.reg_read(UC_ARM_REG_R8) == 1

    r6_ui = SCRATCH + 0x700
    r8_ui = SCRATCH + 0x740
    h.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=-180)
    u.mem_write(r6_ui, b"\x00" * 0x40)
    u.mem_write(r8_ui, struct.pack("b", 12))
    u.reg_write(UC_ARM_REG_SP, STACK_TOP)
    u.reg_write(UC_ARM_REG_R6, r6_ui)
    u.reg_write(UC_ARM_REG_R8, r8_ui)
    u.emu_start(0x1036A7CC | 1, 0x1036A7D4)
    assert u.reg_read(UC_ARM_REG_R0) == 70

    h.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=-200)
    u.mem_write(r8_ui, b"\x00\x00\x00\x0f")
    u.reg_write(UC_ARM_REG_SP, STACK_TOP)
    u.reg_write(UC_ARM_REG_R7, r8_ui)
    u.emu_start(0x1037A8BC | 1, 0x1037A8C0)
    assert u.reg_read(UC_ARM_REG_R5) == 72

    u.reg_write(UC_ARM_REG_SP, STACK_TOP)
    u.reg_write(UC_ARM_REG_R0, r8_ui)
    u.emu_start(0x1041E71A | 1, 0x1041E71E)
    assert u.reg_read(UC_ARM_REG_R4) == 72

    h.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=-224)
    sp_base = STACK_TOP - 0x400
    u.reg_write(UC_ARM_REG_SP, sp_base)
    u.mem_write(sp_base + 0x1C4, struct.pack("<ii", 24, -224))
    u.mem_write(r6_ui + 0x30, struct.pack("<I", 0xABCD1234))
    u.reg_write(UC_ARM_REG_R4, r6_ui)
    u.reg_write(UC_ARM_REG_R5, 0)
    u.emu_start(0x10473810 | 1, 0x10473828)
    assert u.reg_read(UC_ARM_REG_R0) == 74 and u.reg_read(UC_ARM_REG_R1) == 0xABCD1234

    for uid in (UI_FIRST, UI_LAST):
        u.reg_write(UC_ARM_REG_R4, uid)
        u.emu_start(0x102F9E94 | 1, 0x102F9EB2)
        u.reg_write(UC_ARM_REG_R1, uid)
        u.emu_start(0x102F9EBC | 1, 0x102F9ECC)
        u.reg_write(UC_ARM_REG_R4, uid)
        u.emu_start(0x1041E546 | 1, 0x1041E554)
        assert u.reg_read(UC_ARM_REG_R0) == uid + 1
        u.reg_write(UC_ARM_REG_R4, uid)
        u.emu_start(0x1041E730 | 1, 0x1041E766)

    # Sentinel -1 on ADDR_RANGE_3 must jump to 0x1041E584 (not 0x1041E554!)
    u.reg_write(UC_ARM_REG_R4, 0xFFFFFFFF)
    u.emu_start(0x1041E546 | 1, 0x1041E584)
    assert u.reg_read(UC_ARM_REG_R0) == 0

    # 5. Native LV/EVF 0x1041E714 -> 0x1041E51C -> ARM 0x1023B50C strncpy with ui_id = -1 sentinel & ui_id = 74
    assert struct.unpack("<I", u.mem_read(ADDR_STR_PTR_TBL - 4, 4))[0] == 0x11BA8D58
    font_tbl = SCRATCH + 0x680
    u.mem_write(font_tbl, struct.pack("<8H", *([0x11] * 8)))
    u.mem_write(0xC182A350 + 0x10, struct.pack("<I", font_tbl))
    u.mem_write(0xC182A6F4 + 0x41, b"\x01")
    assert h.call(0x103AD8DA, 2, 2)[0] == 1

    h.lv_draw_calls.clear()
    h.set_camera_mode(exp_mode=3, movie=0, sub=2, tv_s24=-224)
    u.mem_write(0xC202139C, b"\x00\x00\x00\xff")
    u.reg_write(UC_ARM_REG_SP, STACK_TOP)
    u.emu_start(0x1041E714 | 1, 0x1041E766)
    assert h.lv_draw_calls == []
    u.mem_write(STACK_TOP - 0x20, b"\xEE" * 0x20)
    h.call(0x1041E51C, -1)
    assert bytes(u.mem_read(STACK_TOP - 0x18 + 4, 2)) == b"9\x00" and h.lv_draw_calls == []

    h.lv_draw_calls.clear()
    h.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=-224)
    u.mem_write(0xC202139C, b"\x00\x00\x00\x12")
    u.reg_write(UC_ARM_REG_SP, STACK_TOP)
    u.emu_start(0x1041E714 | 1, 0x1041E766)
    assert len(h.lv_draw_calls) == 1 and h.lv_draw_calls[0][3] == '600"'

    return {
        "rom_mapped_read_exec_only": True,
        "native_scalar_getters_and_1319_verified": True,
        "pool_and_mtbl_ok": True,
        "pool_reset_invalidation_ok": True,
        "sentinel_fallback_ok": True,
        "timers_and_exif": timer_rows,
        "min_tv8_clamp_and_active_ui_mode_gate_ok": True,
        "bulb_disabled_step_to_time_ok": True,
        "lv_evf_sentinel_minus1_and_600s_native_strncpy_ok": True,
        "ui_adapters_and_oled_ok": True,
    }

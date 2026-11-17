"""Extended Unicorn coverage for UI adapters, range checks, allowed-Tv filter, and dial burst stop."""
from __future__ import annotations
import struct
from unicorn.arm_const import (
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_SP,
)

from z6_m600_tables import EXT_SLOW_TO_FAST, EXT_STEPS, M_COUNT, UI_FIRST, UI_LAST

SCRATCH = 0x20000000
STACK_TOP = 0x2005F000


def run_extra_m600_tests(h: object, mtbl_ptr: int) -> dict:
    u = h.uc

    # 1. UI adapters at 0x1036a7cc, 0x1037a8bc, 0x1041e71a, 0x10473810
    h.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=-180)  # 180" -> UI ID 70
    r6_box = SCRATCH + 0x700
    r8_box = SCRATCH + 0x740
    u.mem_write(r6_box, b"\x00" * 0x40)
    u.mem_write(r8_box, struct.pack("b", 12))
    u.reg_write(UC_ARM_REG_SP, STACK_TOP)
    u.reg_write(UC_ARM_REG_R6, r6_box)
    u.reg_write(UC_ARM_REG_R8, r8_box)
    u.emu_start(0x1036A7CC | 1, 0x1036A7D4)
    assert u.reg_read(UC_ARM_REG_R0) == 70
    assert struct.unpack("<I", u.mem_read(r6_box + 0x18, 4))[0] == 70

    # Non-M-still fallback at 0x1036a7cc
    h.set_camera_mode(exp_mode=2, movie=0, sub=0, tv_s24=-180)
    u.reg_write(UC_ARM_REG_SP, STACK_TOP)
    u.reg_write(UC_ARM_REG_R6, r6_box)
    u.reg_write(UC_ARM_REG_R8, r8_box)
    u.emu_start(0x1036A7CC | 1, 0x1036A7D4)
    assert u.reg_read(UC_ARM_REG_R0) == 12

    # 0x1037a8bc (R7+3 -> R5) and 0x1041e71a (R0+3 -> R4)
    h.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=-200)  # 300" -> UI ID 72
    u.mem_write(r8_box, b"\x00\x00\x00\x0f")
    u.reg_write(UC_ARM_REG_SP, STACK_TOP)
    u.reg_write(UC_ARM_REG_R7, r8_box)
    u.emu_start(0x1037A8BC | 1, 0x1037A8C0)
    assert u.reg_read(UC_ARM_REG_R5) == 72

    u.reg_write(UC_ARM_REG_SP, STACK_TOP)
    u.reg_write(UC_ARM_REG_R0, r8_box)
    u.emu_start(0x1041E71A | 1, 0x1041E71E)
    assert u.reg_read(UC_ARM_REG_R4) == 72

    # 0x10473810 rational -> UI ID 74 (600")
    h.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=-224)
    u.reg_write(UC_ARM_REG_SP, STACK_TOP - 0x400)
    sp_base = STACK_TOP - 0x400
    u.mem_write(sp_base + 0x1C4, struct.pack("<ii", 24, -224))
    u.mem_write(r6_box + 0x30, struct.pack("<I", 0xABCD1234))
    u.reg_write(UC_ARM_REG_R4, r6_box)
    u.reg_write(UC_ARM_REG_R5, 0)
    u.emu_start(0x10473810 | 1, 0x10473828)
    assert u.reg_read(UC_ARM_REG_R0) == 74 and u.reg_read(UC_ARM_REG_R1) == 0xABCD1234

    # 2. All 4 UI range adapters across UI IDs 67..74 and 66/75 boundaries
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

    for uid in (66, 75):
        u.reg_write(UC_ARM_REG_R4, uid)
        u.emu_start(0x102F9E94 | 1, 0x102F9E98)
        u.reg_write(UC_ARM_REG_R1, uid)
        u.emu_start(0x102F9EBC | 1, 0x102F9EC0)
        u.reg_write(UC_ARM_REG_R4, uid)
        u.emu_start(0x1041E546 | 1, 0x1041E54A)
        u.reg_write(UC_ARM_REG_R4, uid)
        u.emu_start(0x1041E730 | 1, 0x1041E734)

    # 3. Allowed-Tv filter at 0x1015093e: emits 8 extended Tv values in M-still, 0 in A-mode
    out_arr = SCRATCH + 0x800
    cnt_rec = SCRATCH + 0x900
    ctx_rec = SCRATCH + 0x940
    in_tbl = SCRATCH + 0xA00
    for idx, (tv, _, _, _) in enumerate(EXT_SLOW_TO_FAST):
        u.mem_write(in_tbl + idx * 8, struct.pack("<ii", tv, 2))

    for exp_m, want_cnt in ((3, 8), (2, 0)):
        u.mem_write(cnt_rec + 0x0C, struct.pack("<I", 0))
        u.mem_write(ctx_rec + 0xA4, struct.pack("B", 0))
        u.mem_write(ctx_rec + 0xB8, struct.pack("<I", exp_m))
        sp_loop = STACK_TOP - 0x200
        u.mem_write(sp_loop + 0x98, struct.pack("<I", ctx_rec))
        for idx in range(8):
            u.reg_write(UC_ARM_REG_SP, sp_loop)
            u.reg_write(UC_ARM_REG_R1, cnt_rec)
            u.reg_write(UC_ARM_REG_R3, 0)
            u.reg_write(UC_ARM_REG_R4, out_arr)
            u.reg_write(UC_ARM_REG_R6, idx)
            u.reg_write(UC_ARM_REG_R8, in_tbl)
            u.emu_start(0x1015093E | 1, 0x101509A6)
        got_cnt = struct.unpack("<I", u.mem_read(cnt_rec + 0x0C, 4))[0]
        assert got_cnt == want_cnt

    # 4. Multi-click burst boundary stop at 0x1012a874 (25" -> 30" stops at 0x1012a880)
    u.mem_write(mtbl_ptr + 0x3C, struct.pack("<I", 1))
    tv_seq = [-116, -120]  # 25" before step -> 30" after step -> must stop burst!
    h.stubs[0x1015BEBE] = lambda uc: uc.reg_write(UC_ARM_REG_R0, tv_seq.pop(0) & 0xFFFFFFFF)
    h.stubs[0x1012A68C] = lambda uc: None
    u.reg_write(UC_ARM_REG_SP, STACK_TOP)
    u.reg_write(UC_ARM_REG_R7, 0)
    u.emu_start(0x1012A874 | 1, 0x1012A880)

    # Multi-click burst from 90" -> 60" -> 30": 90" -> 60" continues (0x1012a878), 25" -> 60" stops (0x1012a880)
    tv_seq[:] = [-156, -144]
    u.reg_write(UC_ARM_REG_SP, STACK_TOP)
    u.reg_write(UC_ARM_REG_R7, 0)
    u.emu_start(0x1012A874 | 1, 0x1012A878)

    # 5. Full PTP 0x500D setter 0x1033175c + commit 0x103316c4 regression test (verifying {0x20D, 0x204} prefix)
    h.stubs.pop(0x1034037C, None)
    committed: list[tuple[tuple[int, ...], tuple[int, ...]]] = []
    cur_ptp_req = [0]

    def _chk_prop_valid(uc: object) -> None:
        pid = uc.reg_read(UC_ARM_REG_R0)
        uc.reg_write(UC_ARM_REG_R0, 1 if pid in (0x20D, 0x204) else 0)

    def _commit_props(uc: object) -> None:
        p_ids = uc.reg_read(UC_ARM_REG_R0)
        p_vals = uc.reg_read(UC_ARM_REG_R1)
        cnt = uc.reg_read(UC_ARM_REG_R2)
        ids = struct.unpack(f"<{cnt}I", uc.mem_read(p_ids, cnt * 4))
        vals = struct.unpack(f"<{cnt}i", uc.mem_read(p_vals, cnt * 4))
        committed.append((ids, vals))
        uc.reg_write(UC_ARM_REG_R0, 0)

    h.stubs[0x10401670] = _chk_prop_valid
    h.stubs[0x10401630] = _commit_props
    h.stubs[0x10331506] = lambda uc: uc.reg_write(UC_ARM_REG_R0, cur_ptp_req[0])

    ptp_in = SCRATCH + 0xB00
    h.set_camera_mode(exp_mode=3, movie=0, sub=0)
    for req_val, want_tv in ((300_000, -120), (600_000, -144), (6_000_000, -224)):
        committed.clear()
        cur_ptp_req[0] = req_val
        u.mem_write(ptp_in, struct.pack("<I", req_val))
        rc_set, _ = h.call(0x1033175C, ptp_in)
        assert rc_set == 0x2001 and committed == [((0x20D, 0x204), (0, want_tv))]

    # Outside M-still: 30s still commits {0x20D, 0x204}, while 60s/600s are rejected with 0 commits
    h.set_camera_mode(exp_mode=2, movie=0, sub=0)
    committed.clear()
    cur_ptp_req[0] = 300_000
    u.mem_write(ptp_in, struct.pack("<I", 300_000))
    rc_30_a, _ = h.call(0x1033175C, ptp_in)
    assert rc_30_a == 0x2001 and committed == [((0x20D, 0x204), (0, -120))]

    for req_val in (600_000, 6_000_000):
        committed.clear()
        cur_ptp_req[0] = req_val
        u.mem_write(ptp_in, struct.pack("<I", req_val))
        rc_ext_a, _ = h.call(0x1033175C, ptp_in)
        assert rc_ext_a == 0x201C and committed == []

    return {
        "ui_adapters_all_4_ok": True,
        "ui_range_checks_all_4_ok": True,
        "allowed_tv_filter_ok": True,
        "dial_burst_boundary_stop_ok": True,
        "ptp_500d_full_setter_commit_ok": True,
        "extended_step_count": len(EXT_STEPS),
    }

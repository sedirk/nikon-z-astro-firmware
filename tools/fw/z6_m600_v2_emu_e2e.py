"""End-to-end Unicorn verification for Nikon Z6 C3.80 Modified15 vs Modified14.

Executes native ROM scalar getters (0x1015BEBE / 0x104014DE -> 0x100700A0) with coherent 32-bit
RAM storage for 0x0204 (0xC24CD9C0), 0x020D (0xC24CD9E4), and derived 0x1319 (0xC24CC790) across:
  - Modified14 negative control (47-entry 0x204 context shift -> pub_err=1 -> 0/120 enabled -> T-lock)
  - Modified15 x200 <-> Time <-> Bulb <-> 600"..60" <-> 30".. across 1/3, 1/2, and 1 EV grids
  - Faster and slower multi-click Fn bursts (commands 0, 1, 2, 3) across all 3 EV grids
  - Complete PTP 0x500D (0x1033175C) & 0xD100 (0x10331992) source/destination state matrix
"""
from __future__ import annotations
import gc
import struct
from unicorn.arm_const import UC_ARM_REG_R0

from z6_m600_tables import ADDR_ACTIVE_UI, BASE, EXT_STEPS, IDX_30S, M_COUNT
from z6_m600_v2_emu import M600V2Harness, SCRATCH, run_core_and_ui_tests


def _publish_prop_list(h: M600V2Harness, prop_id: int, values: list[int], err: int = 0) -> int:
    desc = SCRATCH + 0x10000
    arr = SCRATCH + 0x10100
    h.uc.mem_write(arr, struct.pack(f"<{len(values)}i", *values))
    h.uc.mem_write(desc, struct.pack("<IB3xII", prop_id, err, len(values), arr))
    rc, _ = h.call(0x1020931C, desc)
    return rc


def _run_cold_boot_prop_204_builder(
    h: M600V2Harness, blob: bytes, ev_step: int, shutter_mode_20d: int = 2, exp_0002: int = 0x20, movie: int = 0
) -> dict:
    """Execute native 0x10150602 (0x204 property builder + 0x1020931C publisher) using ROM's dependency table."""
    desc_addr = 0x114D3510
    _pid, _z, dep_desc, _tbl = struct.unpack_from("<4I", blob, desc_addr - BASE)
    dep_cnt, dep_ptr = struct.unpack_from("<II", blob, dep_desc - BASE)
    dep_ids = struct.unpack_from(f"<{dep_cnt}I", blob, dep_ptr - BASE)
    prop_vals = {
        0x180C: 0,
        0x0204: h.get_scalar(0x0204),
        0x1013: ev_step,
        0x1034: -120,
        0x1035: 312,
        0x0002: exp_0002,
        0x1C14: 0,
        0x020D: shutter_mode_20d,
        0x138D: movie,
    }
    ctx = SCRATCH + 0x11000
    for idx, pid in enumerate(dep_ids):
        h.uc.mem_write(ctx + idx * 4, struct.pack("<i", prop_vals.get(pid, 0)))

    canary = b"\xAA\x55\xAA\x55" * 4
    h.uc.mem_write(0xC236C080, canary)

    rc, _ = h.call(0x10150602, desc_addr, ctx)
    stg_id, stg_err, stg_cnt, stg_ptr = struct.unpack("<IB3xII", h.uc.mem_read(0xC236C070, 16))
    pub_id, pub_err, pub_cnt, pub_ptr, pub_max, _chg, _sub, pub_init = struct.unpack(
        "<IB3x6I", h.uc.mem_read(0xC18BD7C4, 32)
    )
    canary_intact = bytes(h.uc.mem_read(0xC236C080, 16)) == canary
    return {
        "rc": rc,
        "dep_count": dep_cnt,
        "stg_id": stg_id,
        "stg_err": stg_err,
        "stg_cnt": stg_cnt,
        "stg_ptr": stg_ptr,
        "pub_id": pub_id,
        "pub_err": pub_err,
        "pub_cnt": pub_cnt,
        "pub_ptr": pub_ptr,
        "pub_max": pub_max,
        "pub_init": pub_init,
        "canary_intact": canary_intact,
    }


def reproduce_modified14_tmode_lock(m14_blob: bytes) -> dict:
    """Negative control: prove Modified14 locks in pre-flash Time (T门) on native 0x10150602 -> 0x1012A752 path."""
    h = M600V2Harness(m14_blob)
    h.call(0x101120DC)
    h.set_camera_mode(exp_mode=3, movie=0, sub=2, tv_s24=-120)
    assert _publish_prop_list(h, 0x20D, [0, 1, 2, 3]) == 1

    b_res = _run_cold_boot_prop_204_builder(h, m14_blob, ev_step=0, shutter_mode_20d=2)
    assert b_res["dep_count"] == 47 and b_res["pub_err"] == 1 and b_res["pub_cnt"] == 55

    h.uc.mem_write(0xC1815CDD, b"\x02")
    h.uc.mem_write(0xC1815D9C, struct.pack("<I", 1))
    h.call(0x1012EC70, 0, 0)
    cnt_box = SCRATCH + 0x12000
    mtbl_ptr, _ = h.call(0x10090102, cnt_box)
    enabled_flags = [struct.unpack("<I", h.uc.mem_read(mtbl_ptr + i * 16 + 0x0C, 4))[0] for i in range(M_COUNT)]
    assert enabled_flags == [0] * M_COUNT

    h.committed_batches.clear()
    for dial_cmd in (3, 3, 1, 1):
        h.call(0x1012A752, dial_cmd)
    assert h.committed_batches == []
    assert h.get_scalar(0x020D) == 2 and h.get_scalar(0x1319) == 2

    rc_117 = _publish_prop_list(h, 0x204, list(range(-224, -224 + 117 * 4, 4)))
    assert rc_117 == 0

    h.uc = None
    del h
    gc.collect()
    return {
        "m14_dep_count": b_res["dep_count"],
        "m14_0x204_pub_err": b_res["pub_err"],
        "m14_enabled_mtbl_entries": sum(enabled_flags),
        "m14_dial_commits_from_time": 0,
        "m14_117_entry_publish_rc": rc_117,
        "reproduced_exact_hardware_tmode_lock": True,
    }


def run_all_m600_v2_tests(m15_blob: bytes, m14_blob: bytes) -> dict:
    neg_ctrl = reproduce_modified14_tmode_lock(m14_blob)

    h = M600V2Harness(m15_blob)
    u = h.uc
    core_ui = run_core_and_ui_tests(h)

    # 1. Coherent x200(0) <-> Time(1) <-> Bulb(2) <-> 600"(3)..60"(10) <-> 30"(11) <-> above-30"
    #    with native ROM scalar getters & synchronized 0xC24CC790 (0x1319) across all 3 EV grids!
    assert _publish_prop_list(h, 0x20D, [0, 1, 2, 3]) == 1

    ev_grid_results = {}
    burst_grid_results = {}
    for ev_code, ev_name, want_cnt, want_next_tv, want_15s_tv in (
        (0, "1/3_EV", 55, -112, -96),
        (1, "1/2_EV", 37, -108, -96),
        (2, "1_EV", 19, -96, -96),
    ):
        # Start from pre-flash Time (T门: idx=1, 0x20D=2, 0x1319=2 at 0xC24CC790!)
        h.set_camera_mode(exp_mode=3, movie=0, sub=2, tv_s24=-120)
        h.set_scalar(0x1013, ev_code)
        u.mem_write(0xC1815CDD, b"\x02")
        u.mem_write(0xC1815D9C, struct.pack("<I", 1))
        assert h.get_scalar(0x1319) == 2

        b_res = _run_cold_boot_prop_204_builder(h, m15_blob, ev_step=ev_code, shutter_mode_20d=2)
        assert b_res["rc"] == 1 and b_res["dep_count"] == 46
        assert b_res["pub_err"] == 0 and b_res["pub_cnt"] == want_cnt and b_res["pub_init"] == 1
        assert b_res["canary_intact"] is True

        # Step faster 11 single clicks from Time(1) -> Bulb(2) -> 600"(3)..60"(10) -> 30"(11) -> next!
        up_trace = []
        for _ in range(11):
            h.call(0x1012A752, 3)
            cur_idx = struct.unpack("<I", u.mem_read(0xC1815D9C, 4))[0]
            up_trace.append((cur_idx, h.get_scalar(0x020D), h.get_scalar(0x1319), h.get_scalar(0x0204)))

        want_up = [
            (2, 1, 1, -120),   # Bulb (0x1319=1!)
            (3, 0, 0, -224),   # 600" (0x1319=0!)
            (4, 0, 0, -216),   # 480"
            (5, 0, 0, -200),   # 300"
            (6, 0, 0, -192),   # 240"
            (7, 0, 0, -180),   # 180"
            (8, 0, 0, -168),   # 120"
            (9, 0, 0, -156),   # 90"
            (10, 0, 0, -144),  # 60"
            (11, 0, 0, -120),  # 30"
        ]
        assert up_trace[:10] == want_up
        assert up_trace[10][1:] == (0, 0, want_next_tv) and up_trace[10][0] > IDX_30S

        # Step slower 12 single clicks all the way down to Bulb(2) -> Time(1) -> x200(0)!
        down_trace = []
        for _ in range(12):
            h.call(0x1012A752, 1)
            cur_idx = struct.unpack("<I", u.mem_read(0xC1815D9C, 4))[0]
            down_trace.append((cur_idx, h.get_scalar(0x020D), h.get_scalar(0x1319), h.get_scalar(0x0204)))

        assert down_trace[-3] == (2, 1, 1, -224)  # Bulb (0x204 stays -224, ADDR_ACTIVE_UI must be 0!)
        assert down_trace[-2] == (1, 2, 2, -224)  # Time
        assert down_trace[-1] == (0, 3, 3, -224)  # x200
        assert h.call(ADDR_ACTIVE_UI)[0] == 0

        # Step faster from x200(0) -> Time(1) -> Bulb(2) -> 600"(3) even while 0x204 holds -224!
        from_x200 = []
        for _ in range(3):
            h.call(0x1012A752, 3)
            cur_idx = struct.unpack("<I", u.mem_read(0xC1815D9C, 4))[0]
            from_x200.append((cur_idx, h.get_scalar(0x020D), h.get_scalar(0x1319), h.get_scalar(0x0204)))
        assert from_x200 == [(1, 2, 2, -224), (2, 1, 1, -224), (3, 0, 0, -224)]
        assert h.call(ADDR_ACTIVE_UI) == (74, 600)

        ev_grid_results[ev_name] = {
            "published_0x204_count": want_cnt,
            "up_from_time_through_600s_ok": True,
            "down_to_bulb_time_x200_ok": True,
            "up_from_x200_ok": True,
            "first_above_30s_tv": want_next_tv,
        }

        # 2. Multi-click Fn burst (r0=2 faster & r0=0 slower) across ALL 3 EV grids & BOTH directions!
        # Start at Time (idx=1): burst faster -> Bulb(2) -> 600"(3) -> ... -> stops dead on 30"(11) -> 15"(-96)!
        h.set_camera_mode(exp_mode=3, movie=0, sub=2, tv_s24=-120)
        u.mem_write(0xC1815D9C, struct.pack("<I", 1))
        h.call(0x1012A752, 2)
        assert (struct.unpack("<I", u.mem_read(0xC1815D9C, 4))[0], h.get_scalar(0x1319)) == (2, 1)  # Bulb
        h.call(0x1012A752, 2)
        assert (struct.unpack("<I", u.mem_read(0xC1815D9C, 4))[0], h.get_scalar(0x0204)) == (3, -224)  # 600"

        # Explicitly test faster burst from 90" (idx=9) and 60" (idx=10):
        # In 1/3 EV (r4=3) and 1/2 EV (r4=2), BOTH 90" and 60" stop at 30" (idx=11); in 1 EV (r4=1), 90" -> 60" then 60" -> 30"!
        h.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=-156)
        u.mem_write(0xC1815D9C, struct.pack("<I", 9))
        h.call(0x1012A752, 2)
        if ev_code in (0, 1):
            assert (struct.unpack("<I", u.mem_read(0xC1815D9C, 4))[0], h.get_scalar(0x0204)) == (IDX_30S, -120)
        else:
            assert (struct.unpack("<I", u.mem_read(0xC1815D9C, 4))[0], h.get_scalar(0x0204)) == (10, -144)

        h.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=-144)
        u.mem_write(0xC1815D9C, struct.pack("<I", 10))
        h.call(0x1012A752, 2)
        assert (struct.unpack("<I", u.mem_read(0xC1815D9C, 4))[0], h.get_scalar(0x0204)) == (IDX_30S, -120)

        # Next faster burst from 30" (idx=11) advances cleanly by 1 full EV to 15" (-96)!
        h.call(0x1012A752, 2)
        assert h.get_scalar(0x0204) == want_15s_tv

        # Slower burst from above 30" (e.g. first step faster than 30") stops cleanly at 30" (-120), then at 60" (-144)!
        h.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=want_next_tv)
        h.call(0x1012EC70, 0, 0)
        h.call(0x1012A752, 0)
        assert struct.unpack("<I", u.mem_read(0xC1815D9C, 4))[0] == IDX_30S and h.get_scalar(0x0204) == -120
        h.call(0x1012A752, 0)
        assert struct.unpack("<I", u.mem_read(0xC1815D9C, 4))[0] == 10 and h.get_scalar(0x0204) == -144

        # Slower burst from 480" (idx=4) stops cleanly at 600" (idx=3), then Bulb (idx=2), then Time (idx=1)!
        h.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=-216)
        u.mem_write(0xC1815D9C, struct.pack("<I", 4))
        h.call(0x1012A752, 0)
        assert (struct.unpack("<I", u.mem_read(0xC1815D9C, 4))[0], h.get_scalar(0x0204)) == (3, -224)
        h.call(0x1012A752, 0)
        assert (struct.unpack("<I", u.mem_read(0xC1815D9C, 4))[0], h.get_scalar(0x1319)) == (2, 1)
        h.call(0x1012A752, 0)
        assert (struct.unpack("<I", u.mem_read(0xC1815D9C, 4))[0], h.get_scalar(0x1319)) == (1, 2)

        burst_grid_results[ev_name] = {"faster_and_slower_stops_ok": True}

    full_109 = [struct.unpack_from("<i", m15_blob, 0x114CEF28 - BASE + i * 8)[0] for i in range(109)]
    assert _publish_prop_list(h, 0x204, full_109) == 1

    # 3. Mode isolation in 0x1012D464, 0x10209636/0x10401670, and 0x10401684 snap-to-nearest
    _run_cold_boot_prop_204_builder(h, m15_blob, ev_step=0, shutter_mode_20d=0)
    cnt_box = SCRATCH + 0x12000
    mtbl_ptr, _ = h.call(0x10090102, cnt_box)
    for exp_m, mov in ((2, 0), (1, 0), (0, 0), (3, 1)):
        h.set_camera_mode(exp_mode=exp_m, movie=mov, sub=0, tv_s24=-224)
        h.call(0x1012EC70, 0, 0)
        ext_flags = [struct.unpack("<I", u.mem_read(mtbl_ptr + i * 16 + 0x0C, 4))[0] for i in range(3, 11)]
        assert ext_flags == [0] * 8
        assert h.call(0x10401670, 0x204, -224)[0] == 0
        snapped_tv, _ = h.call(0x10401684, 0x204, -224)
        if snapped_tv >= 0x80000000:
            snapped_tv -= 0x100000000
        assert snapped_tv == -120

    # Verify mtbl[3..10] remain ENABLED in M-still across Timed(0), Bulb(1), Time(2), and x200(3)!
    for sub_m in (0, 1, 2, 3):
        h.set_camera_mode(exp_mode=3, movie=0, sub=sub_m, tv_s24=-120)
        h.call(0x1012EC70, 0, 0)
        ext_flags = [struct.unpack("<I", u.mem_read(mtbl_ptr + i * 16 + 0x0C, 4))[0] for i in range(3, 11)]
        assert ext_flags == [1] * 8
        for tv, _, _, _ in EXT_STEPS:
            assert h.call(0x10401670, 0x204, tv)[0] == 1

    # Also verify mtbl[3..10] are disabled in M-still if -120 (30") is absent from 0x204
    h.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=0)
    assert _publish_prop_list(h, 0x204, [0, 24, 48, 72]) == 1
    h.call(0x1012EC70, 0, 0)
    assert [struct.unpack("<I", u.mem_read(mtbl_ptr + i * 16 + 0x0C, 4))[0] for i in range(3, 11)] == [0] * 8
    assert h.call(0x10401670, 0x204, -224)[0] == 0

    # Restore standard 1/3 EV 0x204 list (55 entries)
    _run_cold_boot_prop_204_builder(h, m15_blob, ev_step=0, shutter_mode_20d=0)

    # 4. PTP GetDevicePropDesc enum builders 0x10331D12 (0x500D) & 0x10331D92 (0xD100) across Timed/Bulb/Time & A-mode
    _run_cold_boot_prop_204_builder(h, m15_blob, ev_step=0, shutter_mode_20d=0)
    enum_buf = SCRATCH + 0x13000
    enum_canary = b"\xCC\xDD\xEE\xFF" * 4
    for sub_m in (0, 1, 2):
        h.set_camera_mode(exp_mode=3, movie=0, sub=sub_m, tv_s24=-120)
        u.mem_write(enum_buf + 0x200, enum_canary)
        cnt_500d_m, _ = h.call(0x10331D12, enum_buf, 0x200)
        vals_500d_m = struct.unpack(f"<{cnt_500d_m}I", u.mem_read(enum_buf, cnt_500d_m * 4))
        assert bytes(u.mem_read(enum_buf + 0x200, 16)) == enum_canary
        for _, _, sec, _ in EXT_STEPS:
            assert (sec * 10000) in vals_500d_m
        assert 0xFFFFFFFF in vals_500d_m and 0xFFFFFFFD in vals_500d_m

        u.mem_write(enum_buf + 0x200, enum_canary)
        cnt_d100_m, _ = h.call(0x10331D92, enum_buf, 0x200)
        vals_d100_m = struct.unpack(f"<{cnt_d100_m}I", u.mem_read(enum_buf, cnt_d100_m * 4))
        assert bytes(u.mem_read(enum_buf + 0x200, 16)) == enum_canary
        for _, _, sec, _ in EXT_STEPS:
            assert ((sec << 16) | 1) in vals_d100_m
        assert 0xFFFFFFFF in vals_d100_m and 0xFFFFFFFD in vals_d100_m and 0xFFFFFFFE in vals_d100_m

    # Switch to A-mode keeping the same 55-entry 1/3 EV 0x204 list (err=0) so the mode gate alone is tested
    h.set_camera_mode(exp_mode=2, movie=0, sub=0, tv_s24=-120)
    cnt_500d_a, _ = h.call(0x10331D12, enum_buf, 0x200)
    vals_500d_a = struct.unpack(f"<{cnt_500d_a}I", u.mem_read(enum_buf, cnt_500d_a * 4))
    cnt_d100_a, _ = h.call(0x10331D92, enum_buf, 0x200)
    vals_d100_a = struct.unpack(f"<{cnt_d100_a}I", u.mem_read(enum_buf, cnt_d100_a * 4))
    assert [cnt_500d_m, cnt_d100_m] == [63, 66] and [cnt_500d_a, cnt_d100_a] == [55, 58]
    assert all((sec * 10000) not in vals_500d_a for _, _, sec, _ in EXT_STEPS)
    assert all(((sec << 16) | 1) not in vals_d100_a for _, _, sec, _ in EXT_STEPS)

    # Restore M-still 55-entry 1/3 EV list
    h.set_camera_mode(exp_mode=3, movie=0, sub=0, tv_s24=-120)
    _run_cold_boot_prop_204_builder(h, m15_blob, ev_step=0, shutter_mode_20d=0)

    # 5. Complete PTP 0x500D (0x1033175C) & 0xD100 (0x10331992) source/destination state matrix!
    cur_ptp_500d = [0]
    cur_ptp_d100 = [0]
    h.stubs[0x10331506] = lambda uc: uc.reg_write(UC_ARM_REG_R0, cur_ptp_500d[0])
    h.stubs[0x1033146C] = lambda uc: uc.reg_write(UC_ARM_REG_R0, cur_ptp_d100[0])
    ptp_in = SCRATCH + 0x14000

    # Matrix: from every source shutter state (Timed=0, Bulb=1, Time=2, x200=3) to Bulb, Time, 30s, 60s, 600s!
    for src_sub, src_tv in ((0, -120), (0, -224), (1, -224), (2, -120), (2, -224), (3, -120)):
        for dst_500d, dst_d100, want_batch in (
            (0xFFFFFFFF, 0xFFFFFFFF, [((0x20D,), (1,))]),            # -> Bulb
            (0xFFFFFFFD, 0xFFFFFFFD, [((0x20D,), (2,))]),            # -> Time
            (300_000, (30 << 16) | 1, [((0x20D, 0x204), (0, -120))]),  # -> 30"
            (600_000, (60 << 16) | 1, [((0x20D, 0x204), (0, -144))]),  # -> 60"
            (6_000_000, (600 << 16) | 1, [((0x20D, 0x204), (0, -224))]),  # -> 600"
        ):
            h.set_camera_mode(exp_mode=3, movie=0, sub=src_sub, tv_s24=src_tv)
            h.committed_batches.clear()
            cur_ptp_500d[0] = dst_500d
            u.mem_write(ptp_in, struct.pack("<I", dst_500d))
            rc5, _ = h.call(0x1033175C, ptp_in)
            assert rc5 == 0x2001 and h.committed_batches == want_batch

            h.set_camera_mode(exp_mode=3, movie=0, sub=src_sub, tv_s24=src_tv)
            h.committed_batches.clear()
            cur_ptp_d100[0] = dst_d100
            u.mem_write(ptp_in, struct.pack("<I", dst_d100))
            rcd, _ = h.call(0x10331992, ptp_in)
            assert rcd == 0x2001 and h.committed_batches == want_batch

    # Reject >30s PTP writes in A mode (2), S mode (1), and Movie mode (movie=1) via BOTH 0x500D and 0xD100
    for exp_m, mov in ((2, 0), (1, 0), (3, 1)):
        h.set_camera_mode(exp_mode=exp_m, movie=mov, sub=0, tv_s24=-120)
        for sec in (60, 600):
            h.committed_batches.clear()
            u.mem_write(ptp_in, struct.pack("<I", sec * 10000))
            assert h.call(0x1033175C, ptp_in)[0] == 0x201C and h.committed_batches == []
            u.mem_write(ptp_in, struct.pack("<I", (sec << 16) | 1))
            assert h.call(0x10331992, ptp_in)[0] == 0x201C and h.committed_batches == []

    h.uc = None
    del h
    gc.collect()
    return {
        **core_ui,
        "negative_control_modified14": neg_ctrl,
        "cold_boot_and_dial_grids": ev_grid_results,
        "multiclick_burst_grids": burst_grid_results,
        "full_109_entry_publish_ok": True,
        "multiclick_burst_boundary_stop_ok": True,
        "non_m_still_isolation_and_snap_to_30s_ok": True,
        "ptp_500d_and_d100_enum_counts_m_still": [cnt_500d_m, cnt_d100_m],
        "ptp_500d_and_d100_enum_counts_a_mode": [cnt_500d_a, cnt_d100_a],
        "ptp_full_source_dest_matrix_ok": True,
        "extended_step_count": len(EXT_STEPS),
    }

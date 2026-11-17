"""Native Unicorn ARM/Thumb verification for Nikon Z6 C3.80 Modified20 firmware."""
from __future__ import annotations
import argparse
import gc
import json
import struct
from pathlib import Path
import sys

from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_THUMB, Uc
from unicorn.arm_const import (
    UC_ARM_REG_CPSR,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_R9,
    UC_ARM_REG_R10,
    UC_ARM_REG_R11,
    UC_ARM_REG_SP,
)

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from probe_raw_candidates import BASE, RAM, Rig
from z6_astro_ui_color_space_v2 import (
    ADDR_M9_SANITIZER,
    LANG_ZH_CN,
    LANG_ZH_TW,
    RAM_PROP_0508,
    RAM_PROP_131B,
    UI_OVERRIDES_M20,
)
from z6_interval_post_exposure import (
    ADDR_IV_OBJECT_A,
    ADDR_IV_SHOTS_PER_INT,
    RAM_PROP_0204,
    RAM_PROP_1308,
    RAM_PROP_1319,
    RAM_PROP_136F,
)
from z6_m600_tables import EXT_STEPS

ROOT = THIS_DIR.parents[1]


def _reset_rig(rig: Rig) -> None:
    rig.uc.reg_write(UC_ARM_REG_CPSR, 0x20)
    rig.uc.reg_write(UC_ARM_REG_SP, RAM + 0x30000)
    rig.uc.reg_write(UC_ARM_REG_LR, 0x10020001)


def _set_astro_ram(rig: Rig, color_space: int, effective_rec: int) -> None:
    rig.put(RAM_PROP_0508, color_space, "B")
    rig.put(RAM_PROP_131B, effective_rec)


def run_predicate_tests(m20: bytes, snap: dict, syms: dict[str, int]) -> dict:
    rig = Rig(m20, snap)
    fn_addr = syms["fn_is_astro_r0"]
    pred_cases = 0

    for cs in (0, 1, 2):
        for rec in (0, 1, 2, 3, 0xFF):
            _reset_rig(rig)
            _set_astro_ram(rig, cs, rec)
            res = rig.call(fn_addr)
            got = int(res["registers"]["r0"], 16)
            exp = 1 if (cs == 1 and rec in (0, 1)) else 0
            assert got == exp, f"fn_is_astro_r0(cs={cs}, rec={rec}) -> {got} != {exp}"
            pred_cases += 1

    rig.uc = None
    del rig
    gc.collect()
    return {"predicate_matrix_cases": pred_cases}


def run_color_space_srgb_lock_tests(m20: bytes, snap: dict) -> dict:
    rig = Rig(m20, snap)
    lock_cases = 0

    for cs in (0, 1, 2):
        _reset_rig(rig)
        _set_astro_ram(rig, cs, 0)
        res = rig.call(0x1040AD00)
        got = int(res["registers"]["r0"], 16)
        assert got == 1, f"IsColorSpace_sRGB(cs={cs}) returned {got} != 1"
        lock_cases += 1

    rig.uc = None
    del rig
    gc.collect()
    return {"srgb_lock_cases": lock_cases}


def run_ui_string_tests(blobs: dict[str, bytes], snap: dict) -> dict:
    """Verify GetLanguageString (0x104C0104) across all 36 languages for Modified20 wording + 5 untouched neighbors."""
    rig_s = Rig(blobs["stock"], snap)
    rig_m = Rig(blobs["m20"], snap)

    ui_ptr_resolver = struct.unpack_from("<I", blobs["stock"], 0x104C0224 - BASE)[0] - 0x1C
    ui_ptr_limit = struct.unpack_from("<I", blobs["stock"], 0x104C0220 - BASE)[0]
    for r in (rig_s, rig_m):
        r.put(ui_ptr_resolver + 0x0, 0x112C2A98)
        r.put(ui_ptr_resolver + 0x8, 0x112C2A08)
        r.put(ui_ptr_limit + 0x14, 2291)

    OUT_PTR = RAM + 0x4A000
    OUT_LEN = RAM + 0x4A004

    def resolve_ui_str(rig: Rig, lang: int, sid: int) -> tuple[int, int, str]:
        rig.put(OUT_PTR, 0)
        rig.put(OUT_LEN, 0)
        rig.call(0x104C0104, [lang, sid, OUT_PTR, OUT_LEN])
        s_ptr = rig.get(OUT_PTR)
        s_len = rig.get(OUT_LEN)
        raw_b = bytes(rig.uc.mem_read(s_ptr, s_len))
        return s_ptr, s_len, raw_b.decode("utf-16le")

    ui_checks = 0
    for lang in range(36):
        for sid, _, txt_en, txt_cn, txt_tw in UI_OVERRIDES_M20:
            _, s_len, s_txt = resolve_ui_str(rig_m, lang, sid)
            exp = txt_cn if lang == LANG_ZH_CN else (txt_tw if lang == LANG_ZH_TW else txt_en)
            assert s_txt == exp and s_len == len(exp.encode("utf-16le")), (
                f"Lang {lang} SID {sid:#x} mismatch: got {s_txt!r} ({s_len}B), expected {exp!r}"
            )
            ui_checks += 1

        for neighbor_sid in (0x0000, 0x03B2, 0x03B6, 0x082A, 0x082D):
            assert resolve_ui_str(rig_m, lang, neighbor_sid) == resolve_ui_str(rig_s, lang, neighbor_sid), (
                f"Neighbor SID {neighbor_sid:#x} corrupted in lang {lang}"
            )
            ui_checks += 1

    rig_s.uc = None
    rig_m.uc = None
    del rig_s, rig_m
    gc.collect()
    return {"ui_36_languages_string_checks": ui_checks}


def run_dual_branch_trampoline_tests(blobs: dict[str, bytes], snap: dict, syms: dict[str, int]) -> dict:
    m20 = blobs["m20"]
    rig = Rig(m20, snap)
    u = rig.uc
    tramp_cases = 0

    for cs, exp_target in [(0, 0x101BA474), (1, 0x101BA4B6)]:
        _reset_rig(rig)
        _set_astro_ram(rig, cs, 0)
        rig.call(syms["tramp_ae3a4"], args=[0x1234, 0x5678, 0x9ABC], until=exp_target)
        assert u.reg_read(UC_ARM_REG_PC) == exp_target
        assert u.reg_read(UC_ARM_REG_R0) == 0x1234
        assert u.reg_read(UC_ARM_REG_R1) == 0x5678
        assert u.reg_read(UC_ARM_REG_R2) == 0x9ABC
        tramp_cases += 1

    DUMMY_OWNER = RAM + 0x20000
    for cs in (0, 1):
        _reset_rig(rig)
        _set_astro_ram(rig, cs, 0)
        TARGET = 0x100C28B6
        rig.call(syms["tramp_c28b2"], regs={4: DUMMY_OWNER, 9: 0x55}, until=TARGET)
        assert u.reg_read(UC_ARM_REG_PC) == TARGET
        val_written = u.mem_read(DUMMY_OWNER + 0x62, 1)[0]
        assert val_written == (0x55 if cs == 1 else 0)
        tramp_cases += 1

    for cs, exp_target in [(0, 0x1011D548), (1, ADDR_M9_SANITIZER)]:
        _reset_rig(rig)
        _set_astro_ram(rig, cs, 0)
        rig.call(syms["tramp_17d834"], until=exp_target)
        assert u.reg_read(UC_ARM_REG_PC) == exp_target
        tramp_cases += 1

    rig.uc = None
    del rig
    gc.collect()
    return {"dual_branch_trampoline_cases": tramp_cases}


def _sim_interval_sequence(
    fw_bytes: bytes,
    interval_ms: int,
    intervals: int,
    exp_done_ms: int,
    shots_per_iv: int = 1,
    t0_ms: int = 1_000_000,
    strict_timer_delivery: bool = False,
) -> tuple[list[int], list[int], int, int | None, int]:
    """
    Emulate native 0x10200D9C..0x10200DBC (shutter start + native rem decrement + native final 0x101FED02)
    and native 0x102065A8 -> 0x101FF380 -> 0x101FF308 -> 0x101FF2D0 -> 0x101BF034 (RTOS timer arming).
    """
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    mu.mem_map(0x10000000, 0x02400000)
    mu.mem_map(0xC1800000, 0x01000000)
    mu.mem_map(0xD0000000, 0x00100000)
    mu.mem_write(BASE, fw_bytes[:0x02000000])

    A = ADDR_IV_OBJECT_A
    mu.mem_write(0xC18B8718, struct.pack("<Q", 4_102_444_800_000))
    now_box = [t0_ms]
    timer_armed = [None]
    ended = [None]
    intra_burst_fired = [0]
    low_word_carries = [0]

    mu.mem_write(A + 0x00, struct.pack("<I", 1))
    mu.mem_write(A + 0x05, bytes([2, 5]))
    mu.mem_write(A + 0x08, struct.pack("<I", intervals * shots_per_iv))
    mu.mem_write(A + 0x10, struct.pack("<Q", now_box[0]))
    mu.mem_write(A + 0x20, struct.pack("<I", interval_ms))
    mu.mem_write(A + 0x28, struct.pack("<I", shots_per_iv))
    mu.mem_write(A + 0x34, struct.pack("<I", 0))
    mu.mem_write(A + 0x54, struct.pack("<I", 0x77))

    stubs = {
        0x101FC616: lambda u: (
            u.reg_write(UC_ARM_REG_R0, now_box[0] & 0xFFFFFFFF),
            u.reg_write(UC_ARM_REG_R1, (now_box[0] >> 32) & 0xFFFFFFFF),
        ),
        0x101BF034: lambda u: (timer_armed.__setitem__(0, u.reg_read(UC_ARM_REG_R1)), u.reg_write(UC_ARM_REG_R0, 0)),
        0x101BF044: lambda u: u.reg_write(UC_ARM_REG_R0, 0),
        0x1020610C: lambda u: None,
        0x1020612A: lambda u: None,
        0x101FC556: lambda u: None,
        0x1005F574: lambda u: None,
        0x1005F58C: lambda u: None,
        0x100600C4: lambda u: u.reg_write(UC_ARM_REG_R0, 0),
        0x10060348: lambda u: u.reg_write(UC_ARM_REG_R0, 1),
        0x100603D6: lambda u: None,
        0x10061FAA: lambda u: None,
        0x101FC4D0: lambda u: None,
        0x10206E90: lambda u: intra_burst_fired.__setitem__(0, intra_burst_fired[0] + 1),
        0x101FED02: lambda u: (
            ended.__setitem__(0, u.reg_read(UC_ARM_REG_R0)),
            u.mem_write(A + 0x19, bytes([1])),
        ),
    }

    def hook_code(u, address, size, user_data):
        fn = stubs.get(address)
        if fn is not None:
            fn(u)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))

    mu.hook_add(UC_HOOK_CODE, hook_code)

    shots_log: list[int] = []
    for _ in range(intervals * shots_per_iv + 10):
        rem = struct.unpack("<I", mu.mem_read(A + 8, 4))[0]
        if rem == 0 or ended[0] is not None:
            break
        shots_log.append(now_box[0] - t0_ms)

        # Execute native shutter-start block 0x10200D9C..0x10200DBC (decrements [A+8] & triggers 0x101FED02 on final shot)
        ended[0] = None
        mu.mem_write(A + 5, bytes([2]))
        mu.reg_write(UC_ARM_REG_CPSR, 0x20)
        mu.reg_write(UC_ARM_REG_SP, 0xD0080000)
        mu.reg_write(UC_ARM_REG_R4, A)
        mu.reg_write(UC_ARM_REG_R7, 0)
        mu.reg_write(UC_ARM_REG_LR, 0xD0090001)
        mu.emu_start(0x10200D9C | 1, 0x10200DBC)

        now_box[0] += exp_done_ms
        now_before_sched = now_box[0]

        if ended[0] is not None:
            # Also verify native 0x102065A8 exits cleanly via [A+0x19] == 1 -> 0x101FED02
            ended_shutter = ended[0]
            ended[0] = None
            mu.reg_write(UC_ARM_REG_CPSR, 0x20)
            mu.reg_write(UC_ARM_REG_SP, 0xD0080000)
            mu.reg_write(UC_ARM_REG_R0, 0)
            mu.reg_write(UC_ARM_REG_LR, 0xD0090001)
            mu.emu_start(0x102065A8 | 1, 0xD0090000)
            assert ended[0] is not None
            ended[0] = ended_shutter
            break

        timer_armed[0] = None
        intra_burst_fired[0] = 0
        mu.reg_write(UC_ARM_REG_CPSR, 0x20)
        mu.reg_write(UC_ARM_REG_SP, 0xD0080000)
        mu.reg_write(UC_ARM_REG_R0, 0)
        mu.reg_write(UC_ARM_REG_LR, 0xD0090001)
        mu.emu_start(0x102065A8 | 1, 0xD0090000)

        if ended[0] is not None:
            break
        if intra_burst_fired[0] > 0:
            assert timer_armed[0] == 0x1F40, f"Expected 8000ms intra-burst watchdog, got {timer_armed[0]}"
            continue

        tgt = struct.unpack("<Q", mu.mem_read(A + 0x10, 8))[0]
        if (now_before_sched >> 32) < (tgt >> 32):
            low_word_carries[0] += 1

        stage_hops = 0
        while intra_burst_fired[0] == 0 and ended[0] is None:
            assert timer_armed[0] is not None and timer_armed[0] > 0, (
                f"Expected RTOS stage timer via 0x101BF034, got {timer_armed[0]}"
            )
            now_box[0] += timer_armed[0]
            timer_armed[0] = None
            stage_hops += 1
            assert stage_hops <= 16, "Too many countdown stage hops"
            mu.reg_write(UC_ARM_REG_CPSR, 0x20)
            mu.reg_write(UC_ARM_REG_SP, 0xD0080000)
            mu.reg_write(UC_ARM_REG_LR, 0xD0090001)
            mu.emu_start(0x10206950 | 1, 0xD0090000)

        if ended[0] is not None:
            break
        assert intra_burst_fired[0] == 1, "Next interval shot was not triggered via 0x10206950 -> 0x102063F0"
        # 0x101FF308 subtracts 5ms shutter-curtain pre-trigger latency (subs r0, r0, #5 at 0x101FF32A):
        assert now_box[0] == tgt - 5, f"Stage-5 shutter pre-trigger {now_box[0]} != tgt - 5 ({tgt - 5})"
        now_box[0] += 5
        if strict_timer_delivery:
            assert now_box[0] - now_before_sched == interval_ms, (
                f"Expected total interval wait {interval_ms}ms, got {now_box[0] - now_before_sched}ms"
            )
    rem_final = struct.unpack("<I", mu.mem_read(A + 8, 4))[0]
    gaps = [shots_log[i + 1] - (shots_log[i] + exp_done_ms) for i in range(len(shots_log) - 1)]
    del mu
    gc.collect()
    return shots_log, gaps, rem_final, ended[0], low_word_carries[0]


def run_interval_timer_tests(blobs: dict[str, bytes]) -> dict:
    """Verify Stock bug reproduction AND Modified20 post-exposure scheduling (with genuine 64-bit carry & timer delivery)."""
    stock = blobs["stock"]
    m20 = blobs["m20"]

    s_33_log, _, s_33_rem, _, _ = _sim_interval_sequence(stock, 1000, 33, 32250, 1)
    s_34_log, _, s_34_rem, _, _ = _sim_interval_sequence(stock, 1000, 34, 32250, 1)
    assert len(s_33_log) == 1 and s_33_rem == 0
    assert len(s_34_log) == 2 and s_34_rem == 0

    s_31_log, s_31_gaps, _, _, _ = _sim_interval_sequence(stock, 31000, 4, 32250, 1)
    assert len(s_31_log) == 2 and s_31_gaps == [29750]

    s_61_log, s_61_gaps, _, _, _ = _sim_interval_sequence(stock, 61000, 4, 60250, 1)
    assert len(s_61_log) == 4 and s_61_gaps == [750, 750, 750]

    # Genuine 64-bit carry: t0_ms = 0xFFFFFF00 - 32250 so Shot 1 finishes at now = 0xFFFFFF00;
    # adding 1000ms crosses 0xFFFFFFFF -> 0x1_0000_02E8 via ADDS + ADC.W!
    carry_t0 = 0xFFFFFF00 - 32250
    m20_cases = [
        (1000, 33, 32250, 1, 1_000_000, 0),
        (500, 6, 32250, 1, 1_000_000, 0),
        (31000, 4, 32250, 1, 1_000_000, 0),
        (1000, 5, 60250, 1, 1_000_000, 0),
        (2000, 4, 300250, 1, 1_000_000, 0),
        (1000, 3, 600250, 1, 1_000_000, 0),
        (5000, 3, 10250, 2, 1_000_000, 0),
        (1000, 4, 32250, 1, carry_t0, 1),
    ]
    verified_cases = 0
    total_carries = 0
    for iv_ms, n_iv, exp_ms, s_per_iv, t0, exp_carries in m20_cases:
        log, gaps, rem, end_code, carries = _sim_interval_sequence(
            m20, iv_ms, n_iv, exp_ms, s_per_iv, t0, strict_timer_delivery=True
        )
        assert len(log) == n_iv * s_per_iv, f"Expected {n_iv * s_per_iv} shots, got {len(log)}"
        assert rem == 0 and end_code == 1
        assert carries == exp_carries, f"Expected {exp_carries} low-word carries, got {carries}"
        total_carries += carries
        for idx, g in enumerate(gaps):
            exp_gap = 0 if ((idx + 1) % s_per_iv != 0) else iv_ms
            assert g == exp_gap, f"Gap mismatch at idx {idx}: got {g}, expected {exp_gap}"
        verified_cases += 1

    assert total_carries >= 1
    return {
        "stock_bug_reproductions": 3,
        "m20_interval_post_exposure_sequences": verified_cases,
        "verified_64bit_low_word_carries": total_carries,
    }


def run_interval_endtime_tests(blobs: dict[str, bytes]) -> dict:
    """
    Emulate full native 0x1049C19A(out_rtc_ptr) ('End day/time' / '结束日期/时间') including
    ARM-state __aeabi_uldivmod (0x1023AE48), 0x101C486E US timer, 0x10205530 pause calculator,
    and 0x1049BFF4 calendar rollover across stock and Modified20.
    """
    UI_CTX = 0xD0010000
    OUT_RTC = 0xD0010100

    def _eval_endtime(
        fw_bytes: bytes,
        *,
        start_ymdhms: tuple[int, int, int, int, int] = (2026, 11, 16, 22, 0),
        start_choose: int = 1,
        iv_hms_tenths: tuple[int, int, int] = (0, 0, 10),
        intervals: int = 10,
        shots_per_iv: int = 1,
        exp_mode: int = 3,
        sub_1319: int = 0,
        tv_s24: int = -120,
        rat_1308: tuple[int, int] = (0, 0),
        lenr: int = 0,
        exp_delay_ms: int = 0,
        x200_tv_s24: int = 184,
        ui_screen: int = 0,
        iv_state: int = 0,
        rem_total_shots: int = 0,
    ) -> tuple[int, int, int, int, int]:
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        mu.mem_map(0x10000000, 0x02400000)
        mu.mem_map(0xC1800000, 0x01000000)
        mu.mem_map(0xD0000000, 0x00100000)
        mu.mem_write(BASE, fw_bytes)
        scatter_off = 0x11E94DD4 - BASE
        mu.mem_write(0xC1800000, fw_bytes[scatter_off : scatter_off + 0x101400])
        mu.mem_write(0xC181C99C, b"\x00\x00")

        y0, m0, d0, hh0, mm0 = start_ymdhms
        mu.mem_write(0xC1832440 + 9, bytes([start_choose]))
        if start_choose == 1:
            mu.mem_write(0xC1832440 + 0x28, struct.pack("<H", y0))
            for off, val in [(0x04, m0), (0x28, d0), (0x4C, hh0), (0x70, mm0)]:
                mu.mem_write(0xC18328CC + off, bytes([val]))

        ih, im, itenths = iv_hms_tenths
        mu.mem_write(0xC183295C + 0x04, struct.pack("<I", ih))
        mu.mem_write(0xC183295C + 0x28, struct.pack("<I", im))
        mu.mem_write(0xC183295C + 0x4C, struct.pack("<I", itenths))

        digits = [(intervals // 1000) % 10, (intervals // 100) % 10, (intervals // 10) % 10, intervals % 10]
        for idx, dg in enumerate(digits):
            mu.mem_write(0xC18329C8 + 4 + idx * 0x24, struct.pack("<I", dg))
        mu.mem_write(ADDR_IV_SHOTS_PER_INT, struct.pack("<I", shots_per_iv))

        mu.mem_write(ADDR_IV_OBJECT_A + 0x08, struct.pack("<I", rem_total_shots))
        mu.mem_write(ADDR_IV_OBJECT_A + 0x28, struct.pack("<I", shots_per_iv))

        mu.mem_write(RAM_PROP_136F, struct.pack("<I", exp_mode))
        mu.mem_write(RAM_PROP_1319, struct.pack("<I", sub_1319))
        mu.mem_write(RAM_PROP_0204, struct.pack("<i", tv_s24))
        mu.mem_write(RAM_PROP_1308, struct.pack("<hhi", rat_1308[0], 0, rat_1308[1]))
        mu.mem_write(UI_CTX + 2, struct.pack("<H", ui_screen))

        props = {0x0528: lenr, 0x1025: exp_delay_ms, 0x1034: x200_tv_s24 & 0xFFFF}

        def stub_rtc_now(u: Uc) -> None:
            dst = u.reg_read(UC_ARM_REG_R1)
            u.mem_write(dst, struct.pack("<HBBBBBBH", y0, m0, d0, hh0, mm0, 0, 0, 0))

        stubs = {
            0x10408E7C: lambda u: u.reg_write(UC_ARM_REG_R0, UI_CTX),
            0x1040A652: lambda u: u.mem_write(
                u.reg_read(UC_ARM_REG_R1), struct.pack("<I", min(u.reg_read(UC_ARM_REG_R0), 28800))
            ),
            0x10299208: lambda u: u.reg_write(UC_ARM_REG_R0, iv_state),
            0x10409234: lambda u: u.reg_write(UC_ARM_REG_R0, props.get(u.reg_read(UC_ARM_REG_R0), 0)),
            0x104A89C0: stub_rtc_now,
        }

        def hc(u, addr, sz, ud):
            fn = stubs.get(addr)
            if fn is not None:
                fn(u)
                u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))

        mu.hook_add(UC_HOOK_CODE, hc)

        sp_init = 0xD0080000
        callee_sentinels = {
            UC_ARM_REG_R4: 0x44444444,
            UC_ARM_REG_R5: 0x55555555,
            UC_ARM_REG_R6: 0x66666666,
            UC_ARM_REG_R7: 0x77777777,
            UC_ARM_REG_R8: 0x88888888,
            UC_ARM_REG_R9: 0x99999999,
            UC_ARM_REG_R10: 0xAAAAAAAA,
            UC_ARM_REG_R11: 0xBBBBBBBB,
        }
        for reg_id, val in callee_sentinels.items():
            mu.reg_write(reg_id, val)
        mu.reg_write(UC_ARM_REG_CPSR, 0x20)
        mu.reg_write(UC_ARM_REG_SP, sp_init)
        mu.reg_write(UC_ARM_REG_R0, OUT_RTC)
        mu.reg_write(UC_ARM_REG_LR, 0xD0090001)

        mu.emu_start(0x1049C19A | 1, 0xD0090000)

        assert mu.reg_read(UC_ARM_REG_SP) == sp_init, "SP corrupted across 0x1049C19A"
        for reg_id, val in callee_sentinels.items():
            assert mu.reg_read(reg_id) == val, f"Callee-saved reg {reg_id} corrupted across 0x1049C19A"

        y, m, d, hh, mm = struct.unpack_from("<HBBBB", mu.mem_read(OUT_RTC, 6), 0)
        del mu
        gc.collect()
        return (y, m, d, hh, mm)

    stock = blobs["stock"]
    m20 = blobs["m20"]

    # 1. Verify Stock under-reports long-exposure end time (hardcoded 32s x 1 interval = +1m -> 22:01):
    assert _eval_endtime(stock, intervals=10, tv_s24=-224) == (2026, 11, 16, 22, 1)
    assert _eval_endtime(stock, intervals=30, tv_s24=-120) == (2026, 11, 16, 22, 2)

    cases: list[tuple[str, dict, tuple[int, int, int, int, int]]] = [
        # M-mode stock shutter speeds
        ("m_1_8000s_single", {"intervals": 1, "tv_s24": 312}, (2026, 11, 16, 22, 0)),
        ("m_1_1000s_single", {"intervals": 1, "tv_s24": 240}, (2026, 11, 16, 22, 0)),
        ("m_1_1000s_61shots_1s_gap", {"intervals": 61, "tv_s24": 240}, (2026, 11, 16, 22, 1)),
        ("m_half_sec_10x_1s_gap", {"intervals": 10, "tv_s24": 24}, (2026, 11, 16, 22, 1)),
        ("m_1sec_60x_1s_gap", {"intervals": 60, "tv_s24": 0}, (2026, 11, 16, 22, 2)),
        ("m_30sec_real32s_30x_1s_gap", {"intervals": 30, "tv_s24": -120}, (2026, 11, 16, 22, 17)),
        # M-mode all 8 extended shutter speeds (10 shots + 9 x 1s gaps from 22:00)
        ("m_ext_60s", {"intervals": 10, "tv_s24": -144}, (2026, 11, 16, 22, 11)),
        ("m_ext_90s", {"intervals": 10, "tv_s24": -156}, (2026, 11, 16, 22, 16)),
        ("m_ext_120s", {"intervals": 10, "tv_s24": -168}, (2026, 11, 16, 22, 21)),
        ("m_ext_180s", {"intervals": 10, "tv_s24": -180}, (2026, 11, 16, 22, 31)),
        ("m_ext_240s", {"intervals": 10, "tv_s24": -192}, (2026, 11, 16, 22, 41)),
        ("m_ext_300s", {"intervals": 10, "tv_s24": -200}, (2026, 11, 16, 22, 51)),
        ("m_ext_480s", {"intervals": 10, "tv_s24": -216}, (2026, 11, 16, 23, 21)),
        ("m_ext_600s", {"intervals": 10, "tv_s24": -224}, (2026, 11, 16, 23, 41)),
        ("m_ext_600s_single_exact_10m", {"intervals": 1, "tv_s24": -224}, (2026, 11, 16, 22, 10)),
        # Multi-shot bursts (10 intervals x 3 shots/interval @ 60s + 2s gap = 1818s -> +31m)
        ("m_burst_10x3_60s_2s_gap", {"intervals": 10, "shots_per_iv": 3, "iv_hms_tenths": (0, 0, 20), "tv_s24": -144}, (2026, 11, 16, 22, 31)),
        # Long Exposure NR (0x0528): inactive at <=1s, doubles exposure at >1s
        ("lenr_1s_not_triggered", {"intervals": 30, "tv_s24": 0, "lenr": 1}, (2026, 11, 16, 22, 1)),
        ("lenr_2s_triggered", {"intervals": 30, "tv_s24": -24, "lenr": 1}, (2026, 11, 16, 22, 3)),
        ("lenr_600s_triggered", {"intervals": 3, "tv_s24": -224, "lenr": 1}, (2026, 11, 16, 23, 1)),
        # Exposure Delay Mode (0x1025): 3000ms x 20 shots + 19 x 1s = 79s -> +2m
        ("exp_delay_3s_20x", {"intervals": 20, "tv_s24": 240, "exp_delay_ms": 3000}, (2026, 11, 16, 22, 2)),
        ("exp_delay_invalid_ignored", {"intervals": 1, "tv_s24": 240, "exp_delay_ms": 99999}, (2026, 11, 16, 22, 0)),
        # M submodes: 121 intervals x 1s gap -> Bulb/Time (0ms) = 120.000s (+2m), x200 (1/200s=5ms x 121=605ms) = 120.605s -> 121s (+3m)
        ("m_bulb_submode", {"intervals": 121, "sub_1319": 1}, (2026, 11, 16, 22, 2)),
        ("m_time_submode", {"intervals": 121, "sub_1319": 2}, (2026, 11, 16, 22, 2)),
        ("m_x200_submode", {"intervals": 121, "sub_1319": 3, "x200_tv_s24": 184}, (2026, 11, 16, 22, 3)),
        # S mode: normal 30" and stale -224 clamped to -120 (32s * 10 + 9s = 329s -> +6m)
        ("s_mode_30s", {"exp_mode": 1, "intervals": 10, "tv_s24": -120}, (2026, 11, 16, 22, 6)),
        ("s_mode_clamp_from_600s", {"exp_mode": 1, "intervals": 10, "tv_s24": -224}, (2026, 11, 16, 22, 6)),
        # P / A / Auto modes (metered 0x1308 + slight AE rounding + Lo/Hi/unmetered sentinels)
        ("a_mode_metered_30s_192", {"exp_mode": 2, "intervals": 10, "rat_1308": (192, -960)}, (2026, 11, 16, 22, 6)),
        ("a_mode_slight_under_30s_clamped", {"exp_mode": 2, "intervals": 10, "rat_1308": (192, -965)}, (2026, 11, 16, 22, 6)),
        ("a_mode_unmetered_zero", {"exp_mode": 2, "intervals": 10, "rat_1308": (0, 0), "iv_hms_tenths": (0, 1, 0)}, (2026, 11, 16, 22, 9)),
        ("a_mode_lo_sentinel", {"exp_mode": 2, "intervals": 10, "rat_1308": (192, -0x80000000), "iv_hms_tenths": (0, 1, 0)}, (2026, 11, 16, 22, 9)),
        ("p_mode_hi_sentinel", {"exp_mode": 0, "intervals": 10, "rat_1308": (192, 0x7FFFFFFF), "iv_hms_tenths": (0, 1, 0)}, (2026, 11, 16, 22, 9)),
        # Pause screen (0x9E) with mid-burst remaining shots: rem_total_shots=5, K=2 -> rem_intervals=3 (2 gaps x 10s + 5 x 60s = 320s -> +6m)
        ("pause_screen_mid_burst", {"ui_screen": 0x9E, "rem_total_shots": 5, "shots_per_iv": 2, "iv_hms_tenths": (0, 0, 100), "tv_s24": -144}, (2026, 11, 16, 22, 6)),
        ("pause_screen_zero_rem", {"ui_screen": 0x9E, "rem_total_shots": 0, "shots_per_iv": 2, "tv_s24": -224}, (2026, 11, 16, 22, 0)),
        ("menu_zero_intervals", {"intervals": 0, "tv_s24": -224}, (2026, 11, 16, 22, 0)),
        # Year-end rollover + Start='Now' (start_choose=0): 2026-12-31 23:30 + 10x600s + 9x1s (+1h 41m) -> 2027-01-01 01:11
        ("year_rollover_start_now_600s", {"start_ymdhms": (2026, 12, 31, 23, 30), "start_choose": 0, "intervals": 10, "tv_s24": -224}, (2027, 1, 1, 1, 11)),
    ]

    assert len({tv for tv, _, _, _ in EXT_STEPS}) == 8
    for name, kw, expected in cases:
        got = _eval_endtime(m20, **kw)
        assert got == expected, f"End day/time case {name!r} failed: got {got}, expected {expected}"

    return {"interval_endtime_native_cases": len(cases) + 2}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "analysis/modified20-preflash-2026-11-16/lab-build/modified20-manifest.json",
    )
    args = ap.parse_args()

    manifest_p = args.manifest.resolve()
    assert manifest_p.is_file(), f"Missing manifest: {manifest_p}"
    manifest = json.loads(manifest_p.read_text(encoding="utf-8"))

    m20_bi = manifest_p.parent / "modified20-candidate.bi"
    m20_bytes = m20_bi.read_bytes()
    stock_bytes = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()

    syms = {k: int(v, 16) for k, v in manifest["cave_symbols"].items()}
    snap_p = ROOT / "analysis/modified16-preflash-2026-11-15/native-probe/probe-snap.json"
    if not snap_p.is_file():
        snap_p = ROOT / "analysis/modified15-preflash-2026-11-15/native-probe/probe-snap.json"
    snap = json.loads(snap_p.read_text(encoding="utf-8")) if snap_p.is_file() else {}

    blobs = {"m20": m20_bytes, "stock": stock_bytes}
    res_pred = run_predicate_tests(m20_bytes, snap, syms)
    res_lock = run_color_space_srgb_lock_tests(m20_bytes, snap)
    res_ui = run_ui_string_tests(blobs, snap)
    res_tramp = run_dual_branch_trampoline_tests(blobs, snap, syms)
    res_iv = run_interval_timer_tests(blobs)
    res_end = run_interval_endtime_tests(blobs)

    out_json = manifest_p.parent / "probe_modified20_native_result.json"
    report = {
        "candidate": manifest["candidate"],
        "design": manifest["design"],
        "modified20_sha256": manifest["modified20_sha256"],
        "tests": {
            **res_pred,
            **res_lock,
            **res_ui,
            **res_tramp,
            **res_iv,
            **res_end,
        },
        "status": "PASS",
    }
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()

"""Nikon Z6 C3.80 Interval Timer Shooting Post-Exposure Gap Patch (Modified19).

Root Cause of Stock Interval Timer + Long Exposure Bugs:
  1. Stock Nikon '30"' shutter speed (tv_s24 = -120, -5.0 EV) actually exposes for
     2^5 = 32,000,000 us = 32.000 seconds (~32.25s total until shot-completion
     callback 0x102065A8 runs), whereas our extended shutter patch (z6_m600_core.py)
     programs exact decimal durations (60" = 60.000s, 90" = 90.000s, 120" = 120.000s,
     300" = 300.000s, 600" = 600.000s).
  2. Stock Interval Timer Shooting (Object A = 0xC2376340) schedules shots on a rigid
     start-to-start wall-clock grid in 0x101FF380:
       101ff390: ldr  r1, [r4, #0x20]      ; r1 = interval_ms
       101ff392: ldrd r2, r0, [r4, #0x10]  ; (r2, r0) = old scheduled start [A+0x10]
       101ff396: adds r1, r2, r1
       101ff398: mov  r2, ip
       101ff39a: adc.w r0, r0, ip
       101ff39e: strd r1, r0, [r4, #0x10]  ; [A+0x10] = old_start + interval_ms
     - With Stock 30" (= 32.0s) + 1s interval x 32 shots: Shot 1 finishes at ~32.25s;
       0x101FF308 returns 0 (overdue), entering the catch-up loop at 0x101FF3E4..0x101FF40E
       which calls 0x101FEDBA on every missed 1s grid step, burning ~30-31 shot counts in
       a tight loop during/after a single exposure so only 1-2 frames are captured.
     - With Stock 30" (= 32.0s) + 31s interval: Shot 1 finishes at ~32.25s, missing the
       31.0s grid mark by 1.25s! 0x101FF3E4 burns 1 interval count and advances [A+0x10]
       to 62.0s, causing a ~29.75s (~30-31s) idle wait after the shutter closes.
     - With Extended 60" (= 60.0s exact) + 61s interval: Shot 1 finishes at ~60.25s < 61.0s,
       beating the 61.0s grid mark by ~0.75s without entering 0x101FF3E4.

Surgical Fix at 0x101FF392 (4 bytes):
  All three callers of 0x101FF380(r0, r1) (0x102065DE on shot completion, 0x10206444 on
  busy skip, 0x102069FC on focus-timeout skip) pass 64-bit now_ms from 0x101FC616(), saved
  into (r6, r7) at 0x101FF386..0x101FF388.
  Replacing `ldrd r2, r0, [r4, #0x10]` (d4e90420) with `mov r2, r6; mov r0, r7` (32463846)
  sets `[A+0x10] = now_ms + interval_ms`, matching Nikon's own Focus Shift post-exposure
  scheduler at 0x10206A4E..0x10206A58:
    - Redefines Interval Timer interval uniformly as post-exposure delay (shutter/burst
      completion to next shot start) across all shutter speeds (including 0.5s, 1s, 30",
      and 60"..600").
    - Preserves multi-shot bursts (Intervals x Shots/interval, S > 1) via 0x10206590.
    - Leaves Time-Lapse Movie (Object B = 0xC23763B0 at 0x101FF206) and Focus Shift
      (Object C = 0xC23763F8 at 0x10206A3E) 100% factory stock.
"""
from __future__ import annotations

from z6_m600_tables import BASE
from z6_thumb_emit import (
    COND_CS,
    COND_EQ,
    COND_GE,
    COND_GT,
    COND_LE,
    COND_LS,
    COND_LT,
    COND_NE,
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
    SP,
    ThumbEmitter,
    encode_branch32,
)

ADDR_IV_OBJECT_A = 0xC2376340
ADDR_IV_POST_EXPOSURE = 0x101FF392
STOCK_IV_POST_EXPOSURE_HEX = "d4e90420"  # ldrd r2, r0, [r4, #0x10]
PATCH_IV_POST_EXPOSURE_HEX = "32463846"  # mov r2, r6; mov r0, r7

# Modified20 Interval Timer UI "End day/time" (结束日期/时间, 0x1049C19A) dynamic calculator:
ADDR_IV_ENDTIME_HOOK = 0x1049C26C
STOCK_IV_ENDTIME_HOOK_HEX = "5fea0900"  # movs.w r0, sb
ADDR_IV_ENDTIME_RESUME_DIV = 0x1049C310
ADDR_IV_ENDTIME_RESUME_ZERO = 0x1049C31A
ADDR_IV_ENDTIME_CAVE = 0x1002E000
ADDR_IV_ENDTIME_CAVE_LIMIT = 0x1002EF04  # < ADDR_PTP_HDR - 0x10 (m600_v2 ptp_prefix)

ADDR_IV_SHOTS_PER_INT = 0xC1832A5C  # 0xC183295C + 0x6C + 0x94 (uint32 K, 1..9)
RAM_PROP_136F = 0xC24CC8FC          # Exposure mode (0=P, 1=S, 2=A, 3=M, >=4=Auto)
RAM_PROP_1319 = 0xC24CC790          # M shutter submode (0=Timed, 1=Bulb, 2=Time, 3=x200)
RAM_PROP_0204 = 0xC24CD9C0          # Dial shutter speed tv_s24 (int32/int16)
RAM_PROP_1308 = 0xC24CC73C          # Metered exposure rational {int16 denom, int16 pad, int32 num}
ADDR_GET_PROP = 0x10409234          # GetProperty(pid)
ADDR_US_TIMER_FN = 0x101C486E       # Microsecond exposure converter (handles stock + 60"..600" in M)

def build_interval_post_exposure_spans(
    stock: bytes,
    group_name: str = "m19_interval_post_exposure_gap",
) -> list[tuple[int, str, bytes, str]]:
    """Return validated span(s) redefining Interval Timer interval as post-exposure gap."""
    off = ADDR_IV_POST_EXPOSURE - BASE
    expected = bytes.fromhex(STOCK_IV_POST_EXPOSURE_HEX)
    actual = stock[off : off + len(expected)]
    assert actual == expected, (
        f"Anchor mismatch at 0x{ADDR_IV_POST_EXPOSURE:08x}: "
        f"expected {expected.hex()}, found {actual.hex()}"
    )
    patch = bytes.fromhex(PATCH_IV_POST_EXPOSURE_HEX)
    assert len(patch) == len(expected) == 4
    return [
        (
            ADDR_IV_POST_EXPOSURE,
            group_name,
            patch,
            (
                "Interval Timer 0x101FF392: compute next shot target [0xC2376350] = "
                "now_ms + interval_ms (mov r2, r6; mov r0, r7) instead of old_target + interval_ms, "
                "preventing background shot-count burning during long exposures and defining interval "
                "uniformly as post-exposure delay"
            ),
        )
    ]


def _emit_udiv(em: ThumbEmitter, rd: int, rn: int, rm: int) -> None:
    assert rd != rm or rd != rn or True
    em.h32(0xFBB0 | rn, 0xF0F0 | (rd << 8) | rm)


def _emit_mla(em: ThumbEmitter, rd: int, rn: int, rm: int, ra: int) -> None:
    em.h32(0xFB00 | rn, (ra << 12) | (rd << 8) | rm)


def _emit_adds_w(em: ThumbEmitter, rd: int, rn: int, rm: int) -> None:
    em.h32(0xEB10 | rn, (rd << 8) | rm)


def _emit_adc_w(em: ThumbEmitter, rd: int, rn: int, rm: int) -> None:
    em.h32(0xEB40 | rn, (rd << 8) | rm)


def build_interval_endtime_cave() -> tuple[bytes, dict[str, int]]:
    """
    Build Thumb-2 cave at 0x1002E000 for 0x1049C19A ('End day/time' / '结束日期/时间'):
      total_ms = (N - 1) * (interval_tenths * 100)
               + total_shots * (exp_ms + lenr_ms + exp_delay_ms)
      total_sec = (total_ms + 500) // 1000
    """
    em = ThumbEmitter(ADDR_IV_ENDTIME_CAVE)
    em.label("tramp_iv_endtime")

    # Entry from 0x1049C26C: sb = N (intervals), (r6, r5) = interval_tenths (uint64),
    # r8 = 4 (menu path) or 0 (active/pause path where [sp, #0x24] = rem_total_shots).
    em.mov_reg(R0, R9)
    em.cmp_u8(R0, 0)
    em.j_cond(COND_EQ, "zero_intervals")

    em.cmp_u8(R8, 0)
    em.j_cond(COND_NE, "menu_shots")
    em.ldr_u32(R1, SP, 0x24)
    em.cmp_u8(R1, 0)
    em.j_cond(COND_EQ, "zero_intervals")
    em.j_local("have_shots")

    em.label("menu_shots")
    em.set_u32(R1, ADDR_IV_SHOTS_PER_INT)
    em.ldr_u32(R1, R1, 0)
    em.mul32(R1, R0, R1)
    em.cmp_u8(R1, 0)
    em.j_cond(COND_NE, "have_shots")

    em.label("zero_intervals")
    em.mov_u16(R0, 0)
    em.mov_u16(R1, 0)
    em.jump_abs(ADDR_IV_ENDTIME_RESUME_ZERO)
    em.label("have_shots")
    em.mov_reg(R10, R1)   # sl = total_shots
    em.subs_u8(R0, 1)
    em.mov_reg(R9, R0)    # sb = N - 1 (num_gaps)

    em.sp_sub(16)         # 8-byte AAPCS aligned scratch [sp, #0..15]
    em.mov_u16(R7, 0)     # r7 = exp_ms = 0 default

    em.set_u32(R0, RAM_PROP_136F)
    em.ldr_u32(R0, R0, 0)
    em.cmp_u8(R0, 3)
    em.j_cond(COND_EQ, "mode_m")
    em.cmp_u8(R0, 1)
    em.j_cond(COND_EQ, "mode_s")

    # P / A / Auto: read metered rational {int16 denom, int16 pad, int32 num} at 0xC24CC73C
    em.set_u32(R0, RAM_PROP_1308)
    em.ldr_s16(R2, R0, 0)
    em.cmp_u8(R2, 0)
    em.j_cond(COND_LE, "after_exp")
    em.mov_u16(R3, 0x400)
    em.cmp_reg(R2, R3)
    em.j_cond(COND_GT, "after_exp")
    em.ldr_u32(R3, R0, 4)
    # Reject Lo/unmetered (< -10 * denom) and Hi (> 16 * denom); clamp [-10..-5]*denom to -5*denom (30")
    em.mov_u16(R1, 10)
    em.neg_reg(R1, R1)
    em.mul32(R1, R1, R2)
    em.cmp_reg(R3, R1)
    em.j_cond(COND_LT, "after_exp")
    em.mov_u16(R1, 5)
    em.neg_reg(R1, R1)
    em.mul32(R1, R1, R2)
    em.cmp_reg(R3, R1)
    em.j_cond(COND_GE, "pa_check_hi")
    em.mov_reg(R3, R1)
    em.label("pa_check_hi")
    em.lsl_imm(R1, R2, 4)
    em.cmp_reg(R3, R1)
    em.j_cond(COND_GT, "after_exp")
    em.str_u32(R2, SP, 0)
    em.str_u32(R3, SP, 4)
    em.j_local("run_us_timer")

    # S mode: read dial tv_s24 at 0xC24CD9C0, clamp to >= -120 (30" max in S mode)
    em.label("mode_s")
    em.set_u32(R1, RAM_PROP_0204)
    em.ldr_u32(R1, R1, 0)
    em.sxth(R1, R1)
    em.mov_u16(R2, 255)
    em.neg_reg(R2, R2)
    em.cmp_reg(R1, R2)
    em.j_cond(COND_LT, "after_exp")
    em.mov_u16(R2, 384)
    em.cmp_reg(R1, R2)
    em.j_cond(COND_GT, "after_exp")
    em.mov_u16(R2, 120)
    em.neg_reg(R2, R2)
    em.cmp_reg(R1, R2)
    em.j_cond(COND_GE, "pack_s24")
    em.mov_reg(R1, R2)
    em.j_local("pack_s24")

    # M mode: check submode 0x1319 (0=Timed incl. 60"..600", 3=x200, 1/2=Bulb/Time -> 0ms)
    em.label("mode_m")
    em.set_u32(R1, RAM_PROP_1319)
    em.ldr_u32(R1, R1, 0)
    em.cmp_u8(R1, 0)
    em.j_cond(COND_EQ, "m_timed")
    em.cmp_u8(R1, 3)
    em.j_cond(COND_NE, "after_exp")
    em.mov_u16(R0, 0x1034)
    em.call_abs(ADDR_GET_PROP)
    em.sxth(R1, R0)
    em.j_local("check_m_bounds")

    em.label("m_timed")
    em.set_u32(R1, RAM_PROP_0204)
    em.ldr_u32(R1, R1, 0)
    em.sxth(R1, R1)

    em.label("check_m_bounds")
    em.mov_u16(R2, 255)
    em.neg_reg(R2, R2)
    em.cmp_reg(R1, R2)
    em.j_cond(COND_LT, "after_exp")
    em.mov_u16(R2, 384)
    em.cmp_reg(R1, R2)
    em.j_cond(COND_GT, "after_exp")

    em.label("pack_s24")
    em.mov_u16(R0, 24)
    em.str_u32(R0, SP, 0)
    em.str_u32(R1, SP, 4)

    em.label("run_us_timer")
    em.mov_reg(R0, SP)
    em.call_abs(ADDR_US_TIMER_FN)
    em.cmp_u8(R1, 0)
    em.j_cond(COND_NE, "clamp_max_exp")
    em.set_u32(R2, 600_000_000)
    em.cmp_reg(R0, R2)
    em.j_cond(COND_CS, "clamp_max_exp")
    em.add_u12(R0, R0, 500)
    em.mov_u16(R2, 1000)
    _emit_udiv(em, R7, R0, R2)
    em.j_local("after_exp")

    em.label("clamp_max_exp")
    em.set_u32(R7, 600_000)

    em.label("after_exp")
    em.mov_reg(R4, R7)    # r4 = shot_ms = exp_ms

    # Long Exposure NR (0x0528): active on Z6 when shutter speed is slower than 1s (exp_ms > 1000)
    em.mov_u16(R1, 1000)
    em.cmp_reg(R7, R1)
    em.j_cond(COND_LS, "skip_lenr")
    em.mov_u16(R0, 0x0528)
    em.call_abs(ADDR_GET_PROP)
    em.cmp_u8(R0, 0)
    em.j_cond(COND_EQ, "skip_lenr")
    em.add_lsl(R4, R4, R7, 0)

    em.label("skip_lenr")
    # Exposure Delay Mode (0x1025): returns milliseconds directly (0, 200, 500, 1000, 2000, 3000)
    em.mov_u16(R0, 0x1025)
    em.call_abs(ADDR_GET_PROP)
    em.mov_u16(R1, 10000)
    em.cmp_reg(R0, R1)
    em.j_cond(COND_CS, "skip_delay")
    em.add_lsl(R4, R4, R0, 0)

    em.label("skip_delay")
    # 64-bit total_ms = (N - 1) * interval_tenths * 100 + total_shots * shot_ms
    em.mov_reg(R0, R9)               # r0 = N - 1
    em.umull64(R2, R3, R6, R0)       # (r2, r3) = interval_tenths_lo * (N - 1)
    _emit_mla(em, R3, R5, R0, R3)    # r3 += interval_tenths_hi * (N - 1)
    em.mov_u16(R0, 100)
    em.umull64(R8, R1, R2, R0)       # (r8, r1) = gap_tenths_lo * 100
    _emit_mla(em, R5, R3, R0, R1)    # r5 = gap_tenths_hi * 100 + r1 -> (r8, r5) = gap_total_ms

    em.mov_reg(R0, R10)              # r0 = total_shots
    em.umull64(R0, R1, R0, R4)       # (r0, r1) = total_shots * shot_ms
    _emit_adds_w(em, R0, R0, R8)     # r0 = total_ms_lo
    _emit_adc_w(em, R5, R5, R1)      # r5 = total_ms_hi

    em.sp_add(16)
    em.mov_u16(R1, 500)              # +500 ms round-to-nearest-second at 0x1049C310
    em.mov_u16(R2, 1000)             # divisor_lo = 1000
    em.mov_u16(R3, 0)                # divisor_hi = 0
    em.jump_abs(ADDR_IV_ENDTIME_RESUME_DIV)

    cave_bytes = em.finish()
    syms = dict(em.labels)
    syms["iv_cave_end"] = ADDR_IV_ENDTIME_CAVE + len(cave_bytes)
    assert syms["iv_cave_end"] <= ADDR_IV_ENDTIME_CAVE_LIMIT, (
        f"iv endtime cave overflowed: {syms['iv_cave_end']:#x} > {ADDR_IV_ENDTIME_CAVE_LIMIT:#x}"
    )
    return cave_bytes, syms


def build_all_m20_interval_spans(
    stock: bytes,
) -> tuple[list[tuple[int, str, bytes, str]], dict[str, int]]:
    """Build Modified20 Interval Timer post-exposure scheduling + dynamic End day/time spans."""
    spans = build_interval_post_exposure_spans(
        stock, group_name="m20_interval_post_exposure_gap"
    )

    hook_off = ADDR_IV_ENDTIME_HOOK - BASE
    expected_hook = bytes.fromhex(STOCK_IV_ENDTIME_HOOK_HEX)
    actual_hook = stock[hook_off : hook_off + len(expected_hook)]
    assert actual_hook == expected_hook, (
        f"Anchor mismatch at 0x{ADDR_IV_ENDTIME_HOOK:08x}: "
        f"expected {expected_hook.hex()}, found {actual_hook.hex()}"
    )

    cave_bytes, syms = build_interval_endtime_cave()
    cave_off = ADDR_IV_ENDTIME_CAVE - BASE
    expected_cave = b"\x00" * len(cave_bytes)
    actual_cave = stock[cave_off : cave_off + len(cave_bytes)]
    assert actual_cave == expected_cave, (
        f"Non-zero bytes in cave 0x{ADDR_IV_ENDTIME_CAVE:08x}..0x{ADDR_IV_ENDTIME_CAVE + len(cave_bytes):08x}"
    )

    hook_patch = encode_branch32(ADDR_IV_ENDTIME_HOOK, syms["tramp_iv_endtime"], link=False)
    assert len(hook_patch) == 4

    spans.append(
        (
            ADDR_IV_ENDTIME_CAVE,
            "m20_interval_endtime_cave",
            cave_bytes,
            (
                f"Interval Timer End day/time cave ({len(cave_bytes)}B at 0x1002E000): "
                "dynamically queries active shutter speed (M timed incl. 60\"..600\", M x200, "
                "M Bulb/Time=0, S clamped <=30\", P/A/Auto metered 0x1308) + LENR (>1s) + "
                "Exposure Delay across all N*K frames plus (N-1) post-exposure intervals"
            ),
        )
    )
    spans.append(
        (
            ADDR_IV_ENDTIME_HOOK,
            "m20_interval_endtime_hook",
            hook_patch,
            (
                "Hook 0x1049C26C -> 0x1002E000 so Interval Timer 'End day/time' (结束日期/时间) "
                "reflects actual exposure duration + post-exposure interval logic"
            ),
        )
    )
    spans.sort(key=lambda s: s[0])
    return spans, syms

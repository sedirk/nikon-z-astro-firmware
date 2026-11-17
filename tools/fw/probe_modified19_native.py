"""Unicorn native ARM/Thumb verification for Nikon Z6 C3.80 Modified19 (Full Color Space UI v2 + Post-Exposure Interval Timer + RAW Trampolines)."""
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
    UI_OVERRIDES,
)
from z6_interval_post_exposure import ADDR_IV_OBJECT_A

ROOT = THIS_DIR.parents[1]


def _reset_rig(rig: Rig) -> None:
    rig.uc.reg_write(UC_ARM_REG_CPSR, 0x20)
    rig.uc.reg_write(UC_ARM_REG_SP, RAM + 0x30000)
    rig.uc.reg_write(UC_ARM_REG_LR, 0x10020001)


def _set_astro_ram(rig: Rig, color_space: int, effective_rec: int) -> None:
    rig.put(RAM_PROP_0508, color_space, "B")
    rig.put(RAM_PROP_131B, effective_rec)


def run_predicate_tests(m19: bytes, snap: dict, syms: dict[str, int]) -> dict:
    rig = Rig(m19, snap)
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


def run_color_space_srgb_lock_tests(m19: bytes, snap: dict) -> dict:
    rig = Rig(m19, snap)
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
    """Verify GetLanguageString (0x104C0104) across all 36 languages for all 5 overridden IDs + 5 untouched neighbors."""
    rig_s = Rig(blobs["stock"], snap)
    rig_m = Rig(blobs["m19"], snap)

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
        for sid, _, txt_en, txt_cn, txt_tw in UI_OVERRIDES:
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
    m19 = blobs["m19"]
    rig = Rig(m19, snap)
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
) -> tuple[list[int], list[int], int, int | None]:
    """Emulate native 0x10200D9C (shutter start) + 0x102065A8 -> 0x101FF380 -> 0x101FF308 -> 0x101FF2D0."""
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
        0x100600C4: lambda u: u.reg_write(UC_ARM_REG_R0, 0),
        0x10061FAA: lambda u: None,
        0x10206E90: lambda u: intra_burst_fired.__setitem__(0, intra_burst_fired[0] + 1),
        0x101FED02: lambda u: ended.__setitem__(0, u.reg_read(UC_ARM_REG_R0)),
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
        if rem == 0:
            break
        shots_log.append(now_box[0] - t0_ms)
        rem -= 1
        mu.mem_write(A + 8, struct.pack("<I", rem))
        mu.mem_write(A + 5, bytes([2]))
        if rem == 0:
            ended[0] = 1
            break
        now_box[0] += exp_done_ms
        ended[0] = None
        intra_burst_fired[0] = 0
        mu.reg_write(UC_ARM_REG_SP, 0xD0080000)
        mu.reg_write(UC_ARM_REG_R0, 0)
        mu.reg_write(UC_ARM_REG_LR, 0xD0090001)
        mu.emu_start(0x102065A8 | 1, 0xD0090000)
        if ended[0] is not None:
            break
        if intra_burst_fired[0] > 0:
            continue
        tgt = struct.unpack("<Q", mu.mem_read(A + 0x10, 8))[0]
        assert tgt >= now_box[0], f"Scheduled target {tgt} < now {now_box[0]}"
        now_box[0] = tgt

    rem_final = struct.unpack("<I", mu.mem_read(A + 8, 4))[0]
    gaps = [shots_log[i + 1] - (shots_log[i] + exp_done_ms) for i in range(len(shots_log) - 1)]
    del mu
    gc.collect()
    return shots_log, gaps, rem_final, ended[0]


def run_interval_timer_tests(blobs: dict[str, bytes]) -> dict:
    """Verify Stock bug reproduction AND Modified19 post-exposure interval scheduling (including 64-bit carry)."""
    stock = blobs["stock"]
    m19 = blobs["m19"]

    # A. Reproduce Stock bugs:
    # 1) Stock 30" (= 32.0s + 0.25s = 32,250ms) + 1s interval -> burns 32 extra shot counts in 0x101FF3E4!
    s_32_log, _, s_32_rem, _ = _sim_interval_sequence(stock, 1000, 32, 32250, 1)
    s_34_log, _, s_34_rem, _ = _sim_interval_sequence(stock, 1000, 34, 32250, 1)
    assert len(s_32_log) == 1 and s_32_rem == 0
    assert len(s_34_log) == 2 and s_34_rem == 0

    # 2) Stock 30" (= 32,250ms) + 31s interval x 4 shots -> misses 31s deadline, waits 29.75s (~30s) & drops half the shots!
    s_31_log, s_31_gaps, _, _ = _sim_interval_sequence(stock, 31000, 4, 32250, 1)
    assert len(s_31_log) == 2 and s_31_gaps == [29750]

    # 3) Stock with Extended 60" (= 60,250ms) + 61s interval x 4 shots -> beats 61s deadline (0.75s gap), 4 shots
    s_61_log, s_61_gaps, _, _ = _sim_interval_sequence(stock, 61000, 4, 60250, 1)
    assert len(s_61_log) == 4 and s_61_gaps == [750, 750, 750]

    # B. Verify Modified19 post-exposure interval across all shutter durations, multi-shot bursts, and 32-bit carry boundary:
    m19_cases = [
        (1000, 32, 32250, 1, 1_000_000),   # 30" (32.25s) + 1s gap x 32 shots -> all 32 shots, exact 1.000s gap!
        (500, 6, 32250, 1, 1_000_000),     # 30" (32.25s) + 0.5s minimum gap x 6 shots -> exact 0.500s gap!
        (31000, 4, 32250, 1, 1_000_000),   # 30" (32.25s) + 31s gap x 4 shots -> exact 31.000s gap!
        (1000, 5, 60250, 1, 1_000_000),    # 60" (60.25s) + 1s gap x 5 shots -> exact 1.000s gap!
        (2000, 4, 300250, 1, 1_000_000),   # 300" (300.25s) + 2s gap x 4 shots -> exact 2.000s gap!
        (5000, 3, 10250, 2, 1_000_000),    # 3 intervals x 2 shots/interval burst -> [0, 5000, 0, 5000, 0]!
        (1000, 4, 32250, 1, 0xFFFFFF00),   # 64-bit carry across 0xFFFFFFFF -> 0x1_0000_xxxx boundary!
    ]
    verified_cases = 0
    for iv_ms, n_iv, exp_ms, s_per_iv, t0 in m19_cases:
        log, gaps, rem, end_code = _sim_interval_sequence(m19, iv_ms, n_iv, exp_ms, s_per_iv, t0)
        assert len(log) == n_iv * s_per_iv, f"Expected {n_iv * s_per_iv} shots, got {len(log)}"
        assert rem == 0 and end_code == 1
        for idx, g in enumerate(gaps):
            exp_gap = 0 if ((idx + 1) % s_per_iv != 0) else iv_ms
            assert g == exp_gap, f"Gap mismatch at idx {idx}: got {g}, expected {exp_gap}"
        verified_cases += 1

    return {
        "stock_bug_reproductions": 3,
        "m19_interval_post_exposure_sequences": verified_cases,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "analysis/modified19-preflash-2026-11-16/lab-build/modified19-manifest.json",
    )
    args = ap.parse_args()

    manifest_p = args.manifest.resolve()
    assert manifest_p.is_file(), f"Missing manifest: {manifest_p}"
    manifest = json.loads(manifest_p.read_text(encoding="utf-8"))

    m19_bi = manifest_p.parent / "modified19-candidate.bi"
    m19_bytes = m19_bi.read_bytes()
    stock_bytes = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()

    syms = {k: int(v, 16) for k, v in manifest["cave_symbols"].items()}
    snap_p = ROOT / "analysis/modified16-preflash-2026-11-15/native-probe/probe-snap.json"
    if not snap_p.is_file():
        snap_p = ROOT / "analysis/modified15-preflash-2026-11-15/native-probe/probe-snap.json"
    snap = json.loads(snap_p.read_text(encoding="utf-8")) if snap_p.is_file() else {}

    blobs = {"m19": m19_bytes, "stock": stock_bytes}
    res_pred = run_predicate_tests(m19_bytes, snap, syms)
    res_lock = run_color_space_srgb_lock_tests(m19_bytes, snap)
    res_ui = run_ui_string_tests(blobs, snap)
    res_tramp = run_dual_branch_trampoline_tests(blobs, snap, syms)
    res_iv = run_interval_timer_tests(blobs)

    out_json = manifest_p.parent / "probe_modified19_native_result.json"
    report = {
        "candidate": manifest["candidate"],
        "design": manifest["design"],
        "modified19_sha256": manifest["modified19_sha256"],
        "tests": {
            **res_pred,
            **res_lock,
            **res_ui,
            **res_tramp,
            **res_iv,
        },
        "verdict": "100% PASS",
    }
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"ALL UNICORN NATIVE PROBES PASSED: {json.dumps(report['tests'])}")


if __name__ == "__main__":
    main()

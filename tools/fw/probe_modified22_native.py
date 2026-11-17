"""Offline Unicorn native end-to-end verification for Nikon Z6 C3.80 Modified22.

Verifies:
  1. End-to-end UI Color space submenu actions (0x104A149E 'Standard sRGB' & 0x104A14A8 'Astro RAW sRGB')
     -> native SetProperty (0x100703E4) -> native GetProperty (0x100700A0) RAM slot discovery for
     PID 0x0526 (0xC24CDEA0), PID 0x130A (0xC24CC74C), PID 0x131B (0xC24CC798), PID 0x0508 (0xC24CDE28),
     PID 0x1381 (0xC24CC948), PID 0x0440 (0xC24CDDC4), and PID 0x0500 (0xC24CDE08), plus U1/U2/U3 bank copy
     (0x100701DE / 0x10070178).
  2. Exact reproduction of real-camera samples/11.16_modified21 failure (Manual M mode, Auto ISO 0x0508=0,
     Focus Shift 0x0440=100, Pure RAW 0x131B=1, Color space 0x0526=1):
       - Modified20 fn_is_astro_r0() == 0 (misread 0xC24CDDC4 == 100)
       - Modified21 fn_is_astro_r0() == 0 (misread 0xC24CDE28 == 0) AND 0x1014BAEA sets 0x130A = 1 -> '_Z61'
       - Modified22 fn_is_astro_r0() == 1 (reads 0xC24CDEA0 == 1 && 0xC24CC798 == 1) AND 0x1014BAEA locks
         0x130A = 0 -> still-capture bulk read 0x101703DC(0xC18B6390) -> DCF builder 0x10255850 -> 'Z61_'!
  3. Native Effective Color Space evaluator (0x1014BAEA) locking PID 0x130A = 0 (sRGB) across all exposure
     modes while preserving PID 0x0526 = 0/1, PLUS verification that Auto ISO sensitivity control
     (0x1014F638 -> PID 0x1381 and UI submenu condition 0x1040AD00 -> PID 0x0508) is 100% restored to Stock!
  4. All 13 patched Astro RAW firmware hook sites (26+ dual-branch Stock vs Astro paths + NZCV/register
     preservation).
  5. 36-language GetLanguageString (0x104C0104) verification for '天文直通RAW模式' / '标准 (sRGB)' /
     '直通RAW (sRGB)' wording + 5 untouched neighbor String IDs (360 checks).
  6. Post-exposure Interval Timer sequences & 37-case native End day/time (0x1049C19A) matrix.
"""
from __future__ import annotations
import argparse
import gc
import json
import struct
from pathlib import Path
import sys

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm_const import (
    UC_ARM_REG_CPSR,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R6,
    UC_ARM_REG_SP,
)

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from prepare_modified22_lab import (
    M20_SHA,
    M21_SHA,
    STOCK_SHA,
    _apply_spans,
    sha,
    update_crc,
)
from probe_modified20_native import run_interval_endtime_tests, run_interval_timer_tests
from probe_raw_candidates import BASE, RAM, Rig
from z6_astro_ui_color_space_v2 import (
    ADDR_M9_SANITIZER,
    LANG_ZH_CN,
    LANG_ZH_TW,
    RAM_PROP_0508,
    RAM_PROP_0508_REAL,
    RAM_PROP_0526,
    RAM_PROP_130A,
    RAM_PROP_131B,
    RAM_PROP_1381,
    UI_OVERRIDES_M21,
    build_all_m20_astro_ui_spans,
    build_all_m21_astro_ui_spans,
)
from z6_c380_container import load_stock_eg_module
from z6_interval_post_exposure import build_all_m20_interval_spans
from z6_m600_v2 import build_all_m600_v2_spans

ROOT = THIS_DIR.parents[1]


def _synthesize_m20_m21_from_stock(
    stock_bytes: bytes,
) -> tuple[bytes, dict[str, int], bytes, dict[str, int]]:
    """Deterministically reconstruct historical M20 and M21 images + symbols from Stock in memory."""
    m600_spans = build_all_m600_v2_spans(stock_bytes)
    iv20_spans, iv_syms = build_all_m20_interval_spans(stock_bytes)
    m20_ui, syms20_ui = build_all_m20_astro_ui_spans(stock_bytes)
    m21_ui, syms21_ui = build_all_m21_astro_ui_spans(stock_bytes)

    m20_bytes = _apply_spans(stock_bytes, m20_ui + iv20_spans + m600_spans)
    m21_bytes = _apply_spans(stock_bytes, m21_ui + iv20_spans + m600_spans)
    assert sha(m20_bytes) == M20_SHA, "Synthesized M20 SHA-256 mismatch"
    assert sha(m21_bytes) == M21_SHA, "Synthesized M21 SHA-256 mismatch"

    syms20 = {**syms20_ui, **iv_syms}
    syms21 = {**syms21_ui, **iv_syms}
    return m20_bytes, syms20, m21_bytes, syms21


def _synthesize_m22_from_manifest(stock_bytes: bytes, manifest: dict) -> bytes:
    buf = bytearray(stock_bytes)
    for ed in manifest["edits"]:
        off = int(ed["address"], 16) - BASE
        before = bytes.fromhex(ed["before"])
        after = bytes.fromhex(ed["after"])
        assert buf[off : off + len(before)] == before
        buf[off : off + len(after)] = after
    update_crc(buf)
    out = bytes(buf)
    assert sha(out) == manifest["modified22_sha256"], "Synthesized M22 SHA-256 mismatch"
    return out


def _reset_rig(rig: Rig) -> None:
    rig.uc.reg_write(UC_ARM_REG_CPSR, 0x20)
    rig.uc.reg_write(UC_ARM_REG_SP, RAM + 0x30000)
    rig.uc.reg_write(UC_ARM_REG_LR, 0x10020001)


def _init_data_and_c24_ram(rig: Rig) -> None:
    for m_addr in range(0xC2400000, 0xC2600000, 0x100000):
        try:
            rig.uc.mem_map(m_addr, 0x100000)
        except Exception:
            pass
    # Populate .data segments from ROM init table (0x10034000..0x10034120) so 0xC18B6390 etc. are live:
    for off in range(0x14000, 0x14120, 16):
        src, dst, n, handler = struct.unpack_from("<4I", rig.blob, off)
        if handler == 0x1002006C and 0xC1800000 <= dst < dst + n <= 0xC5800000:
            rig.uc.mem_write(dst, rig.blob[src - BASE : src - BASE + n])


def _discover_native_prop_ram(rig: Rig, pid: int) -> int:
    """Execute native GetProperty(0x100700A0) and capture the exact C24xxxxx RAM slot it reads."""
    reads: list[int] = []

    def _on_read(_uc, _access, addr, _size, _val, _user):
        if 0xC2400000 <= addr < 0xC2500000:
            reads.append(addr)

    h = rig.uc.hook_add(UC_HOOK_MEM_READ, _on_read)
    try:
        out_p = RAM + 0x49000
        _reset_rig(rig)
        res = rig.call(0x100700A0, [pid, out_p])
        assert int(res["registers"]["r0"], 16) == 1, f"GetProperty({pid:#06x}) failed"
        assert len(reads) == 1, f"Expected 1 C24xxxxx read for {pid:#06x}, got {[hex(x) for x in reads]}"
        return reads[0]
    finally:
        rig.uc.hook_del(h)


def _run_color_space_eval_130a(rig: Rig, cs_0526: int, exp_mode: int = 4, flags_r4: int = 0) -> int:
    """Execute native 0x1014BAEA (PID 0x0526 -> PID 0x130A evaluator) and write result into RAM_PROP_130A."""
    written: list[tuple[int, int]] = []
    u = rig.uc

    def _hook_set_eval(uc, address, _size, _user):
        if address == 0x1014A6E0:
            pid_p = uc.reg_read(UC_ARM_REG_R1)
            val_p = uc.reg_read(UC_ARM_REG_R2)
            pid = struct.unpack("<I", uc.mem_read(pid_p, 4))[0]
            val = struct.unpack("<I", uc.mem_read(val_p, 4))[0]
            written.append((pid, val))
            struct.pack_into("<I", b_tmp := bytearray(4), 0, val)
            if pid == 0x130A:
                uc.mem_write(RAM_PROP_130A, bytes(b_tmp))
            uc.reg_write(UC_ARM_REG_R0, 1)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    h = u.hook_add(UC_HOOK_CODE, _hook_set_eval, begin=0x1014A6E0, end=0x1014A6E4)
    try:
        IN_STRUCT = RAM + 0x48000
        CTX_STRUCT = RAM + 0x48100
        u.mem_write(IN_STRUCT, b"\x00" * 0x40)
        u.mem_write(CTX_STRUCT, b"\x00" * 0x100)
        # [r1+0x00]=r7 (0x180C=1), [r1+0x04]=0x0526, [r1+0x08]=old 0x130A (set 0xFF to force write),
        # [r1+0x0C]=r4 flags, [r1+0x14]=exposure mode
        rig.put(IN_STRUCT + 0x00, 1)
        rig.put(IN_STRUCT + 0x04, cs_0526)
        rig.put(IN_STRUCT + 0x08, 0xFF)
        rig.put(IN_STRUCT + 0x0C, flags_r4)
        rig.put(IN_STRUCT + 0x14, exp_mode)
        _reset_rig(rig)
        rig.call(0x1014BAEA, [0, IN_STRUCT, CTX_STRUCT])
        assert len(written) == 1 and written[0][0] == 0x130A, f"Unexpected 0x1014BAEA writes: {written}"
        return written[0][1]
    finally:
        u.hook_del(h)


def _run_dcf_prefix_0x10255850(rig: Rig, cs_byte_val: int, file_naming: bytes = b"Z61\x00") -> str:
    """Execute native DCF 4-char prefix builder 0x10255850(mode=0, &cs_byte, out_4char)."""
    u = rig.uc
    # Write File Naming PID 0x0500 ("Z61\0" or "DSC\0") via native SetProperty 0x100703E4:
    SRC_STR = RAM + 0x49100
    u.mem_write(SRC_STR, file_naming)
    _reset_rig(rig)
    r_set = rig.call(0x100703E4, [0x0500, 4, SRC_STR])
    assert int(r_set["registers"]["r0"], 16) == 1

    # Bridge RTOS wrapper 0x1017050A(pid, dst_buf, max_len, ...) -> native string GetProperty 0x100700EE(pid, max_len, dst_buf):
    def _hook_1017050a(uc, address, _size, _user):
        if address == 0x1017050A:
            pid = uc.reg_read(UC_ARM_REG_R0)
            dst_buf = uc.reg_read(UC_ARM_REG_R1)
            max_len = uc.reg_read(UC_ARM_REG_R2)
            raw_b = bytes(uc.mem_read(0xC24CDE08, min(max_len, 4)))
            assert pid == 0x0500
            uc.mem_write(dst_buf, raw_b)
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    h = u.hook_add(UC_HOOK_CODE, _hook_1017050a, begin=0x1017050A, end=0x1017050E)
    try:
        CS_BYTE_PTR = RAM + 0x49200
        OUT_PREFIX = RAM + 0x49210
        u.mem_write(CS_BYTE_PTR, bytes([cs_byte_val & 0xFF]))
        u.mem_write(OUT_PREFIX, b"\x00" * 8)
        _reset_rig(rig)
        rig.call(0x10255850, [0, CS_BYTE_PTR, OUT_PREFIX])
        return bytes(u.mem_read(OUT_PREFIX, 4)).decode("ascii")
    finally:
        u.hook_del(h)


def run_e2e_predicate_and_m20_m21_regression_tests(
    m22: bytes,
    m21: bytes,
    m20: bytes,
    snap: dict,
    syms22: dict[str, int],
    syms21: dict[str, int],
    syms20: dict[str, int],
) -> dict:
    rig = Rig(m22, snap)
    _init_data_and_c24_ram(rig)

    # 1. Discover genuine RAM addresses via native 0x100700A0:
    native_0526_ram = _discover_native_prop_ram(rig, 0x0526)
    native_130a_ram = _discover_native_prop_ram(rig, 0x130A)
    native_131b_ram = _discover_native_prop_ram(rig, 0x131B)
    native_0508_ram = _discover_native_prop_ram(rig, 0x0508)
    native_1381_ram = _discover_native_prop_ram(rig, 0x1381)
    native_0440_ram = _discover_native_prop_ram(rig, 0x0440)
    assert native_0526_ram == RAM_PROP_0526 == 0xC24CDEA0
    assert native_130a_ram == RAM_PROP_130A == 0xC24CC74C
    assert native_131b_ram == RAM_PROP_131B == 0xC24CC798
    assert native_0508_ram == RAM_PROP_0508_REAL == 0xC24CDE28
    assert native_1381_ram == RAM_PROP_1381 == 0xC24CC948
    assert native_0440_ram == RAM_PROP_0508 == 0xC24CDDC4

    # 2. Execute real UI submenu handlers 0x104A149C ('Standard sRGB' -> 0) and 0x104A14A6 ('Astro RAW sRGB' -> 1)
    #    forwarding UI SetProp 0x10409240(pid, val) into native SetProperty 0x100703E4(pid, 4, &val):
    ui_set_calls: list[tuple[int, int]] = []

    def _hook_ui_setprop(uc, address, _size, _user):
        if address == 0x10409240:
            pid = uc.reg_read(UC_ARM_REG_R0)
            val = uc.reg_read(UC_ARM_REG_R1)
            ui_set_calls.append((pid, val))
            changed_p = RAM + 0x49300
            # Tail-jump directly into native scalar SetProperty 0x10070366(pid, val, &changed)!
            uc.reg_write(UC_ARM_REG_R2, changed_p)
            uc.reg_write(UC_ARM_REG_PC, 0x10070366 | 1)

    h_ui = rig.uc.hook_add(UC_HOOK_CODE, _hook_ui_setprop, begin=0x10409240, end=0x10409244)
    try:
        for entry_fn, exp_val in ((0x104A149C, 0), (0x104A14A6, 1)):
            ui_set_calls.clear()
            _reset_rig(rig)
            rig.call(entry_fn)
            assert ui_set_calls == [(0x0526, exp_val)], f"Unexpected UI SetProp call: {ui_set_calls}"
            assert rig.get(native_0526_ram) == exp_val, "Native 0x10070366 did not update 0xC24CDEA0!"
    finally:
        rig.uc.hook_del(h_ui)

    # 3. Verify U1/U2/U3 6-bank read/write for PID 0x0526 via native 0x10070428 & 0x10070178:
    #    Bank 0 is live RAM 0xC24CDEA0; Banks 1..3 store U1/U2/U3!
    CHG_BUF = RAM + 0x49310
    OUT_BUF = RAM + 0x49320
    for bank_idx, test_v in ((0, 1), (1, 0), (2, 1), (3, 1)):
        _reset_rig(rig)
        r_bw = rig.call(0x10070428, [bank_idx, 0x0526, test_v, CHG_BUF])
        assert int(r_bw["registers"]["r0"], 16) == 1
        _reset_rig(rig)
        r_br = rig.call(0x10070178, [bank_idx, 0x0526, OUT_BUF])
        assert int(r_br["registers"]["r0"], 16) == 1 and rig.get(OUT_BUF) == test_v
    assert rig.get(native_0526_ram) == 1  # Bank 0 == 0xC24CDEA0

    # 4. Full 30-case predicate matrix on Modified22 (with Focus Shift=100 AND Auto ISO=0):
    rig.put(native_0440_ram, 100)
    rig.put(native_0508_ram, 0)
    fn_addr = syms22["fn_is_astro_r0"]
    out_p = RAM + 0x49000
    pred_cases = 0
    for cs in (0, 1, 2, 0x101, 0xFFFFFFFF):
        for rec in (0, 1, 2, 3, 4, 0xFF):
            rig.put(native_0526_ram, cs)
            rig.put(native_131b_ram, rec)
            _reset_rig(rig)
            rig.call(0x100700A0, [0x0526, out_p])
            assert rig.get(out_p) == cs
            _reset_rig(rig)
            res = rig.call(fn_addr)
            got = int(res["registers"]["r0"], 16)
            exp = 1 if (cs == 1 and rec in (0, 1)) else 0
            assert got == exp, f"fn_is_astro_r0(0x0526={cs:#x}, 0x131B={rec:#x}) -> {got} != {exp}"
            pred_cases += 1

    # 5. Reproduce exact real-camera samples/11.16_modified21 failure on M20 and M21 vs M22 fix:
    rig20 = Rig(m20, snap)
    _init_data_and_c24_ram(rig20)
    rig21 = Rig(m21, snap)
    _init_data_and_c24_ram(rig21)

    for r_any in (rig20, rig21, rig):
        r_any.put(native_0440_ram, 100)  # Focus shift default = 100
        r_any.put(native_0508_ram, 0)    # Manual mode with Auto ISO OFF!
        r_any.put(native_131b_ram, 1)    # Pure RAW ('RAW    ')
        r_any.put(native_0526_ram, 1)    # Selected '直通RAW (sRGB)' in Color space menu!

    _reset_rig(rig20)
    m20_astro = int(rig20.call(syms20["fn_is_astro_r0"])["registers"]["r0"], 16)
    assert m20_astro == 0, "Expected Modified20 failure (0x0440==100 != 1)"

    _reset_rig(rig21)
    m21_astro = int(rig21.call(syms21["fn_is_astro_r0"])["registers"]["r0"], 16)
    m21_130a = _run_color_space_eval_130a(rig21, cs_0526=1, exp_mode=4)
    BULK_DST = RAM + 0x49400
    _reset_rig(rig21)
    rig21.call(0x101703DC, [0xC18B6390, BULK_DST, 0xB1])
    m21_snap_cs = rig21.get(BULK_DST + 0x10C)
    m21_dcf = _run_dcf_prefix_0x10255850(rig21, m21_snap_cs, b"Z61\x00")
    assert m21_astro == 0 and m21_130a == 1 and m21_snap_cs == 1 and m21_dcf == "_Z61", (
        f"Unexpected M21 reproduction: astro={m21_astro}, 130a={m21_130a}, dcf={m21_dcf!r}"
    )

    _reset_rig(rig)
    m22_astro = int(rig.call(syms22["fn_is_astro_r0"])["registers"]["r0"], 16)
    m22_130a = _run_color_space_eval_130a(rig, cs_0526=1, exp_mode=4)
    _reset_rig(rig)
    rig.call(0x101703DC, [0xC18B6390, BULK_DST, 0xB1])
    m22_snap_cs = rig.get(BULK_DST + 0x10C)
    m22_dcf_z61 = _run_dcf_prefix_0x10255850(rig, m22_snap_cs, b"Z61\x00")
    m22_dcf_dsc = _run_dcf_prefix_0x10255850(rig, m22_snap_cs, b"DSC\x00")
    assert m22_astro == 1 and m22_130a == 0 and m22_snap_cs == 0
    assert m22_dcf_z61 == "Z61_" and m22_dcf_dsc == "DSC_"
    assert rig.get(native_0526_ram) == 1  # Menu & U1-U3 setting preserved!

    rig.uc = None
    rig20.uc = None
    rig21.uc = None
    del rig, rig20, rig21
    gc.collect()
    return {
        "e2e_native_predicate_cases": pred_cases,
        "ui_submenu_0x104a149e_0x104a14a8_verified": True,
        "u1_u3_banks_0526_verified": True,
        "m20_and_m21_real_sample_failure_reproduced_and_fixed": {
            "m20_astro": m20_astro,
            "m21_astro": m21_astro,
            "m21_130a": m21_130a,
            "m21_dcf_prefix": m21_dcf,
            "m22_astro": m22_astro,
            "m22_130a": m22_130a,
            "m22_dcf_prefix_z61": m22_dcf_z61,
            "m22_dcf_prefix_dsc": m22_dcf_dsc,
        },
    }


def run_color_space_130a_lock_and_auto_iso_restore_tests(
    m22: bytes, stock: bytes, snap: dict
) -> dict:
    rig = Rig(m22, snap)
    rig_s = Rig(stock, snap)
    _init_data_and_c24_ram(rig)
    _init_data_and_c24_ram(rig_s)

    # 1. Native Effective Color Space evaluator 0x1014BAEA (PID 0x0526 -> PID 0x130A):
    eval_130a_cases = 0
    for cs_0526 in (0, 1):
        for exp_mode in (1, 2, 3, 4, 0x21):
            for flags_r4 in (0, 0x4008, 0x10):
                rig.put(RAM_PROP_0526, cs_0526)
                got_130a = _run_color_space_eval_130a(rig, cs_0526=cs_0526, exp_mode=exp_mode, flags_r4=flags_r4)
                assert got_130a == 0, (
                    f"0x1014BAEA(0x0526={cs_0526}, mode={exp_mode:#x}, flags={flags_r4:#x}) -> {got_130a} != 0"
                )
                assert rig.get(RAM_PROP_0526) == cs_0526, "0x0526 RAM slot was mutated!"
                eval_130a_cases += 1

    # 2. Verify Auto ISO UI submenu grey-out 0x1040AD00 matches Stock 100% (1 when 0x0508==0, 0 when 0x0508==1):
    auto_iso_cases = 0
    for r in (rig, rig_s):
        def _hook_ui_getprop(uc, address, _size, _user):
            if address == 0x10409234:
                pid = uc.reg_read(UC_ARM_REG_R0)
                assert pid == 0x0508
                val = struct.unpack("<I", uc.mem_read(RAM_PROP_0508_REAL, 4))[0]
                uc.reg_write(UC_ARM_REG_R0, val)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

        h = r.uc.hook_add(UC_HOOK_CODE, _hook_ui_getprop, begin=0x10409234, end=0x10409238)
        try:
            for auto_iso, exp_grey in ((0, 1), (1, 0)):
                r.put(RAM_PROP_0508_REAL, auto_iso)
                _reset_rig(r)
                got_grey = int(r.call(0x1040AD00)["registers"]["r0"], 16)
                assert got_grey == exp_grey, f"0x1040AD00(auto_iso={auto_iso}) -> {got_grey} != {exp_grey}"
                auto_iso_cases += 1
        finally:
            r.uc.hook_del(h)

    # 3. Verify Photo-mode Effective Auto ISO evaluator 0x1014F638 matches Stock 100%:
    def _eval_1381(r: Rig, auto_iso: int, exp_mode: int) -> int:
        written_1381: list[tuple[int, int]] = []

        def _hook_set(uc, address, _size, _user):
            if address == 0x1014A6E0:
                pid = struct.unpack("<I", uc.mem_read(uc.reg_read(UC_ARM_REG_R1), 4))[0]
                val = struct.unpack("<I", uc.mem_read(uc.reg_read(UC_ARM_REG_R2), 4))[0]
                written_1381.append((pid, val))
                uc.reg_write(UC_ARM_REG_R0, 1)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

        h2 = r.uc.hook_add(UC_HOOK_CODE, _hook_set, begin=0x1014A6E0, end=0x1014A6E4)
        try:
            IN_S = RAM + 0x48200
            CTX_S = RAM + 0x48300
            r.uc.mem_write(IN_S, b"\x00" * 0x40)
            r.uc.mem_write(CTX_S, b"\x00" * 0x100)
            r.put(IN_S + 0x00, 1)
            r.put(IN_S + 0x04, auto_iso)
            r.put(IN_S + 0x08, 0xFF)  # force write
            r.put(IN_S + 0x14, exp_mode)
            _reset_rig(r)
            r.call(0x1014F638, [0, IN_S, CTX_S])
            assert len(written_1381) == 1 and written_1381[0][0] == 0x1381
            return written_1381[0][1]
        finally:
            r.uc.hook_del(h2)

    for auto_iso in (0, 1):
        for exp_mode in (1, 2, 3, 4, 0x21):
            got_m22 = _eval_1381(rig, auto_iso, exp_mode)
            got_stk = _eval_1381(rig_s, auto_iso, exp_mode)
            exp_1381 = 0 if exp_mode == 0x21 else auto_iso
            assert got_m22 == got_stk == exp_1381, (
                f"Auto ISO 0x1381 mismatch (auto_iso={auto_iso}, mode={exp_mode:#x}): m22={got_m22}, stk={got_stk}"
            )
            auto_iso_cases += 1

    rig.uc = None
    rig_s.uc = None
    del rig, rig_s
    gc.collect()
    return {
        "color_space_130a_srgb_lock_cases": eval_130a_cases,
        "auto_iso_0508_1381_stock_parity_cases": auto_iso_cases,
    }


def run_all_13_hook_site_tests(blobs: dict[str, bytes], snap: dict) -> dict:
    """Execute ALL 13 patched Astro RAW firmware call-sites directly in Unicorn (Stock vs Astro)."""
    m22 = blobs["m22"]
    rig = Rig(m22, snap)
    u = rig.uc
    _init_data_and_c24_ram(rig)

    def _prep(cs: int) -> None:
        _reset_rig(rig)
        rig.put(RAM_PROP_0526, cs)
        rig.put(RAM_PROP_131B, 1)  # Pure RAW (1)
        rig.put(RAM_PROP_0508_REAL, 0)  # Auto ISO OFF to ensure 0x0508 is never consulted!

    cases = 0
    DUMMY = RAM + 0x20000

    # 1. 0x100AE3A4 (BL): Stock -> 0x101BA474, Astro -> 0x101BA4B6
    for cs, tgt in ((0, 0x101BA474), (1, 0x101BA4B6)):
        _prep(cs)
        rig.call(0x100AE3A4, args=[0x1111, 0x2222, 0x3333], until=tgt)
        assert u.reg_read(UC_ARM_REG_PC) == tgt
        assert (u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1), u.reg_read(UC_ARM_REG_R2)) == (0x1111, 0x2222, 0x3333)
        cases += 1

    # 2. 0x100C2654 (BL): Stock -> 0x100C2B22, Astro -> returns r0=0 to 0x100C2658
    _prep(0)
    rig.call(0x100C2654, until=0x100C2B22)
    assert u.reg_read(UC_ARM_REG_PC) == 0x100C2B22
    cases += 1
    _prep(1)
    rig.call(0x100C2654, until=0x100C2658)
    assert u.reg_read(UC_ARM_REG_PC) == 0x100C2658 and u.reg_read(UC_ARM_REG_R0) == 0
    cases += 1

    # 3. 0x100C267C (BL): Stock -> 0x100C2B0A, Astro -> returns r0=2 to 0x100C2680
    _prep(0)
    rig.call(0x100C267C, until=0x100C2B0A)
    assert u.reg_read(UC_ARM_REG_PC) == 0x100C2B0A
    cases += 1
    _prep(1)
    rig.call(0x100C267C, until=0x100C2680)
    assert u.reg_read(UC_ARM_REG_PC) == 0x100C2680 and u.reg_read(UC_ARM_REG_R0) == 2
    cases += 1

    # 4. 0x100C2690 (B.W): Stock ldrb r1,[r0,#0x81a] (=7) vs Astro mov r1,#2 -> 0x100C2694 (preserving NZCV!)
    for cs, exp_r1 in ((0, 7), (1, 2)):
        _prep(cs)
        u.mem_write(DUMMY + 0x81A, bytes([7]))
        u.reg_write(UC_ARM_REG_CPSR, 0xA0000020)
        rig.call(0x100C2690, args=[DUMMY], until=0x100C2694)
        assert u.reg_read(UC_ARM_REG_R1) == exp_r1
        assert (u.reg_read(UC_ARM_REG_CPSR) & 0xF0000000) == 0xA0000000
        cases += 1

    # 5 & 6. 0x100C28B2 & 0x100C28C8 (B.W): vignette neutral byte stores
    for cs, exp_62 in ((0, 0x11), (1, 0x55)):
        _prep(cs)
        rig.call(0x100C28B2, args=[0x11], regs={4: DUMMY, 9: 0x55}, until=0x100C28B6)
        assert u.mem_read(DUMMY + 0x62, 1)[0] == exp_62
        cases += 1
    for cs, exp_63 in ((0, 0x55), (1, 0x11)):
        _prep(cs)
        rig.call(0x100C28C8, args=[0x11], regs={4: DUMMY, 9: 0x55}, until=0x100C28CC)
        assert u.mem_read(DUMMY + 0x63, 1)[0] == exp_63
        cases += 1

    # 7. 0x100C2964 (B.W): Stock ldrb r0,[r0,#0x25f] (=9) vs Astro mov r0,#1 -> 0x100C2968
    for cs, exp_r0 in ((0, 9), (1, 1)):
        _prep(cs)
        u.mem_write(DUMMY + 0x25F, bytes([9]))
        rig.call(0x100C2964, args=[DUMMY], until=0x100C2968)
        assert u.reg_read(UC_ARM_REG_R0) == exp_r0
        cases += 1

    # 8. 0x1011E2DC (B.W): r0!=0 jumps 0x1011E322 vs Astro 0x1011E30C; r0==0 -> 0x1011E2E0
    for cs, exp_tgt in ((0, 0x1011E322), (1, 0x1011E30C)):
        _prep(cs)
        rig.call(0x1011E2DC, args=[1], regs={7: 0xABCD}, until=exp_tgt)
        assert u.reg_read(UC_ARM_REG_PC) == exp_tgt and u.reg_read(UC_ARM_REG_R6) == 0xABCD
        cases += 1
        _prep(cs)
        rig.call(0x1011E2DC, args=[0], regs={7: 0xABCD}, until=0x1011E2E0)
        assert u.reg_read(UC_ARM_REG_PC) == 0x1011E2E0 and u.reg_read(UC_ARM_REG_R6) == 0xABCD
        cases += 1

    # 9. 0x10122CBC (B.W): Stock copies [r1]->[r3] (->0x10122CC0); Astro writes 4x 0x1000 (->0x10122CCC)
    _prep(0)
    rig.put(DUMMY, 0x1357)
    rig.put(DUMMY + 0x100, 0)
    rig.call(0x10122CBC, args=[0, DUMMY, 0, DUMMY + 0x100], until=0x10122CC0)
    assert rig.get(DUMMY + 0x100) == 0x1357
    cases += 1
    _prep(1)
    u.mem_write(DUMMY + 0x100, b"\x00" * 16)
    rig.call(0x10122CBC, args=[0, DUMMY, 0, DUMMY + 0x100], until=0x10122CCC)
    assert struct.unpack("<4I", u.mem_read(DUMMY + 0x100, 16)) == (0x1000, 0x1000, 0x1000, 0x1000)
    cases += 1

    # 10. 0x1017D834 (BL): Stock -> 0x1011D548(r0=1), Astro -> ADDR_M9_SANITIZER
    for cs, exp_tgt in ((0, 0x1011D548), (1, ADDR_M9_SANITIZER)):
        _prep(cs)
        rig.call(0x1017D834, until=exp_tgt)
        assert u.reg_read(UC_ARM_REG_PC) == exp_tgt
        cases += 1

    # 11. 0x10197418 (B.W): r1!=0 -> Stock 0x1019741C vs Astro 0x1019743A
    for cs, exp_tgt in ((0, 0x1019741C), (1, 0x1019743A)):
        _prep(cs)
        rig.put(DUMMY + 0x1C, 0x7788)
        rig.call(0x10197418, args=[DUMMY, 1], until=exp_tgt)
        assert u.reg_read(UC_ARM_REG_PC) == exp_tgt
        if cs == 0:
            assert u.reg_read(UC_ARM_REG_R0) == 0x7788
        cases += 1

    # 12. 0x10197866 (B.W): Stock strb r6,[r1,#0x1d] vs Astro strb r2(=0),[r1,#0x1d] -> 0x10197880
    for cs, exp_1d in ((0, 0x33), (1, 0x00)):
        _prep(cs)
        u.mem_write(DUMMY, b"\xFF" * 0x30)
        rig.call(0x10197866, args=[0, DUMMY, 0], regs={6: 0x33}, until=0x10197880)
        assert u.mem_read(DUMMY + 0x1D, 1)[0] == exp_1d
        cases += 1

    # 13. 0x10197874 (B.W): Stock ldrb r0,[r0,#1]->[r1,#0x1d] vs Astro 0->[r1,#0x1d] -> 0x1019787A
    for cs, exp_1d in ((0, 0x44), (1, 0x00)):
        _prep(cs)
        PTR_HOLDER = DUMMY + 0x200
        SRC_OBJ = DUMMY + 0x300
        rig.put(PTR_HOLDER + 0x10, SRC_OBJ)
        u.mem_write(SRC_OBJ + 1, bytes([0x44]))
        u.mem_write(DUMMY + 0x1D, bytes([0xFF]))
        rig.call(0x10197874, args=[PTR_HOLDER, DUMMY], until=0x1019787A)
        assert u.mem_read(DUMMY + 0x1D, 1)[0] == exp_1d
        cases += 1

    rig.uc = None
    del rig
    gc.collect()
    return {"all_13_hook_sites_dual_branch_cases": cases}


def run_ui_string_tests(blobs: dict[str, bytes], snap: dict) -> dict:
    """Verify GetLanguageString (0x104C0104) across all 36 languages for Modified22 wording + 5 neighbors."""
    rig_s = Rig(blobs["stock"], snap)
    rig_m = Rig(blobs["m22"], snap)

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
        for sid, _, txt_en, txt_cn, txt_tw in UI_OVERRIDES_M21:
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

    assert resolve_ui_str(rig_m, LANG_ZH_CN, 0x03B3)[2] == "天文直通RAW模式"
    assert resolve_ui_str(rig_m, LANG_ZH_CN, 0x03B4)[2] == "标准 (sRGB)"
    assert resolve_ui_str(rig_m, LANG_ZH_CN, 0x03B5)[2] == "直通RAW (sRGB)"

    rig_s.uc = None
    rig_m.uc = None
    del rig_s, rig_m
    gc.collect()
    return {"ui_36_languages_string_checks": ui_checks}


def main() -> None:
    default_manifest = ROOT / "analysis/modified22-preflash-2026-11-17/lab-build/modified22-manifest.json"
    if not default_manifest.is_file():
        default_manifest = ROOT / "patches/z6-c380-modified22-color-space-pid0526-srgb-600s.json"

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--manifest",
        type=Path,
        default=default_manifest,
        help="Path to modified22-manifest.json or tracked Modified22 patch recipe JSON",
    )
    ap.add_argument(
        "--stock",
        type=Path,
        default=None,
        help="Path to official Z_6_0380.bin or decoded eg1620_038000.bi",
    )
    ap.add_argument(
        "--candidate",
        type=Path,
        default=None,
        help="Optional path to built Modified22 .bi/.BIN (otherwise read alongside manifest or built in memory)",
    )
    ap.add_argument(
        "--snap",
        type=Path,
        default=None,
        help="Optional JSON RAM snapshot file (defaults to clean zero-initialized Unicorn RAM + ROM .data)",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output path for probe_modified22_native_result.json",
    )
    args = ap.parse_args()

    manifest_p = args.manifest.resolve()
    assert manifest_p.is_file(), f"Missing manifest: {manifest_p}"
    manifest = json.loads(manifest_p.read_text(encoding="utf-8"))

    stock_bytes = load_stock_eg_module(args.stock, ROOT)
    assert sha(stock_bytes) == STOCK_SHA, "Stock EG SHA-256 mismatch"

    if args.candidate is not None:
        m22_bytes = args.candidate.resolve().read_bytes()
    elif (manifest_p.parent / "modified22-candidate.bi").is_file():
        m22_bytes = (manifest_p.parent / "modified22-candidate.bi").read_bytes()
    else:
        m22_bytes = _synthesize_m22_from_manifest(stock_bytes, manifest)
    assert sha(m22_bytes) == manifest["modified22_sha256"], "Modified22 SHA-256 mismatch"

    m20_bytes, syms20, m21_bytes, syms21 = _synthesize_m20_m21_from_stock(stock_bytes)
    syms22 = {k: int(v, 16) for k, v in manifest["cave_symbols"].items()}

    if args.snap is not None:
        snap_p = args.snap.resolve()
        assert snap_p.is_file(), f"Specified --snap file not found: {snap_p}"
        snap = json.loads(snap_p.read_text(encoding="utf-8"))
        snap_mode = f"file:{snap_p.name}"
    else:
        snap = {}
        snap_mode = "zero_init_plus_rom_data_table"

    blobs = {"m22": m22_bytes, "m20": m22_bytes, "stock": stock_bytes}
    res_pred = run_e2e_predicate_and_m20_m21_regression_tests(
        m22_bytes, m21_bytes, m20_bytes, snap, syms22, syms21, syms20
    )
    res_lock = run_color_space_130a_lock_and_auto_iso_restore_tests(m22_bytes, stock_bytes, snap)
    res_hooks = run_all_13_hook_site_tests(blobs, snap)
    res_ui = run_ui_string_tests(blobs, snap)
    res_iv = run_interval_timer_tests(blobs)
    res_end = run_interval_endtime_tests(blobs)

    if args.output is not None:
        out_json = args.output.resolve()
    elif manifest_p.parent == (ROOT / "patches").resolve():
        out_json = ROOT / "analysis/modified22-preflash-2026-11-17/lab-build/probe_modified22_native_result.json"
    else:
        out_json = manifest_p.parent / "probe_modified22_native_result.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "candidate": manifest["candidate"],
        "design": manifest["design"],
        "modified22_sha256": manifest["modified22_sha256"],
        "ram_snapshot_mode": snap_mode,
        "tests": {
            **res_pred,
            **res_lock,
            **res_hooks,
            **res_ui,
            **res_iv,
            **res_end,
        },
        "status": "PASS",
    }
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()

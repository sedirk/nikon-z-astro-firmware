"""Unicorn native verification probe for Nikon Z6 C3.80 Modified24 Astro Firmware.

SPDX-License-Identifier: GPL-3.0-or-later

Verifies natively in ARM Thumb-2 Unicorn emulation:
  1. Candidate binary identity & negative gates:
     - Computes SHA-256, CRC-16/XMODEM, size, and hook bytes directly from the tested binary;
     - Rejects Stock C3.80 and Modified23 binaries when passed as the Modified24 candidate.
  2. Full Astro Direct RAW / Color Space / Extended Shutter baseline regression on Modified24:
     - All 13 Astro RAW hook sites + Site #14 (`0x100A34D0 -> 0x1002DB5C` format-3 bit-packer);
     - All 437 categorized RAW pipeline cases in Unicorn + 24.5 MP software `packed-14`/`packed-12` round-trip;
     - Effective Color Space (`PID 0x130A = 0` sRGB lock), Stock Auto ISO (`PID 0x0508`) parity,
       post-exposure interval timer (`0x101FF392`), and dynamic End Day/Time (`0x1049C26C`);
     - Native `GetProperty(0x1111)` (`0x100700A0`) RAM discovery (`0xC24DD0EC`) and scalar `SetProperty`
       (`0x10070366`) round-trip via Setup Menu callbacks `0x104CE0A4` (Off=0) & `0x104CE0AE` (On=1).
  3. Strict VGC Channel 1 (`0x20144000` LCD/EVF) vs Channel 0 (`0x20140000` HDMI) isolation:
     - Native `vgc_set_csc` (`0x1024341E`) across `(Ch0, Ch1) x (stage 1,2,4,8) x valid sub-blocks x (PID 0,1)`;
     - Native `vgc_set_grid` (`0x10244086`) across `(Ch0, Ch1) x (PID 0,1)` and varied `(alpha, R, G, B)`.
  4. Stateless single-frame synchronization (`vgc_update_src_buf` @ `0x10243598`):
     - Uninitialized skip (`word0 == 0`), steady-state Off (`0` CSC/grid MMIO writes), `0 -> 1` transition,
       steady-state On (`0` CSC/grid MMIO writes), `1 -> 0` full Stock CSC + neutral gray grid restoration,
       and Ch0 HDMI clean passthrough (`0` CSC/grid MMIO writes).
  5. `DISP` shooting info screen `Light on dark` lock (`0x1040E7D6` & `0x1043A1D6`) across `PID 0/1`.
  6. Chained 36-language `GetLanguageString` (`0x104C0104`):
     - All 4 Astro Red overrides (`0x023F`, `0x0240`, `0x0241`, `0x054C`) across languages `0..35`;
     - All 5 Astro RAW overrides (`0x03B3`, `0x03B4`, `0x03B5`, `0x082B`, `0x082C`) across `0..35`;
     - Untouched neighbor SIDs (`0x023E`, `0x0242`, `0x054B`, `0x054D`, `0x03B2`, `0x03B6`) 100% Stock parity.
"""
from __future__ import annotations

if not __debug__:
    raise RuntimeError(
        "probe_modified24_native.py must not be executed with Python -O/-OO "
        "(imported probe helpers rely on debug checks)."
    )

import argparse
import binascii
import gc
import json
from pathlib import Path
import struct
import sys

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_SP,
)

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from prepare_modified22_lab import STOCK_SHA, collect_m22_edits, sha  # noqa: E402
from prepare_modified24_lab import (  # noqa: E402
    DEFAULT_LAB_OUT,
    M23_SHA,
    M24_SHA,
    collect_m24_edits,
    update_crc,
)
from probe_modified20_native import (  # noqa: E402
    run_interval_endtime_tests,
    run_interval_timer_tests,
)
from probe_modified22_native import (  # noqa: E402
    _init_data_and_c24_ram,
    _reset_rig,
    run_all_13_hook_site_tests,
    run_color_space_130a_lock_and_auto_iso_restore_tests,
)
from probe_modified23_native import (  # noqa: E402
    run_bitpack_and_libraw_roundtrip_tests,
    run_site14_a34d0_hook_tests,
    run_uncompressed_raw_pipeline_matrix,
)
from probe_raw_candidates import BASE, RAM, STACK, Rig  # noqa: E402
from z6_astro_ui_color_space_v2 import (  # noqa: E402
    LANG_ZH_CN,
    LANG_ZH_TW,
    UI_OVERRIDES_M21,
)
from z6_c380_container import STOCK_EG_SIZE, load_stock_eg_module  # noqa: E402
from z6_night_vision_red import (  # noqa: E402
    ADDR_ASTRO_RED_CAVE,
    ADDR_STOCK_POST_CSC_MAT,
    ASTRO_RED_UI_OVERRIDES,
    HOOK_DISP_THEME_A,
    HOOK_DISP_THEME_B,
    HOOK_GET_LANG_EPILOGUE,
    HOOK_VGC_SET_CSC,
    HOOK_VGC_SET_GRID,
    HOOK_VGC_UPDATE_SRC_BUF,
    Q14_LUMA_RED_R00,
    RAM_PROP_1111,
    VGC_CH1_UNIT_OFF,
)

ROOT = THIS_DIR.parents[1]
DEFAULT_PROBE_OUT = (
    ROOT / "analysis/modified24-release-2026-11-21/probe_modified24_native_result.json"
)

STOCK_POST_CSC_WORDS = (0x00004000, 0x00005A00, 0xEA004000, 0x0000D200, 0x71004000, 0x00000000)
LUMA_RED_POST_CSC_WORDS = (Q14_LUMA_RED_R00, 0, 0, 0, 0, 0)


def require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def _apply_edits(stock: bytes, edits: list[dict]) -> bytes:
    buf = bytearray(stock)
    for ed in edits:
        off = int(ed["address"], 16) - BASE
        after = bytes.fromhex(ed["after"])
        buf[off : off + len(after)] = after
    update_crc(buf)
    return bytes(buf)


def validate_m24_binary(blob: bytes, expected_sha: str | None = None) -> dict:
    require(len(blob) == STOCK_EG_SIZE, f"Candidate size mismatch: {len(blob)} != {STOCK_EG_SIZE}")
    require(binascii.crc_hqx(blob, 0) == 0, "Candidate CRC-16/XMODEM remainder is non-zero")
    digest = sha(blob)

    require(
        blob[0x100A34D0 - BASE : 0x100A34D6 - BASE] == bytes.fromhex("8af744bbe9e7"),
        "Candidate missing 0x100A34D0 Uncompressed Astro RAW hook",
    )
    require(
        blob[HOOK_DISP_THEME_A - BASE : HOOK_DISP_THEME_A - BASE + 2] == bytes.fromhex("0024"),
        "Candidate missing Astro Red DISP dark-theme lock A at 0x1040E7D8",
    )
    require(
        blob[HOOK_DISP_THEME_B - BASE : HOOK_DISP_THEME_B - BASE + 2] == bytes.fromhex("18e0"),
        "Candidate missing Astro Red DISP dark-theme lock B at 0x1043A1E0",
    )
    for h_addr, orig_hex, label in (
        (HOOK_VGC_SET_CSC, "0e461d46", "vgc_set_csc"),
        (HOOK_VGC_UPDATE_SRC_BUF, "6a6800218450", "vgc_update_src_buf"),
        (HOOK_VGC_SET_GRID, "c0f81856", "vgc_set_grid"),
        (HOOK_GET_LANG_EPILOGUE, "bde8ff81", "GetLanguageString epilogue"),
    ):
        got = blob[h_addr - BASE : h_addr - BASE + len(orig_hex) // 2]
        require(got != bytes.fromhex(orig_hex), f"Candidate missing Astro Red hook at {label} ({h_addr:#x})")

    require(
        blob[ADDR_ASTRO_RED_CAVE - BASE : ADDR_ASTRO_RED_CAVE - BASE + 4] == bytes.fromhex("0e461d46"),
        "Candidate missing Astro Red cave trampoline header at 0x1002E1B0",
    )
    if expected_sha is not None:
        require(digest == expected_sha, f"Candidate SHA-256 mismatch: {digest} != {expected_sha}")

    return {
        "sha256": digest,
        "crc16_hqx": f"0x{blob[-2:].hex()}",
        "size_bytes": len(blob),
        "crc_remainder": 0,
    }


def _ensure_vgc_mmio_mapped(rig: Rig) -> None:
    try:
        rig.uc.mem_map(0x20140000, 0x10000)
    except Exception:
        pass


def run_pid1111_property_and_menu_cb_tests(m24_bytes: bytes, snap: dict) -> dict:
    """Verify native GetProperty(0x1111) RAM slot == 0xC24DD0EC and Setup Menu Off/On callbacks."""
    rig = Rig(m24_bytes, snap)
    u = rig.uc
    try:
        _init_data_and_c24_ram(rig)

        reads: list[int] = []

        def _on_read(_uc, _access, addr, _size, _val, _user):
            if 0xC2400000 <= addr < 0xC2500000:
                reads.append(addr)

        h_rd = u.hook_add(UC_HOOK_MEM_READ, _on_read)
        try:
            out_p = RAM + 0x49000
            _reset_rig(rig)
            res = rig.call(0x100700A0, [0x1111, out_p])
            require(int(res["registers"]["r0"], 16) == 1, "GetProperty(0x1111) failed")
            require(
                reads == [RAM_PROP_1111],
                f"Expected GetProperty(0x1111) to read [0x{RAM_PROP_1111:08x}], got {[hex(x) for x in reads]}",
            )
        finally:
            u.hook_del(h_rd)

        CHANGED_BOX = RAM + 0x49080
        ui_set_calls: list[tuple[int, int]] = []

        def _hook_ui_setprop(uc, address, _size, _user):
            if address == 0x10409240:
                pid = uc.reg_read(UC_ARM_REG_R0)
                val = uc.reg_read(UC_ARM_REG_R1)
                ui_set_calls.append((pid, val))
                uc.reg_write(UC_ARM_REG_R2, CHANGED_BOX)
                uc.reg_write(UC_ARM_REG_PC, 0x10070366 | 1)

        h_sp = u.hook_add(UC_HOOK_CODE, _hook_ui_setprop, begin=0x10409240, end=0x10409244)
        try:
            ui_set_calls.clear()
            rig.put(RAM_PROP_1111, 0)
            _reset_rig(rig)
            rig.call(0x104CE0AE, [])
            require(ui_set_calls == [(0x1111, 1)], f"Unexpected UI SetProp call at 0x104CE0AE: {ui_set_calls}")
            require(rig.get(RAM_PROP_1111) == 1, "Menu callback 0x104CE0AE failed to set PID 0x1111 = 1")

            ui_set_calls.clear()
            _reset_rig(rig)
            rig.call(0x104CE0A4, [])
            require(ui_set_calls == [(0x1111, 0)], f"Unexpected UI SetProp call at 0x104CE0A4: {ui_set_calls}")
            require(rig.get(RAM_PROP_1111) == 0, "Menu callback 0x104CE0A4 failed to set PID 0x1111 = 0")
        finally:
            u.hook_del(h_sp)

        return {
            "discovered_pid_0x1111_ram": f"0x{RAM_PROP_1111:08x}",
            "menu_cb_set_on_0x104ce0ae_ok": True,
            "menu_cb_set_off_0x104ce0a4_ok": True,
        }
    finally:
        rig.uc = None
        del rig
        gc.collect()


def run_vgc_csc_and_grid_isolation_tests(stock_bytes: bytes, m24_bytes: bytes, snap: dict) -> dict:
    """Verify VGC Ch1 vs Ch0 HDMI isolation across vgc_set_csc and vgc_set_grid."""
    rig_s = Rig(stock_bytes, snap)
    rig_p = Rig(m24_bytes, snap)
    try:
        for r in (rig_s, rig_p):
            _init_data_and_c24_ram(r)
            _ensure_vgc_mmio_mapped(r)

        HDL_CH0 = RAM + 0x24000
        HDL_CH1 = RAM + 0x24040
        GRID_CFG = RAM + 0x24100
        MAT_SCRATCH = RAM + 0x24200

        for r in (rig_s, rig_p):
            r.put(HDL_CH0 + 0, 0x143)
            r.put(HDL_CH0 + 4, 0x0000)
            r.put(HDL_CH1 + 0, 0x143)
            r.put(HDL_CH1 + 4, VGC_CH1_UNIT_OFF)
            r.uc.mem_write(MAT_SCRATCH, struct.pack("<9h", -16, -128, -128, 0, 0, 0, 0, 0, 0))

        csc_cases = 0
        test_calls = (
            (0x0000, HDL_CH0, 8, 0, 0x1062DC28),
            (0x0000, HDL_CH0, 8, 1, ADDR_STOCK_POST_CSC_MAT),
            (0x0000, HDL_CH0, 1, 1, 0x1062DC28),
            (0x0000, HDL_CH0, 1, 2, MAT_SCRATCH),
            (0x0000, HDL_CH0, 2, 1, 0x1062DD38),
            (0x4000, HDL_CH1, 1, 1, 0x1062DC28),
            (0x4000, HDL_CH1, 1, 2, MAT_SCRATCH),
            (0x4000, HDL_CH1, 2, 1, 0x1062DD38),
            (0x4000, HDL_CH1, 4, 1, 0x1062DD38),
            (0x4000, HDL_CH1, 8, 0, 0x1062DC28),
            (0x4000, HDL_CH1, 8, 0, 0x1062DC3A),
            (0x4000, HDL_CH1, 8, 1, ADDR_STOCK_POST_CSC_MAT),
            (0x4000, HDL_CH1, 8, 1, 0x1062DC5E),
        )
        for pid_val in (0, 1):
            for unit_off, hdl, stage, sub, mat_ptr in test_calls:
                for r in (rig_s, rig_p):
                    r.uc.mem_write(0x20140000, b"\x00" * 0x8000)
                    r.put(RAM_PROP_1111, pid_val)
                    _reset_rig(r)
                    ret = r.call(0x1024341E, [hdl, stage, sub, mat_ptr])
                    require(int(ret["registers"]["r0"], 16) == 0, "vgc_set_csc non-zero return")

                mmio_s = bytes(rig_s.uc.mem_read(0x20140000, 0x8000))
                mmio_p = bytes(rig_p.uc.mem_read(0x20140000, 0x8000))

                if pid_val == 1 and unit_off == 0x4000 and stage == 8 and sub == 1:
                    require(mmio_p[:0x4000] == mmio_s[:0x4000], "Ch0 HDMI MMIO touched during Ch1 CSC!")
                    got_words = struct.unpack_from("<6I", mmio_p, 0x54F0)
                    require(
                        got_words == LUMA_RED_POST_CSC_WORDS,
                        f"Expected Ch1 LumaRed words {LUMA_RED_POST_CSC_WORDS}, got {got_words}",
                    )
                    patched_expect = bytearray(mmio_s)
                    struct.pack_into("<6I", patched_expect, 0x54F0, *LUMA_RED_POST_CSC_WORDS)
                    require(bytes(patched_expect) == mmio_p, "Unexpected extra MMIO diff in vgc_set_csc")
                else:
                    require(
                        mmio_p == mmio_s,
                        f"Expected 100% Stock MMIO parity on pid={pid_val}, unit={unit_off:#x}, "
                        f"stage={stage}, sub={sub}",
                    )
                csc_cases += 1

        grid_cases = 0
        color_samples = (
            (0x80, 0x80, 0x80, 2),
            (0xC0, 0xC0, 0xC0, 3),
            (0xFF, 0x40, 0x20, 1),
        )
        for pid_val in (0, 1):
            for unit_off, hdl, reg_addr in (
                (0x0000, HDL_CH0, 0x20141618),
                (0x4000, HDL_CH1, 0x20145618),
            ):
                for r_c, g_c, b_c, alpha in color_samples:
                    rig_p.uc.mem_write(0x20140000, b"\x00" * 0x8000)
                    rig_p.put(0x20141304 + unit_off, (480 << 16) | 640)
                    rig_p.put(RAM_PROP_1111, pid_val)
                    cfg = struct.pack(
                        "<12H4B",
                        160,
                        120,
                        160,
                        2,
                        320,
                        0,
                        160,
                        120,
                        120,
                        2,
                        240,
                        0,
                        r_c,
                        g_c,
                        b_c,
                        alpha,
                    )
                    rig_p.uc.mem_write(GRID_CFG, cfg)
                    _reset_rig(rig_p)
                    ret = rig_p.call(0x10244086, [hdl, GRID_CFG])
                    require(int(ret["registers"]["r0"], 16) == 0, "vgc_set_grid returned error")
                    got_reg = rig_p.get(reg_addr)
                    if unit_off == 0x4000 and pid_val == 1:
                        exp_reg = ((alpha & 3) << 24) | r_c
                    else:
                        exp_reg = ((alpha & 3) << 24) | (b_c << 16) | (g_c << 8) | r_c
                    require(
                        got_reg == exp_reg,
                        f"Grid color mismatch on unit={unit_off:#x}, pid={pid_val}: "
                        f"got {got_reg:#010x}, expected {exp_reg:#010x}",
                    )
                    grid_cases += 1

        return {
            "vgc_set_csc_matrix_cases": csc_cases,
            "vgc_set_grid_color_cases": grid_cases,
            "ch0_hdmi_zero_contamination_verified": True,
        }
    finally:
        rig_s.uc = None
        rig_p.uc = None
        del rig_s, rig_p
        gc.collect()


def run_stateless_frame_sync_tests(m24_bytes: bytes, snap: dict) -> dict:
    """Verify vgc_update_src_buf (0x10243598) single-frame 0<->1 transitions and zero steady-state writes."""
    rig = Rig(m24_bytes, snap)
    u = rig.uc
    try:
        _init_data_and_c24_ram(rig)
        _ensure_vgc_mmio_mapped(rig)

        HDL_CH0 = RAM + 0x25000
        HDL_CH1 = RAM + 0x25040
        rig.put(HDL_CH0 + 0, 0x143)
        rig.put(HDL_CH0 + 4, 0x0000)
        rig.put(HDL_CH1 + 0, 0x143)
        rig.put(HDL_CH1 + 4, VGC_CH1_UNIT_OFF)

        csc_grid_writes: list[int] = []

        def _on_mmio_write(_uc, _access, addr, _size, _val, _user):
            if (0x201414F0 <= addr <= 0x20141620) or (0x201454F0 <= addr <= 0x20145620):
                csc_grid_writes.append(addr)

        h_wr = u.hook_add(UC_HOOK_MEM_WRITE, _on_mmio_write)
        try:
            u.mem_write(0x20140000, b"\x00" * 0x8000)

            def _call_sync(hdl: int, buf_addr: int) -> None:
                _reset_rig(rig)
                res = rig.call(
                    0x10243598,
                    [hdl, 0, 0, buf_addr],
                    regs={4: 0x44445555, 5: 0x55556666, 6: 0x66667777},
                )
                require(int(res["registers"]["r0"], 16) == 0, "vgc_update_src_buf non-zero return")
                require(u.reg_read(UC_ARM_REG_SP) == STACK + 0xF000, "SP corrupted in vgc_update_src_buf")
                require(
                    u.reg_read(UC_ARM_REG_R4) == 0x44445555
                    and u.reg_read(UC_ARM_REG_R5) == 0x55556666
                    and u.reg_read(UC_ARM_REG_R6) == 0x66667777,
                    "Callee-saved r4..r6 corrupted in vgc_update_src_buf",
                )

            rig.put(RAM_PROP_1111, 1)
            csc_grid_writes.clear()
            _call_sync(HDL_CH1, 0xC4100000)
            require(not csc_grid_writes, f"Writes before VGC init: {csc_grid_writes}")

            u.mem_write(0x201454F0, struct.pack("<6I", *STOCK_POST_CSC_WORDS))
            rig.put(0x20145618, 0x02808080)

            rig.put(RAM_PROP_1111, 0)
            csc_grid_writes.clear()
            _call_sync(HDL_CH1, 0xC4110000)
            require(not csc_grid_writes, f"Steady-state Off wrote MMIO: {csc_grid_writes}")

            rig.put(RAM_PROP_1111, 1)
            csc_grid_writes.clear()
            _call_sync(HDL_CH1, 0xC4120000)
            got_on_csc = struct.unpack_from("<6I", bytes(u.mem_read(0x201454F0, 24)), 0)
            require(got_on_csc == LUMA_RED_POST_CSC_WORDS, f"0->1 CSC sync failed: {got_on_csc}")
            require(rig.get(0x20145618) == 0x02000080, f"0->1 grid sync failed: {rig.get(0x20145618):#x}")
            require(len(csc_grid_writes) == 7, f"Expected 6 CSC + 1 grid writes on 0->1, got {len(csc_grid_writes)}")

            csc_grid_writes.clear()
            _call_sync(HDL_CH1, 0xC4130000)
            require(not csc_grid_writes, f"Steady-state On wrote MMIO: {csc_grid_writes}")

            u.mem_write(0x201414F0, struct.pack("<6I", *STOCK_POST_CSC_WORDS))
            rig.put(0x20141618, 0x02808080)
            csc_grid_writes.clear()
            _call_sync(HDL_CH0, 0xC4200000)
            require(not csc_grid_writes, f"Ch0 HDMI frame flip touched CSC/grid: {csc_grid_writes}")

            rig.put(RAM_PROP_1111, 0)
            csc_grid_writes.clear()
            _call_sync(HDL_CH1, 0xC4140000)
            got_off_csc = struct.unpack_from("<6I", bytes(u.mem_read(0x201454F0, 24)), 0)
            require(got_off_csc == STOCK_POST_CSC_WORDS, f"1->0 CSC restore failed: {got_off_csc}")
            require(
                rig.get(0x20145618) == 0x02808080,
                f"1->0 neutral gray grid restore failed: {rig.get(0x20145618):#x}",
            )
            require(len(csc_grid_writes) == 7, f"Expected 6 CSC + 1 grid writes on 1->0, got {len(csc_grid_writes)}")
        finally:
            u.hook_del(h_wr)

        return {
            "uninit_skip_verified": True,
            "steady_state_off_zero_mmio_writes": True,
            "transition_0_to_1_single_frame_verified": True,
            "steady_state_on_zero_mmio_writes": True,
            "ch0_hdmi_flip_zero_csc_grid_writes": True,
            "transition_1_to_0_stock_restore_verified": True,
        }
    finally:
        rig.uc = None
        del rig
        gc.collect()


def run_disp_dark_theme_lock_tests(stock_bytes: bytes, m24_bytes: bytes, snap: dict) -> dict:
    """Verify both DISP info screen helpers (0x1040E7D6 & 0x1043A1D6) lock to Light-on-dark."""
    rig_s = Rig(stock_bytes, snap)
    rig_p = Rig(m24_bytes, snap)
    try:
        for r in (rig_s, rig_p):
            _init_data_and_c24_ram(r)

        mode_box = [4]

        def _attach_ui_stubs(rig: Rig) -> list[int]:
            u = rig.uc

            def _on_code(uc, address, _size, _user):
                if address == 0x10409234:
                    pid = uc.reg_read(UC_ARM_REG_R0)
                    require(pid == 0x1111, f"Unexpected PID {pid:#x} in DISP theme helper")
                    val = struct.unpack("<I", uc.mem_read(RAM_PROP_1111, 4))[0]
                    uc.reg_write(UC_ARM_REG_R0, val)
                    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
                elif address == 0x1030F662:
                    uc.reg_write(UC_ARM_REG_R0, mode_box[0])
                    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
                elif address == 0x1037D114:
                    uc.reg_write(UC_ARM_REG_R0, 0)
                    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
                elif address in (0x1037D90E, 0x1037D93E):
                    uc.reg_write(UC_ARM_REG_R0, 1)
                    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

            h1 = u.hook_add(UC_HOOK_CODE, _on_code)
            return [h1]

        hs_s = _attach_ui_stubs(rig_s)
        hs_p = _attach_ui_stubs(rig_p)
        try:
            for m_val in (4, 0x0F):
                mode_box[0] = m_val
                rig_s.put(RAM_PROP_1111, 1)
                _reset_rig(rig_s)
                exp_dark = int(rig_s.call(0x1040E7D6, [])["registers"]["r0"], 16)

                for pid_val in (0, 1):
                    rig_p.put(RAM_PROP_1111, pid_val)
                    _reset_rig(rig_p)
                    got_p = int(rig_p.call(0x1040E7D6, [])["registers"]["r0"], 16)
                    require(
                        got_p == exp_dark,
                        f"DISP helper A (mode={m_val}, pid={pid_val}) returned {got_p}, expected {exp_dark}",
                    )

            STATE_BUF = RAM + 0x49300
            for pid_val in (0, 1):
                rig_p.uc.mem_write(STATE_BUF, b"\xFF\xFF\xFF\xFF")
                rig_p.put(RAM_PROP_1111, pid_val)
                _reset_rig(rig_p)
                rig_p.uc.reg_write(UC_ARM_REG_R5, STATE_BUF)
                rig_p.uc.reg_write(UC_ARM_REG_R6, 0x11)
                rig_p.uc.reg_write(UC_ARM_REG_R7, 0x22)
                rig_p.uc.emu_start(0x1043A1D6 | 1, 0x1043A1F6)
                theme_byte = rig_p.uc.mem_read(STATE_BUF, 1)[0]
                require(
                    theme_byte == 4,
                    f"DISP helper B (pid={pid_val}) wrote theme {theme_byte}, expected 4 (Light-on-dark)",
                )
        finally:
            for h in hs_s:
                rig_s.uc.hook_del(h)
            for h in hs_p:
                rig_p.uc.hook_del(h)

        return {
            "helper_0x1040e7d6_locked_light_on_dark": True,
            "helper_0x1043a1d6_locked_theme4_light_on_dark": True,
        }
    finally:
        rig_s.uc = None
        rig_p.uc = None
        del rig_s, rig_p
        gc.collect()


def run_chained_36_language_ui_tests(stock_bytes: bytes, m24_bytes: bytes, snap: dict) -> dict:
    """Verify chained GetLanguageString (0x104C0104) across 36 languages for Astro RAW + Astro Red + Stock SIDs."""
    rig_s = Rig(stock_bytes, snap)
    rig_p = Rig(m24_bytes, snap)
    try:
        ui_ptr_resolver = struct.unpack_from("<I", stock_bytes, 0x104C0224 - BASE)[0] - 0x1C
        ui_ptr_limit = struct.unpack_from("<I", stock_bytes, 0x104C0220 - BASE)[0]
        for r in (rig_s, rig_p):
            r.put(ui_ptr_resolver + 0x0, 0x112C2A98)
            r.put(ui_ptr_resolver + 0x8, 0x112C2A08)
            r.put(ui_ptr_limit + 0x14, 2291)

        OUT_PTR = RAM + 0x4A000
        OUT_LEN = RAM + 0x4A004

        def _resolve(rig: Rig, lang: int, sid: int) -> tuple[int, int, str]:
            rig.put(OUT_PTR, 0)
            rig.put(OUT_LEN, 0)
            _reset_rig(rig)
            rig.call(0x104C0104, [lang, sid, OUT_PTR, OUT_LEN])
            s_ptr = rig.get(OUT_PTR)
            s_len = rig.get(OUT_LEN)
            raw_b = bytes(rig.uc.mem_read(s_ptr, s_len))
            return s_ptr, s_len, raw_b.decode("utf-16le")

        astro_red_checks = 0
        astro_raw_checks = 0
        neighbor_checks = 0
        neighbors = (0x0000, 0x023E, 0x0242, 0x054B, 0x054D, 0x03B2, 0x03B6, 0x082A, 0x082D)

        for lang in range(36):
            for sid, _, txt_en, txt_cn, txt_tw in ASTRO_RED_UI_OVERRIDES:
                _, s_len, s_txt = _resolve(rig_p, lang, sid)
                exp = txt_cn if lang == LANG_ZH_CN else (txt_tw if lang == LANG_ZH_TW else txt_en)
                require(
                    s_txt == exp and s_len == len(exp.encode("utf-16le")),
                    f"Astro Red UI mismatch lang={lang} SID={sid:#06x}: got {s_txt!r}",
                )
                astro_red_checks += 1

            for sid, _, txt_en, txt_cn, txt_tw in UI_OVERRIDES_M21:
                _, s_len, s_txt = _resolve(rig_p, lang, sid)
                exp = txt_cn if lang == LANG_ZH_CN else (txt_tw if lang == LANG_ZH_TW else txt_en)
                require(
                    s_txt == exp and s_len == len(exp.encode("utf-16le")),
                    f"Astro RAW UI regression lang={lang} SID={sid:#06x}: got {s_txt!r}",
                )
                astro_raw_checks += 1

            for n_sid in neighbors:
                require(
                    _resolve(rig_p, lang, n_sid) == _resolve(rig_s, lang, n_sid),
                    f"Neighbor SID {n_sid:#06x} altered in lang={lang}",
                )
                neighbor_checks += 1

        return {
            "astro_red_override_checks": astro_red_checks,
            "astro_raw_override_checks": astro_raw_checks,
            "untouched_neighbor_checks": neighbor_checks,
            "total_string_checks": astro_red_checks + astro_raw_checks + neighbor_checks,
            "zh_cn_sample": {
                "0x023f": _resolve(rig_p, LANG_ZH_CN, 0x023F)[2],
                "0x0240": _resolve(rig_p, LANG_ZH_CN, 0x0240)[2],
                "0x0241": _resolve(rig_p, LANG_ZH_CN, 0x0241)[2],
                "0x03b3": _resolve(rig_p, LANG_ZH_CN, 0x03B3)[2],
            },
        }
    finally:
        rig_s.uc = None
        rig_p.uc = None
        del rig_s, rig_p
        gc.collect()


def main() -> None:
    if not __debug__:
        raise RuntimeError("probe_modified24_native.py must not be executed with Python -O/-OO.")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stock", type=Path, default=None)
    ap.add_argument(
        "--candidate",
        type=Path,
        default=None,
        help="Optional explicit path to built Modified24 .bi/.BIN (must exist if provided)",
    )
    ap.add_argument("--output", type=Path, default=DEFAULT_PROBE_OUT)
    args = ap.parse_args()

    stock_bytes = load_stock_eg_module(args.stock, ROOT)
    require(sha(stock_bytes) == STOCK_SHA, "Stock EG SHA-256 mismatch")

    m22_edits, _ = collect_m22_edits(stock_bytes)
    m22_bytes = _apply_edits(stock_bytes, m22_edits)

    m23_bytes, _, combined_edits, _, _ = collect_m24_edits(stock_bytes)
    expected_m24_bytes = _apply_edits(stock_bytes, combined_edits)
    expected_m24_sha = sha(expected_m24_bytes)
    require(expected_m24_sha == M24_SHA, f"Modified24 synthesis SHA mismatch: {expected_m24_sha}")

    default_lab_cand = DEFAULT_LAB_OUT / "modified24-candidate.bi"
    default_rel_cand = ROOT / "outputs/Nikon-Z6-C380-Modified24-Astro-Firmware/01_MODIFIED24/EG162080.BIN"
    if args.candidate is not None:
        cand_path = args.candidate.resolve()
        if not cand_path.is_file():
            raise FileNotFoundError(f"Explicit --candidate file does not exist: {cand_path.name}")
        m24_bytes = cand_path.read_bytes()
        candidate_source = "explicit_candidate_file"
    elif default_lab_cand.is_file():
        m24_bytes = default_lab_cand.read_bytes()
        candidate_source = "lab_build_candidate_bi"
    elif default_rel_cand.is_file():
        m24_bytes = default_rel_cand.read_bytes()
        candidate_source = "release_kit_eg162080_bin"
    else:
        m24_bytes = expected_m24_bytes
        candidate_source = "synthesized_from_stock_and_emitters"
    measured = validate_m24_binary(m24_bytes, expected_m24_sha)

    neg_m23_rejected = False
    try:
        validate_m24_binary(m23_bytes)
    except ValueError:
        neg_m23_rejected = True
    require(neg_m23_rejected, "Modified23 binary was not rejected by Modified24 validator")

    neg_stock_rejected = False
    try:
        validate_m24_binary(stock_bytes)
    except ValueError:
        neg_stock_rejected = True
    require(neg_stock_rejected, "Stock binary was not rejected by Modified24 validator")

    snap: dict = {}
    blobs_for_m22 = {"m22": m24_bytes, "m20": m24_bytes, "stock": stock_bytes}

    m23_cs_iso = run_color_space_130a_lock_and_auto_iso_restore_tests(m24_bytes, stock_bytes, snap)
    m23_hooks13 = run_all_13_hook_site_tests(blobs_for_m22, snap)
    m23_hook14 = run_site14_a34d0_hook_tests(m24_bytes, snap)
    m23_matrix = run_uncompressed_raw_pipeline_matrix(m24_bytes, m22_bytes, stock_bytes)
    m23_pack = run_bitpack_and_libraw_roundtrip_tests()
    m23_iv = run_interval_timer_tests(blobs_for_m22)
    m23_end = run_interval_endtime_tests(blobs_for_m22)

    pid1111_res = run_pid1111_property_and_menu_cb_tests(m24_bytes, snap)
    vgc_iso_res = run_vgc_csc_and_grid_isolation_tests(stock_bytes, m24_bytes, snap)
    sync_res = run_stateless_frame_sync_tests(m24_bytes, snap)
    disp_res = run_disp_dark_theme_lock_tests(stock_bytes, m24_bytes, snap)
    ui_res = run_chained_36_language_ui_tests(stock_bytes, m24_bytes, snap)

    report = {
        "status": "PASS",
        "candidate": "modified24-astro-raw-red-display-pid0526-pid1111-srgb-600s-v1",
        "candidate_source": candidate_source,
        "measured_candidate_sha256": measured["sha256"],
        "measured_candidate_crc16_hqx": measured["crc16_hqx"],
        "measured_candidate_size_bytes": measured["size_bytes"],
        "base_modified23_sha256": M23_SHA,
        "negative_gates": {
            "modified23_rejected": neg_m23_rejected,
            "stock_rejected": neg_stock_rejected,
        },
        "modified23_baseline_regression": {
            **m23_cs_iso,
            **m23_hooks13,
            **m23_hook14,
            **m23_matrix,
            **m23_pack,
            **m23_iv,
            **m23_end,
        },
        "astro_red_display_tests": {
            "pid_0x1111_and_menu_callbacks": pid1111_res,
            "vgc_ch1_vs_ch0_hdmi_isolation": vgc_iso_res,
            "stateless_single_frame_sync": sync_res,
            "disp_shooting_info_dark_lock": disp_res,
            "chained_36_language_ui_strings": ui_res,
        },
    }

    out_p = args.output.resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_bytes((json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    print(
        f"MODIFIED24 NATIVE PROBE PASS | SHA256={measured['sha256']} | CRC={measured['crc16_hqx']} | "
        f"RAW_Matrix={m23_matrix['raw_pipeline_matrix_cases']} | "
        f"VGC_CSC={vgc_iso_res['vgc_set_csc_matrix_cases']} | "
        f"Grid={vgc_iso_res['vgc_set_grid_color_cases']} | "
        f"UI_Strings={ui_res['total_string_checks']}"
    )


if __name__ == "__main__":
    main()

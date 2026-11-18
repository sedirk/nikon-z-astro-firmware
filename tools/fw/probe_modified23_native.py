"""Offline Unicorn native end-to-end & 437-case RAW pipeline verification for Nikon Z6 C3.80 Modified23.

SPDX-License-Identifier: GPL-3.0-or-later

Verifies on a clean clone supplied only with official `Z_6_0380.bin` (and optionally
cross-checks real `Z61_5105.NEF` through `LibRaw / rawpy` when `samples/` is present):
  1. Candidate binary identity & negative Modified22 rejection gate:
     - Computes SHA-256, CRC-16/XMODEM, size, and hook bytes directly from the tested binary;
     - Explicitly rejects Python `-O` / `-OO` optimization mode and verifies that passing
       `Modified22` as candidate fails both binary validation and Hook #14 Unicorn execution.
  2. All Modified22 invariants preserved intact on Modified23:
     - UI Color space submenu actions (`0x104A149C` / `0x104A14A6`) -> native `SetProperty` / `GetProperty`
       RAM slot discovery (`PID 0x0526 = 0xC24CDEA0`, `PID 0x130A = 0xC24CC74C`, `PID 0x131B = 0xC24CC798`,
       `PID 0x0508 = 0xC24CDE28`, `PID 0x1381 = 0xC24CC948`, `PID 0x0440 = 0xC24CDDC4`) + U1-U3 banks;
     - Exact reproduction of real-camera M20/M21 failure vs Modified23 `Z61_` / `DSC_` sRGB DCF fix;
     - 30-case Effective Color Space `0x1014BAEA` sRGB lock + 14-case Auto ISO (`0x1040AD00` / `0x1014F638`)
       100% Stock parity;
     - 36-language `GetLanguageString` (`0x104C0104`) UI overrides + 5 untouched neighbors (360 checks);
     - Post-exposure Interval Timer sequences & 37-case native End day/time (`0x1049C19A`) matrix.
  3. All 14 patched Astro RAW firmware hook sites (the 13 Modified22 sites + site #14 `0x100A34D0 ->
     tramp_a34d0 @ 0x1002DB5C`), including dual-branch Stock vs Astro 14-bit (`out_pack=1`) & 12-bit
     (`out_pack=2`) dispatch and full `r0..r12, sp, lr, NZCV` preservation.
  4. 437-case Unicorn RAW pipeline matrix modeling C3.80 frontend capture (`0x10124196` -> `0x10123E70`),
     post-capture flag handoff (`0x10142D8E` / `0x10142E7A` -> `0x10124224`), release selection
     (`0x100AE33E` / `0x100AE41E`), `JPEG-only` encoder skip (`0x101BA474` / `0x100AF65A`, 108 cases),
     compressed encoder queue descriptor setup (`0x100A323E -> 0x101CAAD8`, 216 cases), uncompressed
     encoder + `StripByteCounts` + `CODEC_MMIO` programmer (`0x100A3480` -> `0x100A359C` -> `0x101CA666` ->
     `0x10108F8A`, 113 cases including electronic shutter and Lossless->Uncompressed fallback), and
     216-case non-Astro 100% field-for-field Stock C3.80 parity.
  5. Three-tier bit-packing & round-trip evidence:
     - `synthetic_pack`: full-frame `6064 x 4040` (`24,498,560` pixels) 14-bit (`42,920,960` B) and
       12-bit (`36,780,160` B) lossless software pack/unpack (`0` ADU error);
     - `real_nef_libraw`: when `samples/11.17_modified22/Z61_5105.NEF` is present, software-repacks clean
       sensor rows `0..3632` & `4001..4039` (`3,672` rows) + substituted rows `3633..4000` (`368` rows) into
       `42,920,960` B, verifies all 3 embedded preview JPEG SHA-256 digests remain intact, and verifies
       `LibRaw` (`rawpy`) decodes all `24,498,560` pixels with `0` ADU difference (`SKIPPED` without `samples/`);
     - `hardware_pixels_verified`: `False` (physical EXPEED 6 silicon capture awaits camera flash).
"""
from __future__ import annotations

if not __debug__:
    raise RuntimeError(
        "probe_modified23_native.py must not be executed with Python -O/-OO "
        "(imported probe helpers rely on debug assertions)."
    )

import argparse
import binascii
import gc
import json
from pathlib import Path
import struct
import sys
import tempfile

import numpy as np
import unicorn as un
from unicorn.arm_const import (
    UC_ARM_REG_CPSR,
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
    UC_ARM_REG_R9,
    UC_ARM_REG_R10,
    UC_ARM_REG_R11,
    UC_ARM_REG_R12,
    UC_ARM_REG_SP,
)

THIS_DIR = Path(__file__).resolve().parent
ROOT = THIS_DIR.parents[1]
EVIDENCE_LIB_DIR = ROOT / "tools/evidence"
for _p in (THIS_DIR, EVIDENCE_LIB_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import nef_evidence_lib as nel  # noqa: E402
from prepare_modified22_lab import (  # noqa: E402
    STOCK_SHA,
    collect_m22_edits,
    sha,
    update_crc,
)
from probe_modified20_native import (  # noqa: E402
    run_interval_endtime_tests,
    run_interval_timer_tests,
)
from probe_modified22_native import (  # noqa: E402
    _init_data_and_c24_ram,
    _reset_rig,
    _synthesize_m20_m21_from_stock,
    run_all_13_hook_site_tests,
    run_color_space_130a_lock_and_auto_iso_restore_tests,
    run_e2e_predicate_and_m20_m21_regression_tests,
    run_ui_string_tests,
)
from probe_raw_candidates import (  # noqa: E402
    BASE,
    CAL,
    DRIVER,
    ENCODED,
    FRAME,
    INPUT,
    OUTPUT,
    OWNER,
    RAM,
    REQ,
    STAGE,
    Rig,
)
from z6_astro_ui_color_space_v2 import (  # noqa: E402
    RAM_PROP_0508_REAL,
    RAM_PROP_0526,
    RAM_PROP_131B,
)
from z6_c380_container import STOCK_EG_SIZE, load_stock_eg_module  # noqa: E402

MODIFIED22_SHA = "c6a23ea40f03d83c6c721e96e8b5af8a8422a7b4ed81d39222392b7635681771"
TRAMP_A34D0_HEX = (
    "07b5eff30082fff7cdfe012807d082f3008cbde80740a270e27075f098bc"
    "0020a0706978022900d00121e17082f3008cbde8074075f08bbc"
)
GLOBAL, CONTEXT, CODEC_MMIO = 0xC23234C8, 0xC180B704, 0x20204000
ALLOC, MAPPED, CODEC_CTX = RAM + 0x45000, RAM + 0x46000, RAM + 0x47000
FIRST_PREVIEW_REL_OFFSET = 44072448


def require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def validate_m23_candidate_binary(blob: bytes, expected_sha: str) -> dict:
    require(len(blob) == STOCK_EG_SIZE, f"Candidate size mismatch: {len(blob)} != {STOCK_EG_SIZE}")
    require(binascii.crc_hqx(blob, 0) == 0, "Candidate CRC-16/XMODEM remainder is non-zero")
    digest = sha(blob)
    require(
        blob[0x1002D900 - BASE : 0x1002D908 - BASE] == bytes.fromhex("4df6a061ccf24c21"),
        "Candidate fn_is_astro_r0 @ 0x1002D900 missing PID 0x0526 load",
    )
    require(
        blob[0x1014BB28 - BASE : 0x1014BB2A - BASE] == bytes.fromhex("00bf"),
        "Candidate missing PID 0x130A sRGB NOP lock at 0x1014BB28",
    )
    require(
        blob[0x100A34D0 - BASE : 0x100A34D6 - BASE] == bytes.fromhex("8af744bbe9e7"),
        "Candidate missing 0x100A34D0 uncompressed pack hook or corrupted 0x100A34D4",
    )
    require(
        blob[0x1002DB5C - BASE : 0x1002DB94 - BASE] == bytes.fromhex(TRAMP_A34D0_HEX),
        "Candidate missing tramp_a34d0 bytes at 0x1002DB5C",
    )
    require(digest == expected_sha, f"Candidate SHA-256 mismatch: {digest} != {expected_sha}")
    return {
        "sha256": digest,
        "crc16_hqx": f"0x{blob[-2:].hex()}",
        "size_bytes": len(blob),
        "crc_remainder": 0,
    }


def _synthesize_from_edits(stock_bytes: bytes, edits: list[dict], expected_sha: str) -> bytes:
    buf = bytearray(stock_bytes)
    for ed in edits:
        off = int(ed["address"], 16) - BASE
        before = bytes.fromhex(ed["before"])
        after = bytes.fromhex(ed["after"])
        require(buf[off : off + len(before)] == before, f"Before-bytes mismatch at {ed['address']}")
        buf[off : off + len(after)] = after
    update_crc(buf)
    out = bytes(buf)
    require(sha(out) == expected_sha, f"Synthesized firmware SHA-256 mismatch: {sha(out)} != {expected_sha}")
    return out


def pack_packed14_rows(img: np.ndarray, stride: int = 10624) -> bytes:
    """LSB-first EXPEED 6 hardware 14-bit packer: 4 uint16 (<16384) pixels -> 7 bytes, padded to `stride`."""
    h, w = img.shape
    require(w % 4 == 0, f"Width {w} is not a multiple of 4")
    pay = w * 14 // 8
    require(pay <= stride, f"Row payload {pay} exceeds stride {stride}")
    v = np.asarray(img, dtype=np.uint16)
    require(int(v.max()) < 16384, "Pixel value >= 16384 in 14-bit pack input")
    out = np.zeros((h, stride), dtype=np.uint8)
    s = out[:, :pay].reshape(h, -1, 7)
    v0, v1, v2, v3 = v[:, 0::4], v[:, 1::4], v[:, 2::4], v[:, 3::4]
    s[:, :, 0] = v0 & 0xFF
    s[:, :, 1] = ((v0 >> 8) & 0x3F) | ((v1 & 0x03) << 6)
    s[:, :, 2] = (v1 >> 2) & 0xFF
    s[:, :, 3] = ((v1 >> 10) & 0x0F) | ((v2 & 0x0F) << 4)
    s[:, :, 4] = (v2 >> 4) & 0xFF
    s[:, :, 5] = ((v2 >> 12) & 0x03) | ((v3 & 0x3F) << 2)
    s[:, :, 6] = (v3 >> 6) & 0xFF
    return out.tobytes()


def pack_packed12_rows(img: np.ndarray, stride: int = 9104) -> bytes:
    """LSB-first EXPEED 6 hardware 12-bit packer: 2 uint16 (<4096) pixels -> 3 bytes, padded to `stride`."""
    h, w = img.shape
    require(w % 2 == 0, f"Width {w} is not even")
    pay = w * 12 // 8
    require(pay <= stride, f"Row payload {pay} exceeds stride {stride}")
    v = np.asarray(img, dtype=np.uint16)
    require(int(v.max()) < 4096, "Pixel value >= 4096 in 12-bit pack input")
    out = np.zeros((h, stride), dtype=np.uint8)
    s = out[:, :pay].reshape(h, -1, 3)
    v0, v1 = v[:, 0::2], v[:, 1::2]
    s[:, :, 0] = v0 & 0xFF
    s[:, :, 1] = ((v0 >> 8) & 0x0F) | ((v1 & 0x0F) << 4)
    s[:, :, 2] = (v1 >> 4) & 0xFF
    return out.tobytes()


def unpack_packed12_rows(blob: bytes, stride: int, width: int) -> np.ndarray:
    nrows = len(blob) // stride
    g = np.frombuffer(blob, dtype=np.uint8, count=nrows * stride).reshape(nrows, stride)
    pay = width * 12 // 8
    s = g[:, :pay].reshape(nrows, -1, 3).astype(np.uint32)
    v = np.empty((nrows, pay // 3 * 2), dtype=np.uint16)
    v[:, 0::2] = s[:, :, 0] | ((s[:, :, 1] & 0x0F) << 8)
    v[:, 1::2] = (s[:, :, 1] >> 4) | (s[:, :, 2] << 4)
    return v[:, :width]


def run_site14_a34d0_hook_tests(cand_bytes: bytes, snap: dict) -> dict:
    """Directly verify Hook #14 (0x100A34D0 -> tramp_a34d0 @ 0x1002DB5C) register/APSR & dual-branch contracts."""
    rig = Rig(cand_bytes, snap)
    u = rig.uc
    try:
        _init_data_and_c24_ram(rig)

        PKT = RAM + 0x22000
        DESC = RAM + 0x22100
        cases = 0

        scenarios = (
            # (cs_0526, rec_131b, target_nef_fmt, r2_in, exp_in_pack, exp_out_pack)
            (0, 0, 4, 0, 0, 0),
            (0, 1, 2, 0, 0, 0),
            (1, 2, 4, 0, 0, 0),  # JPEG-only -> non-Astro Stock path
            (1, 0, 4, 0, 0, 1),  # Astro RAW+JPEG, 14-bit target -> out_pack = 1
            (1, 1, 4, 0, 0, 1),  # Astro pure RAW, 14-bit target -> out_pack = 1
            (1, 0, 2, 0, 0, 2),  # Astro RAW+JPEG, 12-bit target -> out_pack = 2
            (1, 1, 2, 0, 0, 2),  # Astro pure RAW, 12-bit target -> out_pack = 2
        )

        sentinel_regs = {
            0: 0x12345678,
            1: 0x89ABCDEF,
            3: 0x33334444,
            4: PKT,
            5: DESC,
            6: 0x66667777,
            7: 0x77778888,
            8: 0x88889999,
            9: 0x9999AAAA,
            10: 0xAAAABBBB,
            11: 0xBBBBCCCC,
            12: 0xCCCCDDDD,
        }
        reg_consts = {
            0: UC_ARM_REG_R0,
            1: UC_ARM_REG_R1,
            2: UC_ARM_REG_R2,
            3: UC_ARM_REG_R3,
            4: UC_ARM_REG_R4,
            5: UC_ARM_REG_R5,
            6: UC_ARM_REG_R6,
            7: UC_ARM_REG_R7,
            8: UC_ARM_REG_R8,
            9: UC_ARM_REG_R9,
            10: UC_ARM_REG_R10,
            11: UC_ARM_REG_R11,
            12: UC_ARM_REG_R12,
        }

        for cs_val, rec_val, tgt_fmt, r2_in, exp_in, exp_out in scenarios:
            for nzcv in (0xA0000000, 0x50000000, 0x00000000, 0xF0000000):
                _reset_rig(rig)
                rig.put(RAM_PROP_0526, cs_val)
                rig.put(RAM_PROP_131B, rec_val)
                rig.put(RAM_PROP_0508_REAL, 0)
                u.mem_write(PKT, b"\xFF" * 16)
                u.mem_write(DESC, bytes([0, tgt_fmt, 0, 0]))

                init_regs = {**sentinel_regs, 2: r2_in}
                for idx, val in init_regs.items():
                    u.reg_write(reg_consts[idx], val)
                sp_val = RAM + 0x2F000
                lr_val = 0x100AF6EB
                u.reg_write(UC_ARM_REG_SP, sp_val)
                u.reg_write(UC_ARM_REG_LR, lr_val)
                u.reg_write(UC_ARM_REG_CPSR, nzcv | 0x20)

                u.ctl_flush_tb()
                u.emu_start(0x100A34D0 | 1, 0x100A34AA, count=1000)
                require(u.reg_read(UC_ARM_REG_PC) == 0x100A34AA, "Did not reach 0x100A34AA")
                require(u.mem_read(PKT + 2, 1)[0] == exp_in, f"PKT+2 mismatch: expected {exp_in}")
                require(u.mem_read(PKT + 3, 1)[0] == exp_out, f"PKT+3 mismatch: expected {exp_out}")
                require((u.reg_read(UC_ARM_REG_CPSR) & 0xF0000000) == nzcv, "NZCV clobbered in tramp_a34d0")
                require(u.reg_read(UC_ARM_REG_SP) == sp_val, "SP unbalanced in tramp_a34d0")
                require(u.reg_read(UC_ARM_REG_LR) == lr_val, "LR clobbered in tramp_a34d0")
                for idx, exp_reg in init_regs.items():
                    require(u.reg_read(reg_consts[idx]) == exp_reg, f"r{idx} clobbered in tramp_a34d0")
                cases += 1

        # Verify adjacent instruction 0x100A34D4 (`b #0x100a34aa`) remains intact:
        _reset_rig(rig)
        u.ctl_flush_tb()
        u.emu_start(0x100A34D4 | 1, 0x100A34AA, count=16)
        require(u.reg_read(UC_ARM_REG_PC) == 0x100A34AA, "Adjacent 0x100A34D4 branch failed")
    finally:
        rig.uc = None
        del rig
        gc.collect()

    return {
        "site14_a34d0_dual_branch_and_apsr_cases": cases,
        "adjacent_0x100a34d4_branch_intact": True,
    }


def run_negative_m22_rejection_test(m22_bytes: bytes, expected_m23_sha: str, snap: dict) -> dict:
    """Ensure passing Modified22 binary is rejected by both binary validation and Hook #14 Unicorn test."""
    rejected_binary = False
    try:
        validate_m23_candidate_binary(m22_bytes, expected_m23_sha)
    except ValueError:
        rejected_binary = True
    require(rejected_binary, "Modified22 binary was not rejected by validate_m23_candidate_binary")

    rejected_hook14 = False
    try:
        run_site14_a34d0_hook_tests(m22_bytes, snap)
    except ValueError:
        rejected_hook14 = True
    require(rejected_hook14, "Modified22 binary was not rejected by run_site14_a34d0_hook_tests")

    return {
        "negative_m22_binary_gate_rejected": True,
        "negative_m22_hook14_unicorn_rejected": True,
    }


def _clean_reset_raw_rig(rig: Rig) -> None:
    for addr, n in rig.regions:
        rig.uc.mem_write(addr, bytes(n))
    for off in range(0x14000, 0x14120, 16):
        src, dst, n, handler = struct.unpack_from("<4I", rig.blob, off)
        if handler == 0x1002006C and 0xC1800000 <= dst < dst + n <= 0xC5800000:
            rig.uc.mem_write(dst, rig.blob[src - BASE : src - BASE + n])
    p = rig.put
    p(FRAME + 0x3A4, OWNER)
    p(FRAME + 0x1F8, INPUT)
    p(FRAME + 0x1FC, OUTPUT)
    p(FRAME + 0x330, ENCODED)
    p(FRAME + 0x314, 0)
    p(FRAME + 0x318, RAM + 0x33000)
    p(STAGE + 0xC, FRAME)
    p(OWNER, 0, "B")
    p(OWNER + 0x190, 1, "B")
    for off in (0x198, 0x19A, 0x19C, 0x19E):
        p(OWNER + off, 300, "H")
    p(0xC18812B4, 1)
    p(0xC18FA954 + 0x14, CAL)
    p(0xC188D8C4, 1, "B")
    p(DRIVER + 4, 0, "B")


def _make_raw_pipeline_rig(blob: bytes) -> Rig:
    rig = Rig(blob, {})
    rig.uc.mem_map(CODEC_MMIO, 4096)
    rig.uc.hook_add(un.UC_HOOK_MEM_WRITE, rig.on_write, begin=CODEC_MMIO, end=CODEC_MMIO + 4095)
    return rig


def _sim_raw_pipeline_case(
    rig: Rig,
    variant: str,
    astro_ui: int,
    raw_131b: int,
    cfg: dict,
    force_fallback: bool = False,
) -> dict:
    _clean_reset_raw_rig(rig)
    u, p, g = rig.uc, rig.put, rig.get
    p(RAM_PROP_0526, astro_ui)
    p(RAM_PROP_131B, raw_131b)

    for off, val in (
        (0x88, 0),
        (0x170, cfg["area"]),
        (0x190, raw_131b),
        (0x192, cfg["size"]),
        (0x194, cfg["mode"]),
        (0x195, cfg["depth"]),
        (0x252, cfg["wide"]),
        (0x2811, cfg.get("readout", 0)),
    ):
        p(OWNER + off, val, "B")
    p(OWNER + 0x1AF0, cfg.get("slow_1af0", 0))

    pre = rig.call(0x10124196, until=0x100D8868, regs={4: OWNER, 5: 2, 6: RAM + 0x48000})
    fmt = int(pre["registers"]["r5"], 16)
    capacity = int(pre["registers"]["r2"], 16)
    expected_in_fmt = 2 if cfg["depth"] == 0 else (3 if (cfg["wide"] or cfg.get("slow_1af0", 0)) else 4)
    require(fmt == expected_in_fmt, f"Unexpected frontend format {fmt} != {expected_in_fmt}")

    for h, ad, base in ((INPUT, ALLOC, 0x60000000), (OUTPUT, ALLOC + 0x20, 0x64000000), (ENCODED, ALLOC + 0x40, 0x68000000)):
        p(h + 4, ad)
        p(ad, base)
        p(ad + 4, capacity)

    rig.call(0x10123E70, [INPUT, OWNER, fmt])
    # Model C3.80 post-capture handoff (`0x10142D8E` & `0x10142E7A` clear `OWNER+0x252` and `OWNER+0x1AF0`
    # before backend replacement `OUTPUT` descriptor setup `0x10124224`):
    p(OWNER + 0x252, 0, "B")
    p(OWNER + 0x1AF0, 0)
    rig.call(0x10124224, [OUTPUT, OWNER])
    rig.call(0x101254BC, [ENCODED, OWNER])

    out_w, out_h = g(ENCODED + 0x52, "H"), g(ENCODED + 0x54, "H")
    target_nef_fmt = g(ENCODED + 0x51, "B")
    raw_cap = g(ENCODED + 0x4C)

    has_raw = raw_131b in (0, 1)
    astro_active = (variant in ("m22", "m23")) and (astro_ui == 1 and has_raw)
    p(REQ + 0x1A8, 0x5A5A5A5A if has_raw else 0)
    rig.call(0x100AE33E, [STAGE], until=0x100B4C78)

    if not has_raw:
        require(g(REQ + 0x1A8) == 0, "JPEG-only unexpectedly populated REQ+0x1A8")
        ret = rig.call(0x100AF648, [STAGE])
        require(int(ret["registers"]["r0"], 16) == 0, "0x100AF648 non-zero return on JPEG-only")
        return {
            "variant": variant,
            "kind": "jpeg_only_skip",
            "astro_active": False,
            "frontend_fmt": fmt,
            "req_1a8": 0,
            "af648_ret": 0,
        }

    replacement = (not astro_active) or (cfg["size"] != 0)
    require(
        g(REQ + 0x1A8) == (OUTPUT if replacement else 0),
        f"Unexpected REQ+0x1A8 replacement handle for {variant} {cfg}",
    )

    rig.call(0x100AE41E, until=0x100AE438, regs={4: FRAME, 5: REQ})
    chosen = OUTPUT if replacement else INPUT
    require(g(FRAME + 0x1F8) == chosen, "Unexpected chosen buffer in FRAME+0x1F8")
    chosen_fmt = g(chosen + 0x24, "B")

    if force_fallback:
        rig.call(0x100AF648, [STAGE], until=0x101CAAD8)
        p(GLOBAL + 0x5C, 1)
        lr_ret = u.reg_read(UC_ARM_REG_LR) & ~1
        u.reg_write(UC_ARM_REG_R0, 0)
        u.ctl_flush_tb()
        u.emu_start(lr_ret | 1, 0x101CAB2E, count=1500000)
        require(u.reg_read(UC_ARM_REG_PC) == 0x101CAB2E, "Fallback did not reach 0x101CAB2E")
        eff_mode = 0
    else:
        eff_mode = cfg["mode"]
        queue = 0x101CAB2E if eff_mode == 0 else 0x101CAAD8
        rig.call(0x100AF648, [STAGE], until=queue)

    if eff_mode == 0:
        gp = GLOBAL + 0x6C
        in_pack = g(gp + 2, "B")
        out_pack = g(gp + 3, "B")
        src_stride = g(gp + 0x24, "H")
        dst_stride = g(gp + 0x2C, "H")
        pkt_bytes = g(gp + 0x18)
        r4_q = u.reg_read(UC_ARM_REG_R4)
        r5_q = u.reg_read(UC_ARM_REG_R5)
        r8_q = u.reg_read(UC_ARM_REG_R8)
        rig.call(0x100A359C, until=0x100A35AC, regs={0: 0, 4: r4_q, 5: r5_q, 8: r8_q})
        strip_byte_counts = g(ENCODED + 0x5C)

        u.mem_write(CODEC_MMIO, bytes(4096))
        u.mem_write(MAPPED, bytes(0x80))
        p(CONTEXT + 0x10, gp)
        rig.call(0x101CA666, [MAPPED])
        rig.call(0x10108F8A, [CODEC_CTX, MAPPED])
        mmio_40 = g(CODEC_MMIO + 0x40)
        lut_ptr = g(MAPPED + 0x0C)
        return {
            "variant": variant,
            "kind": "uncompressed",
            "astro_active": astro_active,
            "frontend_fmt": fmt,
            "chosen_fmt": chosen_fmt,
            "target_nef_fmt": target_nef_fmt,
            "in_pack": in_pack,
            "out_pack": out_pack,
            "src_stride": src_stride,
            "dst_stride": dst_stride,
            "out_wh": [out_w, out_h],
            "pkt_bytes": pkt_bytes,
            "strip_byte_counts": strip_byte_counts,
            "raw_cap": raw_cap,
            "fits_raw_cap": strip_byte_counts <= raw_cap,
            "mmio_40": f"0x{mmio_40:08x}",
            "mmio_in_fmt": mmio_40 & 7,
            "mmio_out_fmt": (mmio_40 >> 3) & 7,
            "lut_ptr": lut_ptr,
        }

    gp = GLOBAL
    return {
        "variant": variant,
        "kind": "compressed_queue",
        "astro_active": astro_active,
        "frontend_fmt": fmt,
        "chosen_fmt": chosen_fmt,
        "target_nef_fmt": target_nef_fmt,
        "in_pack": g(gp + 2, "B"),
        "src_stride": g(gp + 0x44, "H"),
        "codec_row_bytes": g(gp + 0x4C, "H"),
        "out_wh": [out_w, out_h],
        "raw_cap": raw_cap,
    }


def run_uncompressed_raw_pipeline_matrix(m23_bytes: bytes, m22_bytes: bytes, stock_bytes: bytes) -> dict:
    rig_m23 = _make_raw_pipeline_rig(m23_bytes)
    rig_m22 = _make_raw_pipeline_rig(m22_bytes)
    rig_stk = _make_raw_pipeline_rig(stock_bytes)

    total = 0
    grid_total = 0
    uncomp_verified = 0
    comp_queue_verified = 0
    jpeg_skip_verified = 0
    stock_parity_verified = 0

    try:
        for astro_ui, raw_131b in ((1, 0), (1, 1), (0, 0), (1, 2)):
            astro_on = astro_ui == 1 and raw_131b in (0, 1)
            for area in (0, 1):
                for depth in (0, 1):
                    for wide, slow in ((0, 0), (1, 0), (0, 1)):
                        for size in (0, 1, 2):
                            for mode in (0, 1, 2):
                                c = {
                                    "area": area,
                                    "size": size,
                                    "mode": mode,
                                    "depth": depth,
                                    "wide": wide,
                                    "readout": 0,
                                    "slow_1af0": slow,
                                }
                                r23 = _sim_raw_pipeline_case(rig_m23, "m23", astro_ui, raw_131b, c)
                                r22 = _sim_raw_pipeline_case(rig_m22, "m22", astro_ui, raw_131b, c)
                                total += 1
                                grid_total += 1

                                if r23["kind"] == "uncompressed":
                                    require(r23["fits_raw_cap"], f"RAW strip overflow in M23: {r23}")
                                    uncomp_verified += 1
                                elif r23["kind"] == "compressed_queue":
                                    comp_queue_verified += 1
                                elif r23["kind"] == "jpeg_only_skip":
                                    jpeg_skip_verified += 1

                                if not astro_on:
                                    r_stk = _sim_raw_pipeline_case(rig_stk, "stock", astro_ui, raw_131b, c)
                                    r23_cmp = {k: v for k, v in r23.items() if k != "variant"}
                                    r22_cmp = {k: v for k, v in r22.items() if k != "variant"}
                                    stk_cmp = {k: v for k, v in r_stk.items() if k != "variant"}
                                    require(r23_cmp == stk_cmp, f"Non-astro Stock parity failed: {c}")
                                    require(r23_cmp == r22_cmp, f"Non-astro M22 parity failed: {c}")
                                    stock_parity_verified += 1
                                elif mode == 0:
                                    exp_out = 2 if r23["target_nef_fmt"] == 2 else 1
                                    if r23["chosen_fmt"] == 3:
                                        require(
                                            r23["in_pack"] == 0 and r23["out_pack"] == exp_out,
                                            f"Unexpected M23 format-3 pack codes: {r23}",
                                        )
                                        require(
                                            r23["mmio_in_fmt"] == 0 and r23["mmio_out_fmt"] == exp_out,
                                            f"Unexpected M23 CODEC_MMIO+0x40 format bits: {r23}",
                                        )
                                        require(r23["lut_ptr"] == 0, f"Expected lut_ptr=0 in M23: {r23}")
                                    elif r23["chosen_fmt"] == 4:
                                        require(
                                            r23["in_pack"] == 1 and r23["out_pack"] == 1,
                                            f"Unexpected M23 format-4 pack codes: {r23}",
                                        )
                                    elif r23["chosen_fmt"] == 2:
                                        require(
                                            r23["in_pack"] == 2 and r23["out_pack"] == 2,
                                            f"Unexpected M23 format-2 pack codes: {r23}",
                                        )

        # Electronic shutter (readout=1) uncompressed Astro RAW cases:
        for depth in (0, 1):
            for wide in (0, 1):
                c = {"area": 0, "size": 0, "mode": 0, "depth": depth, "wide": wide, "readout": 1, "slow_1af0": 0}
                r23 = _sim_raw_pipeline_case(rig_m23, "m23", 1, 0, c)
                require(r23["kind"] == "uncompressed" and r23["fits_raw_cap"] and r23["lut_ptr"] == 0, f"ES fail: {r23}")
                total += 1
                uncomp_verified += 1

        # Lossless -> Uncompressed codec error fallback (0x100AF6D8..0x100AF6E6):
        c_fb = {"area": 0, "size": 0, "mode": 1, "depth": 1, "wide": 1, "readout": 0, "slow_1af0": 1}
        r_fb = _sim_raw_pipeline_case(rig_m23, "m23", 1, 0, c_fb, force_fallback=True)
        require(
            r_fb["kind"] == "uncompressed"
            and r_fb["in_pack"] == 0
            and r_fb["out_pack"] == 1
            and r_fb["strip_byte_counts"] == 42920960
            and r_fb["fits_raw_cap"]
            and r_fb["lut_ptr"] == 0,
            f"Lossless->Uncompressed fallback verification failed: {r_fb}",
        )
        total += 1
        uncomp_verified += 1

        # Capture key comparison on FX 14-bit 5s/wide=1 Uncompressed (matching real Z61_5116.NEF vs Z61_5105.NEF):
        c_key = {"area": 0, "size": 0, "mode": 0, "depth": 1, "wide": 1, "readout": 0, "slow_1af0": 0}
        m22_key = _sim_raw_pipeline_case(rig_m22, "m22", 1, 0, c_key)
        m23_key = _sim_raw_pipeline_case(rig_m23, "m23", 1, 0, c_key)
        stk_key = _sim_raw_pipeline_case(rig_stk, "stock", 0, 0, c_key)
        m23_std = _sim_raw_pipeline_case(rig_m23, "m23", 0, 0, c_key)
        require(
            {k: v for k, v in m23_std.items() if k != "variant"}
            == {k: v for k, v in stk_key.items() if k != "variant"},
            "Key FX 14-bit wide=1 Standard mode Stock parity failed",
        )
        require(
            stk_key["chosen_fmt"] == 4 and stk_key["strip_byte_counts"] == 42920960 and stk_key["fits_raw_cap"],
            f"Unexpected Stock Standard 5s uncompressed geometry: {stk_key}",
        )
        require(
            m22_key["chosen_fmt"] == 3 and m22_key["strip_byte_counts"] == 48997120 and not m22_key["fits_raw_cap"],
            f"Failed to reproduce M22 48,997,120 B overflow: {m22_key}",
        )
        require(
            m23_key["chosen_fmt"] == 3 and m23_key["strip_byte_counts"] == 42920960 and m23_key["fits_raw_cap"],
            f"Unexpected M23 FX 14-bit wide=1 uncompressed geometry: {m23_key}",
        )
    finally:
        for r_obj in (rig_m23, rig_m22, rig_stk):
            r_obj.uc = None
        del rig_m23, rig_m22, rig_stk
        gc.collect()

    require(
        uncomp_verified + comp_queue_verified + jpeg_skip_verified == total == 437,
        "Pipeline matrix category counts do not sum to 437",
    )

    return {
        "raw_pipeline_matrix_cases": total,
        "raw_pipeline_matrix_breakdown": {
            "grid_total": grid_total,
            "uncompressed_strip_and_mmio_verified": uncomp_verified,
            "compressed_queue_descriptor_verified": comp_queue_verified,
            "jpeg_only_encoder_skip_verified": jpeg_skip_verified,
            "non_astro_stock_parity_verified": stock_parity_verified,
            "compressed_final_bytes_note": (
                "Compressed modes (Lossless/Lossy) are verified through native descriptor & codec queue "
                "submission (0x100A323E -> 0x101CAAD8) plus Lossless->Uncompressed error fallback; "
                "final variable-length compressed bitstream output is generated by EXPEED hardware."
            ),
        },
        "fx_14bit_wide1_uncompressed_comparison": {
            "stock_standard_chosen_fmt": stk_key["chosen_fmt"],
            "stock_standard_strip_byte_counts": stk_key["strip_byte_counts"],
            "stock_standard_fits_raw_cap": stk_key["fits_raw_cap"],
            "m22_chosen_fmt": m22_key["chosen_fmt"],
            "m22_out_pack": m22_key["out_pack"],
            "m22_dst_stride": m22_key["dst_stride"],
            "m22_strip_byte_counts": m22_key["strip_byte_counts"],
            "m22_fits_raw_cap": m22_key["fits_raw_cap"],
            "m23_chosen_fmt": m23_key["chosen_fmt"],
            "m23_in_pack": m23_key["in_pack"],
            "m23_out_pack": m23_key["out_pack"],
            "m23_dst_stride": m23_key["dst_stride"],
            "m23_strip_byte_counts": m23_key["strip_byte_counts"],
            "m23_raw_cap": m23_key["raw_cap"],
            "m23_fits_raw_cap": m23_key["fits_raw_cap"],
            "m23_mmio_40": m23_key["mmio_40"],
            "m23_lut_ptr": m23_key["lut_ptr"],
            "preview_slot_headroom_bytes": FIRST_PREVIEW_REL_OFFSET - m23_key["strip_byte_counts"],
        },
        "lossless_to_uncompressed_fallback_verified": True,
    }


def run_bitpack_and_libraw_roundtrip_tests() -> dict:
    """Verify synthetic 14/12-bit software bit-packing + optional Z61_5105.NEF software repack & LibRaw decode."""
    rng = np.random.default_rng(20261118)
    syn14 = rng.integers(0, 16384, size=(4040, 6064), dtype=np.uint16)
    syn14[0, :4] = np.array([0, 16383, 1008, 0x2AAA], dtype=np.uint16)
    packed14 = pack_packed14_rows(syn14, stride=10624)
    require(len(packed14) == 42920960, f"Unexpected packed14 length: {len(packed14)}")
    unpacked14 = nel.unpack_packed14_rows(packed14, 10624, 6064)
    require(np.array_equal(syn14, unpacked14), "14-bit full-frame pack/unpack mismatch")

    syn12 = rng.integers(0, 4096, size=(4040, 6064), dtype=np.uint16)
    syn12[0, :4] = np.array([0, 4095, 252, 0x0AAA], dtype=np.uint16)
    packed12 = pack_packed12_rows(syn12, stride=9104)
    require(len(packed12) == 36780160, f"Unexpected packed12 length: {len(packed12)}")
    unpacked12 = unpack_packed12_rows(packed12, 9104, 6064)
    require(np.array_equal(syn12, unpacked12), "12-bit full-frame pack/unpack mismatch")

    synthetic_pack = {
        "status": "PASS",
        "frame_wh": [6064, 4040],
        "pixels_verified": 24498560,
        "packed14_stride_bytes": 10624,
        "packed14_strip_bytes": 42920960,
        "packed12_stride_bytes": 9104,
        "packed12_strip_bytes": 36780160,
        "max_abs_adu_diff": 0,
    }

    nef_rel = "samples/11.17_modified22/Z61_5105.NEF"
    nef_sample = ROOT / nef_rel
    if nef_sample.is_file():
        import rawpy

        raw_bytes = nef_sample.read_bytes()
        source_sha = nel.sha256_bytes(raw_bytes)
        rec = nel.parse_nef(nef_sample)
        li = nel.classify_layout(rec)
        buf = bytearray(raw_bytes)
        off = li["strip_offset"]
        u16_ref = np.frombuffer(buf, dtype="<u2", count=6064 * 4040, offset=off).reshape(4040, 6064).copy()
        r0, r1 = li["preview_overlay_rows"]
        substituted_rows = r1 - r0 + 1
        clean_top_rows = r0
        clean_bottom_rows = 4040 - (r1 + 1)
        clean_total_rows = clean_top_rows + clean_bottom_rows
        require((r0, r1, substituted_rows) == (3633, 4000, 368), f"Unexpected overlay rows: {(r0, r1)}")
        require(int(u16_ref[:clean_top_rows].max()) < 16384, "Clean sensor rows 0..3632 exceed 14-bit range")
        require(int(u16_ref[r1 + 1 :].max()) < 16384, "Clean sensor rows 4001..4039 exceed 14-bit range")
        # Substitute rows 3633..4000 (overwritten on card in M22 by embedded preview JPEGs) with clean rows 0..367
        # to construct a valid 4040-row 14-bit reference frame for software bit-packing + LibRaw decode:
        u16_ref[r0 : r1 + 1] = u16_ref[:substituted_rows]
        packed_real = pack_packed14_rows(u16_ref, 10624)
        buf[off : off + 42920960] = packed_real
        for ent in rec["raw_subifd"]["entries"]:
            if ent["tag"] == 0x0117:
                struct.pack_into("<I", buf, ent["off"], 42920960)
        for s in li["embedded_jpeg_slots"]:
            abs_o, ln = s["abs_offset"], s["length"]
            require(
                nel.sha256_bytes(bytes(buf[abs_o : abs_o + ln])) == s["sha256"],
                f"Embedded preview JPEG slot corrupted at +{s['rel_offset']}",
            )

        with tempfile.NamedTemporaryFile(suffix=".NEF", delete=False) as tf:
            tmp_nef = Path(tf.name)
            tf.write(bytes(buf))
        try:
            with rawpy.imread(str(tmp_nef)) as raw:
                lr_img = raw.raw_image.copy()
            require(lr_img.shape == (4040, 6064), f"Unexpected LibRaw decoded shape: {lr_img.shape}")
            require(int(np.count_nonzero(lr_img != u16_ref)) == 0, "LibRaw decoded pixels differ from reference")
            require(
                int(np.count_nonzero(lr_img[:clean_top_rows] != u16_ref[:clean_top_rows])) == 0
                and int(np.count_nonzero(lr_img[r1 + 1 :] != u16_ref[r1 + 1 :])) == 0,
                "LibRaw clean sensor rows (0..3632 / 4001..4039) mismatch",
            )
        finally:
            if tmp_nef.exists():
                tmp_nef.unlink()

        lr_ver_raw = getattr(rawpy, "libraw_version", "unknown")
        lr_ver = ".".join(map(str, lr_ver_raw)) if isinstance(lr_ver_raw, tuple) else str(lr_ver_raw)
        real_nef_libraw = {
            "status": "PASS",
            "sample_rel_path": nef_rel,
            "source_nef_sha256": source_sha,
            "clean_unmodified_sensor_row_ranges": [[0, clean_top_rows - 1], [r1 + 1, 4039]],
            "clean_unmodified_sensor_row_count": clean_total_rows,
            "clean_unmodified_sensor_pixels": clean_total_rows * 6064,
            "substituted_preview_overlay_rows": [r0, r1],
            "substituted_preview_overlay_row_count": substituted_rows,
            "substituted_preview_overlay_pixels": substituted_rows * 6064,
            "comparison_reference": (
                "Software-repacked 14-bit NEF built from Z61_5105.NEF clean 16-bit LE sensor rows 0..3632 & "
                "4001..4039 plus rows 0..367 substituted into preview-overwritten rows 3633..4000, compared "
                "pixel-for-pixel against that exact pre-pack uint16 reference after end-to-end LibRaw decode."
            ),
            "repacked_strip_byte_counts": 42920960,
            "embedded_preview_jpeg_slots_preserved": len(li["embedded_jpeg_slots"]),
            "rawpy_version": str(getattr(rawpy, "__version__", "unknown")),
            "libraw_version": lr_ver,
            "total_pixels_decoded": 24498560,
            "max_abs_adu_diff_vs_prepack_reference": 0,
        }
    else:
        real_nef_libraw = {
            "status": "SKIPPED",
            "sample_rel_path": nef_rel,
            "reason": "Local calibration sample samples/11.17_modified22/Z61_5105.NEF not present in checkout.",
        }

    m23_hw_dir = ROOT / "samples/11.19_modified23"
    m23_uncomp_names = [f"Z61_{n}.NEF" for n in range(5131, 5137)]
    m23_lossless_names = [f"Z61_{n}.NEF" for n in range(5128, 5131)]
    if m23_hw_dir.is_dir() and all((m23_hw_dir / fn).is_file() for fn in m23_uncomp_names + m23_lossless_names):
        import rawpy

        hw_pixels_verified = 0
        for fn in m23_uncomp_names:
            p_hw = m23_hw_dir / fn
            rec_hw = nel.parse_nef(p_hw)
            li_hw = nel.classify_layout(rec_hw)
            require(li_hw["layout"] == "packed_14bit_stride10624", f"Unexpected layout in {fn}: {li_hw['layout']}")
            off_hw = int(li_hw["strip_offset"])
            sbc_hw = int(li_hw["strip_byte_count"])
            require(sbc_hw == 42920960 and off_hw + sbc_hw == rec_hw["filesize"], f"Strip bounds mismatch in {fn}")
            for pv_hw in rec_hw["previews"]:
                if pv_hw["jpeg_offset"] is not None and pv_hw["jpeg_length"] is not None:
                    po_hw, pl_hw = int(pv_hw["jpeg_offset"]), int(pv_hw["jpeg_length"])
                    require(po_hw + pl_hw <= off_hw or po_hw >= off_hw + sbc_hw, f"Preview overlaps RAW in {fn}")
            indep_hw = nel.unpack_packed14_rows(rec_hw["_buf"][off_hw : off_hw + sbc_hw], 10624, 6064)
            with rawpy.imread(str(p_hw)) as raw_hw:
                lr_hw = raw_hw.raw_image.copy()
            require(np.array_equal(indep_hw, lr_hw), f"Hardware packed-14 vs LibRaw mismatch in {fn}")
            hw_pixels_verified += int(indep_hw.size)
        for fn in m23_lossless_names:
            p_hw = m23_hw_dir / fn
            rec_hw = nel.parse_nef(p_hw)
            li_hw = nel.classify_layout(rec_hw)
            require(li_hw["layout"] == "lossless_14bit", f"Unexpected lossless layout in {fn}: {li_hw['layout']}")
        hardware_camera_nef = {
            "status": "PASS",
            "sample_batch": "samples/11.19_modified23",
            "frames_verified": 9,
            "uncompressed_packed14_frames": 6,
            "lossless_14bit_frames": 3,
            "hardware_packed14_pixels_verified": hw_pixels_verified,
            "libraw_vs_independent_pixel_diff_count": 0,
            "preview_overlap_count": 0,
        }
        hw_verified_flag = True
    else:
        hardware_camera_nef = {
            "status": "SKIPPED",
            "sample_batch": "samples/11.19_modified23",
            "reason": "Real-camera sample batch samples/11.19_modified23 not present in checkout.",
        }
        hw_verified_flag = False

    return {
        "packed14_fullframe_pixels_verified": 24498560,
        "packed14_strip_bytes": 42920960,
        "packed12_fullframe_pixels_verified": 24498560,
        "packed12_strip_bytes": 36780160,
        "synthetic_pack": synthetic_pack,
        "real_nef_libraw": real_nef_libraw,
        "hardware_camera_nef": hardware_camera_nef,
        "hardware_pixels_verified": hw_verified_flag,
    }


def main() -> None:
    if not __debug__:
        raise RuntimeError("probe_modified23_native.py must not be executed with Python -O/-OO.")

    default_manifest = ROOT / "analysis/modified23-preflash-2026-11-18/lab-build/modified23-manifest.json"
    if not default_manifest.is_file():
        default_manifest = ROOT / "patches/z6-c380-modified23-uncompressed-astro-raw-srgb-600s.json"

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--manifest",
        type=Path,
        default=default_manifest,
        help="Path to modified23-manifest.json or tracked Modified23 patch recipe JSON",
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
        help="Optional path to built Modified23 .bi/.BIN (otherwise read alongside manifest or built in memory)",
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
        help="Optional output path for probe_modified23_native_result.json",
    )
    args = ap.parse_args()

    manifest_p = args.manifest.resolve()
    require(manifest_p.is_file(), f"Missing manifest: {manifest_p.name}")
    manifest = json.loads(manifest_p.read_text(encoding="utf-8"))

    stock_bytes = load_stock_eg_module(args.stock, ROOT)
    require(sha(stock_bytes) == STOCK_SHA, "Stock EG SHA-256 mismatch")

    if args.candidate is not None:
        cand_p = args.candidate.resolve()
        require(cand_p.is_file(), f"Missing --candidate file: {cand_p.name}")
        m23_bytes = cand_p.read_bytes()
        candidate_source = "explicit_candidate_file"
    elif (manifest_p.parent / "modified23-candidate.bi").is_file():
        m23_bytes = (manifest_p.parent / "modified23-candidate.bi").read_bytes()
        candidate_source = "lab_build_candidate_bi"
    else:
        m23_bytes = _synthesize_from_edits(stock_bytes, manifest["edits"], manifest["modified23_sha256"])
        candidate_source = "synthesized_from_stock_and_recipe"

    measured_cand = validate_m23_candidate_binary(m23_bytes, manifest["modified23_sha256"])

    m22_edits, _ = collect_m22_edits(stock_bytes)
    m22_bytes = _synthesize_from_edits(stock_bytes, m22_edits, MODIFIED22_SHA)
    m20_bytes, syms20, m21_bytes, syms21 = _synthesize_m20_m21_from_stock(stock_bytes)
    syms23 = {k: int(v, 16) for k, v in manifest["cave_symbols"].items()}

    if args.snap is not None:
        snap_p = args.snap.resolve()
        require(snap_p.is_file(), f"Specified --snap file not found: {snap_p.name}")
        snap = json.loads(snap_p.read_text(encoding="utf-8"))
        snap_mode = f"file:{snap_p.name}"
    else:
        snap = {}
        snap_mode = "zero_init_plus_rom_data_table"

    res_neg = run_negative_m22_rejection_test(m22_bytes, manifest["modified23_sha256"], snap)
    blobs = {"m22": m23_bytes, "m20": m23_bytes, "stock": stock_bytes}
    res_pred = run_e2e_predicate_and_m20_m21_regression_tests(
        m23_bytes, m21_bytes, m20_bytes, snap, syms23, syms21, syms20
    )
    res_lock = run_color_space_130a_lock_and_auto_iso_restore_tests(m23_bytes, stock_bytes, snap)
    res_hooks13 = run_all_13_hook_site_tests(blobs, snap)
    res_hook14 = run_site14_a34d0_hook_tests(m23_bytes, snap)
    res_matrix = run_uncompressed_raw_pipeline_matrix(m23_bytes, m22_bytes, stock_bytes)
    res_pack = run_bitpack_and_libraw_roundtrip_tests()
    res_ui = run_ui_string_tests(blobs, snap)
    res_iv = run_interval_timer_tests(blobs)
    res_end = run_interval_endtime_tests(blobs)

    if args.output is not None:
        out_json = args.output.resolve()
    elif manifest_p.parent == (ROOT / "patches").resolve():
        out_json = ROOT / "analysis/modified23-preflash-2026-11-18/lab-build/probe_modified23_native_result.json"
    else:
        out_json = manifest_p.parent / "probe_modified23_native_result.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "candidate": manifest["candidate"],
        "design": manifest["design"],
        "candidate_source": candidate_source,
        "modified23_sha256": measured_cand["sha256"],
        "measured_candidate_sha256": measured_cand["sha256"],
        "measured_candidate_crc16_hqx": measured_cand["crc16_hqx"],
        "measured_candidate_size_bytes": measured_cand["size_bytes"],
        "ram_snapshot_mode": snap_mode,
        "tests": {
            **res_neg,
            **res_pred,
            **res_lock,
            **res_hooks13,
            **res_hook14,
            **res_matrix,
            **res_pack,
            **res_ui,
            **res_iv,
            **res_end,
        },
        "status": "PASS",
    }
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()

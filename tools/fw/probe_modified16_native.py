"""Comprehensive Unicorn ARM/Thumb native verification for Modified16 (UI-Switchable Astro Lossless + Permanent 30-600s v2)."""
from __future__ import annotations
import argparse
import gc
import itertools
import json
import struct
from pathlib import Path
import sys

import unicorn as un
from unicorn.arm_const import (
    UC_ARM_REG_CPSR,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_SP,
)

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from probe_raw_candidates import (
    A,
    BASE,
    CACHE,
    CAL,
    DRIVER,
    ENCODED,
    FLAGS,
    FRAME,
    INPUT,
    MAINREQ,
    MMIO,
    OUTPUT,
    OWNER,
    PACKET,
    RAM,
    REGS,
    REQ,
    ROOT,
    SPATIAL,
    STACK,
    STAGE,
    STOP,
    STORAGE,
    TABLES,
    VECTOR,
    Rig,
    sha,
)
import probe_release_contract as rel
from probe_still_vignette_neutral import AUX, CURVE, HISTORY, MIXED, TCTX, VOUT, VREQ, seed, serialize
from z6_astro_ui_toggle import (
    HELP_EN,
    HELP_ZH_CN,
    HELP_ZH_TW,
    LABEL_EN,
    LABEL_ZH_CN,
    LABEL_ZH_TW,
    LANG_ZH_CN,
    LANG_ZH_TW,
    RAM_PROP_0506,
    RAM_PROP_1315,
    RAM_PROP_131B,
    UI_STR_ID_HELP,
    UI_STR_ID_LABEL,
    build_astro_ui_cave,
)
from z6_m600_v2_emu_e2e import run_all_m600_v2_tests

STOCK_SHA = "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c"
M10_SHA = "85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4"
M12_SHA = "9734012be0e063fa8f2ccbf77c2dd5a63a76be2f45887aa6b806b97b441cb67c"
M13_SHA = "3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749"
M14_SHA = "6d970609c18ac64302e82a7e4f4bfba9d8d4b14a606b55bf2cbc56dc37ea754b"
M15_SHA = "0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c"
M16_SHA = "4cca328ccbac4a025111bcf5fd6d88ca8667eb2da0b543ce3db42cf0d8da91cf"

CTX, STATE, PKT, ID35 = 0xC18FA844, 0xC18FA954, 0xC29A34C0, 0x56000000
START = 0x1017D7B6
P_REQ, P_OUT = RAM + 0x36000, RAM + 0x36100


def _set_astro_ram(rig: Rig, val_1315: int, val_131b: int = 0) -> None:
    rig.put(RAM_PROP_1315, val_1315)
    rig.put(RAM_PROP_131B, val_131b)


def _reset_rig(rig: Rig) -> None:
    rig.reset(dict(scalar=300, bank=0, cached=0))


def run_predicate_and_0x1315_builder_tests(m16: bytes, snap: dict, syms: dict[str, int]) -> dict:
    """Verify native 0x1014a852 derived property 0x1315 computation and fn_is_astro_r0 gate matrix."""
    rig = Rig(m16, snap)
    u, p, g = rig.uc, rig.put, rig.get

    # 1. Exhaustive matrix on fn_is_astro_r0 across 0x1315 in {0,1,2,3} and 0x131b in {0,1,2,3,0xff}
    pred_cases = 0
    fn_addr = syms["fn_is_astro_r0"]
    for v1315 in (0, 1, 2, 3):
        for v131b in (0, 1, 2, 3, 0xFF):
            _reset_rig(rig)
            _set_astro_ram(rig, v1315, v131b)
            res = rig.call(fn_addr)
            got = int(res["registers"]["r0"], 16)
            exp = 1 if (v1315 == 2 and v131b in (0, 1)) else 0
            assert got == exp, f"fn_is_astro_r0({v1315}, {v131b}) -> {got} != {exp}"
            pred_cases += 1

    # 2. Native 0x1014a852 builder: [r1+0]=flag, [r1+4]=0x0506, [r1+8]=prev, [r1+0xc]=0x0505(size), [r1+0x18]=old_1315
    #    Stub 0x1014a6e0(count=r0, p_pid=r1, p_val=r2, ctx=r3) to capture published (pid, val) into RAM_PROP_1315!
    published: list[tuple[int, int]] = []

    def stub_publish(uc, pc, size, _):
        p_pid = uc.reg_read(UC_ARM_REG_R1)
        p_val = uc.reg_read(UC_ARM_REG_R2)
        pid = struct.unpack("<I", uc.mem_read(p_pid, 4))[0]
        val = struct.unpack("<I", uc.mem_read(p_val, 4))[0]
        published.append((pid, val))
        uc.mem_write(RAM_PROP_1315, struct.pack("<I", val))
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    u.hook_add(un.UC_HOOK_CODE, stub_publish, begin=0x1014A6E0, end=0x1014A6E0)

    builder_cases = 0
    IN_STRUCT = RAM + 0x41000
    CTX_STRUCT = RAM + 0x41100
    for nef_size in (0, 1, 2):  # 0=Large, 1=Medium, 2=Small
        for nef_comp in (0, 1, 2):  # 0=Uncomp, 1=Lossless, 2=Astro Lossless
            _reset_rig(rig)
            published.clear()
            u.mem_write(IN_STRUCT, b"\x00" * 0x20)
            u.mem_write(CTX_STRUCT, b"\x00" * 0x90)
            p(IN_STRUCT + 0x0, 0)
            p(IN_STRUCT + 0x4, nef_comp)
            p(IN_STRUCT + 0x8, 0xFF)
            p(IN_STRUCT + 0xC, nef_size, "B")
            p(IN_STRUCT + 0x18, 0xFF)
            rig.call(0x1014A852, [0, IN_STRUCT, CTX_STRUCT])
            exp_1315 = nef_comp if nef_size == 0 else 1
            assert published == [(0x1315, exp_1315)], f"0x1014a852(size={nef_size}, comp={nef_comp}) -> {published}"
            # Verify downstream fn_is_astro_r0 with RAW active (0x131b=0) vs JPEG-only (0x131b=3):
            p(RAM_PROP_131B, 0)
            r_raw = int(rig.call(fn_addr)["registers"]["r0"], 16)
            assert r_raw == (1 if (nef_size == 0 and nef_comp == 2) else 0)
            p(RAM_PROP_131B, 3)
            r_jpg = int(rig.call(fn_addr)["registers"]["r0"], 16)
            assert r_jpg == 0, "JPEG-only mode must always suppress Astro RAW!"
            builder_cases += 1

    rig.uc = None
    del rig
    gc.collect()
    return {"predicate_matrix_cases": pred_cases, "native_0x1315_builder_cases": builder_cases}


def run_dual_frontend_sanitizer_tests(blobs: dict[str, bytes], snap: dict, cal: bytes, fixed: bytes, ctx_bytes: bytes) -> dict:
    """Verify 0x1017d834 matches Stock 100% when Astro is OFF/JPEG-only and matches Modified13 100% when Astro is ON."""
    configs = [
        dict(mode=1, temp=t, submode=s, category=c, dc=d)
        for t in (0, 1) for s in (0, 2) for c in (0, 1) for d in (0, 1)
    ] + [
        dict(mode=m, temp=1, submode=0, category=c, dc=0)
        for m in range(13) if m != 1 for c in (0, 1)
    ]

    traces = {}
    abi_cases = 0
    error_cases = 0

    modes_to_run = (
        ("stock", "ref_stock", 1, 0),
        ("modified13", "ref_m13", 1, 0),
        ("modified16", "m16_lossless_stock", 1, 0),
        ("modified16", "m16_uncomp_stock", 0, 0),
        ("modified16", "m16_jpeg_only_bypass", 2, 3),
        ("modified16", "m16_astro_raw_only", 2, 0),
        ("modified16", "m16_astro_raw_plus_jpeg", 2, 1),
    )

    for blob_key, label, v1315, v131b in modes_to_run:
        rig = Rig(blobs[blob_key], snap)
        u, p, g = rig.uc, rig.put, rig.get
        for addr, size in ((CAL + 0x100000, 0x68000), (ID35, 0x100000), (0x20061000, 0x1000)):
            u.mem_map(addr, size)
            rig.regions += ((addr, size),)
        writes = []

        def on_write(uc, kind, addr, size, value, _):
            writes.append((addr, size, value & ((1 << (size * 8)) - 1)))

        for lo, hi in ((0x20061000, 0x20061FFF), (0x20068000, 0x20069FFF)):
            u.hook_add(un.UC_HOOK_MEM_WRITE, on_write, begin=lo, end=hi)

        for idx, cfg in enumerate(configs):
            rig.reset(dict(scalar=1008, bank=0, cached=0))
            _set_astro_ram(rig, v1315, v131b)
            u.mem_write(CTX, ctx_bytes)
            u.mem_write(CAL, cal)
            u.mem_write(ID35, fixed)
            p(STATE + 0x18, ID35)
            p(CTX, cfg["mode"], "B")
            p(CTX + 0x84, cfg["temp"])
            p(CTX + 0x21, cfg["submode"], "B")
            p(CTX + 4, 192, "h")
            p(CTX + 8, 1536 if cfg["category"] else 1535, "i")
            p(CTX + 0xDC, cfg["dc"])
            writes.clear()
            rig.call(0x1011C750, [0, CTX], until=0x100CD752)
            rig.call(0x1011C3F4, [CTX])
            id35_w = list(writes)
            writes.clear()
            build = rig.call(START, until=0x1011D548)
            assert int(build["registers"]["r0"], 16) == 1
            cache_b = bytes(u.mem_read(0xC29A3230, 0x1000))
            pkt_b = bytes(u.mem_read(PKT, 0x60))
            rig.call(0x100BCCD0, [PKT])
            mmio_w = list(writes)
            assert len(mmio_w) == 507
            traces[label, idx] = (id35_w, cache_b, pkt_b, mmio_w)

        if label in ("m16_lossless_stock", "m16_astro_raw_only"):
            seen_dispatch = []
            inject_target = [None]
            inject_code = [0]

            def dispatch_stub(uc, pc, size, _):
                seen_dispatch.append(uc.reg_read(UC_ARM_REG_R0))
                uc.reg_write(UC_ARM_REG_R0, 0)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

            def err_stub(uc, pc, size, _):
                if inject_target[0] is not None and pc == inject_target[0]:
                    uc.reg_write(UC_ARM_REG_R0, inject_code[0])
                    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

            u.hook_add(un.UC_HOOK_CODE, dispatch_stub, begin=0x1011D548, end=0x1011D548)
            u.hook_add(un.UC_HOOK_CODE, err_stub)

            for temp in (0, 1):
                for flags in range(16):
                    rig.reset(dict(scalar=1008, bank=0, cached=0))
                    _set_astro_ram(rig, v1315, v131b)
                    u.mem_write(CTX, ctx_bytes)
                    p(CTX + 0x84, temp)
                    u.mem_write(CAL, cal)
                    p(STACK + 0xF000, 0x6A6A1122)
                    p(STACK + 0x100, 0x5566AA55)
                    saved = {r: 0x90101010 + r * 0x10101 for r in range(4, 12)}
                    u.reg_write(UC_ARM_REG_CPSR, (u.reg_read(UC_ARM_REG_CPSR) & 0x0FFFFFFF) | (flags << 28))
                    seen_dispatch.clear()
                    c_res = rig.call(START, regs=saved)
                    assert all(u.reg_read(REGS[r]) == v for r, v in saved.items())
                    assert u.reg_read(UC_ARM_REG_SP) == STACK + 0xF000
                    assert g(STACK + 0xF000) == 0x6A6A1122 and g(STACK + 0x100) == 0x5566AA55
                    assert seen_dispatch == [1] and int(c_res["registers"]["r0"], 16) == 0
                    abi_cases += 1

            for op_entry, err_val in ((0x1011D6B8, 0x4), (0x1011DB02, 0x80), (0x1011E940, 0x80000001), (0x1011EBB8, 0x10)):
                inject_target[0] = op_entry
                inject_code[0] = err_val
                rig.reset(dict(scalar=1008, bank=0, cached=0))
                _set_astro_ram(rig, v1315, v131b)
                u.mem_write(CTX, ctx_bytes)
                p(CTX + 0x84, 1)
                u.mem_write(CAL, cal)
                seen_dispatch.clear()
                c_res = rig.call(START)
                assert seen_dispatch == [1] and int(c_res["registers"]["r0"], 16) == err_val
                error_cases += 1
            inject_target[0] = None

        rig.uc = None
        del rig
        gc.collect()

    for idx in range(len(configs)):
        assert traces["m16_lossless_stock", idx] == traces["ref_stock", idx], f"Stock Lossless mismatch at {idx}"
        assert traces["m16_uncomp_stock", idx] == traces["ref_stock", idx], f"Stock Uncomp mismatch at {idx}"
        assert traces["m16_jpeg_only_bypass", idx] == traces["ref_stock", idx], f"JPEG-only bypass mismatch at {idx}"
        assert traces["m16_astro_raw_only", idx] == traces["ref_m13", idx], f"Astro RAW-only mismatch at {idx}"
        assert traces["m16_astro_raw_plus_jpeg", idx] == traces["ref_m13", idx], f"Astro RAW+JPEG mismatch at {idx}"

    return {
        "configs_per_mode": len(configs),
        "total_trace_executions": len(configs) * len(modes_to_run),
        "abi_nzcv_cases": abi_cases,
        "error_propagation_cases": error_cases,
        "exact_stock_parity_when_off_or_jpeg": True,
        "exact_m13_parity_when_astro_on": True,
    }


def run_dual_digital_gain_and_cal33_tests(blobs: dict[str, bytes], snap: dict, cal: bytes) -> dict:
    """Verify Site 8 (CAL33 0x1011e2dc) and Site 9 (digital gain 0x10122cbc) match Stock vs Modified13 dynamically."""
    vectors = [
        (None, 0),
        ([4096, 4096, 4096, 4096], 0x12),
        ([5305, 4176, 4180, 5171], 0x4D),
        ([8192, 4096, 4096, 2048], 0x00),
        ([1000, 2000, 3000, 4000], 0xFF),
    ]

    gain_results = {}
    for blob_key, label, v1315, v131b in (
        ("stock", "ref_stock", 1, 0),
        ("modified13", "ref_m13", 1, 0),
        ("modified16", "m16_stock_1", 1, 0),
        ("modified16", "m16_stock_0", 0, 0),
        ("modified16", "m16_jpg_bypass", 2, 3),
        ("modified16", "m16_astro_raw", 2, 0),
        ("modified16", "m16_astro_raw_jpg", 2, 1),
    ):
        rig = Rig(blobs[blob_key], snap)
        u = rig.uc
        PKT_BUF = 0xC29A3868
        DESC_PTR = 0xC29A34C0
        REC = RAM + 0x1000
        COEF = RAM + 0x1100
        u.mem_write(REC, struct.pack("<10H", *range(1, 11)))
        rows = []
        for coeffs, ctrl in vectors:
            _set_astro_ram(rig, v1315, v131b)
            u.mem_write(PKT_BUF, b"\xaa" * 32)
            u.mem_write(PKT_BUF, struct.pack("<4I", *([0xDEADBEEF] * 4)))
            r1_val = 0
            if coeffs is not None:
                r1_val = COEF
                u.mem_write(COEF, struct.pack("<4I", *coeffs))
            u.reg_write(UC_ARM_REG_R0, REC)
            u.reg_write(UC_ARM_REG_R1, r1_val)
            u.reg_write(UC_ARM_REG_R2, ctrl)
            u.reg_write(UC_ARM_REG_SP, STACK + 0xF000)
            u.reg_write(UC_ARM_REG_LR, STOP | 1)
            u.emu_start(0x10122CA2 | 1, STOP)
            assert struct.unpack("<I", u.mem_read(DESC_PTR + 0x38, 4))[0] == PKT_BUF
            rows.append(bytes(u.mem_read(PKT_BUF, 32)))
        gain_results[label] = rows
        rig.uc = None
        del rig
        gc.collect()

    assert gain_results["m16_stock_1"] == gain_results["ref_stock"]
    assert gain_results["m16_stock_0"] == gain_results["ref_stock"]
    assert gain_results["m16_jpg_bypass"] == gain_results["ref_stock"]
    assert gain_results["m16_astro_raw"] == gain_results["ref_m13"]
    assert gain_results["m16_astro_raw_jpg"] == gain_results["ref_m13"]
    assert gain_results["ref_stock"] != gain_results["ref_m13"]

    # CAL33 Group Selector (0x1011e2ce)
    def eval_cal33(blob: bytes, v1315: int, v131b: int, is_still: bool, mode_byte: int = 0) -> bytes:
        rig = Rig(blob, snap)
        u = rig.uc
        u.mem_map(CAL + 0x100000, 0x100000)
        rig.regions += ((CAL + 0x100000, 0x100000),)
        u.mem_write(CAL, cal)
        _set_astro_ram(rig, v1315, v131b)
        TABLE_BUF = 0xC29A3BE0
        u.mem_write(CTX, b"\x00" * 0x100)
        u.mem_write(STATE + 0x14, struct.pack("<I", CAL))
        u.mem_write(PKT, b"\x00" * 0x100)
        u.mem_write(TABLE_BUF, b"\x00" * 300)
        if is_still:
            u.mem_write(CTX + 0x84, struct.pack("<I", 1))
            u.mem_write(CTX + 0xDC, struct.pack("<I", 1))
        else:
            u.mem_write(CTX + 0x0, struct.pack("B", mode_byte))
            u.mem_write(CTX + 0x84, struct.pack("<I", 0))
            u.mem_write(CTX + 0xDC, struct.pack("<I", 1))
        u.reg_write(UC_ARM_REG_R0, CTX)
        u.reg_write(UC_ARM_REG_SP, STACK + 0xF000)
        u.reg_write(UC_ARM_REG_LR, STOP | 1)
        u.emu_start(0x1011E2CE | 1, STOP)
        res = bytes(u.mem_read(TABLE_BUF, 264))
        rig.uc = None
        del rig
        return res

    ref_still_stock = eval_cal33(blobs["stock"], 1, 0, True)
    ref_still_m13 = eval_cal33(blobs["modified13"], 1, 0, True)
    assert ref_still_stock != ref_still_m13
    assert struct.unpack("<132H", ref_still_m13) == (16384,) * 132

    assert eval_cal33(blobs["modified16"], 1, 0, True) == ref_still_stock
    assert eval_cal33(blobs["modified16"], 0, 0, True) == ref_still_stock
    assert eval_cal33(blobs["modified16"], 2, 3, True) == ref_still_stock
    assert eval_cal33(blobs["modified16"], 2, 0, True) == ref_still_m13
    assert eval_cal33(blobs["modified16"], 2, 1, True) == ref_still_m13

    for mb in range(14):
        s_non = eval_cal33(blobs["stock"], 1, 0, False, mb)
        assert eval_cal33(blobs["modified16"], 1, 0, False, mb) == s_non
        assert eval_cal33(blobs["modified16"], 2, 0, False, mb) == s_non

    gc.collect()
    return {
        "digital_gain_exact_stock_and_m13_parity": True,
        "cal33_still_stock_group0_and_astro_group4_unity": True,
        "cal33_non_still_modes_0_to_13_unchanged": True,
    }


def run_dual_backend_spatial_and_raw_preserve_tests(blobs: dict[str, bytes], snap: dict) -> dict:
    """Verify Sites 1..7 & 11..13 (dark preserve, vignette, spatial17, fullsize front RAW) in Stock vs Astro mode."""
    coefs = [2122853, -1812904, 1751073, 0]
    spatial = [142, -79, 0, -74, -6, 61]
    cfgs = [
        dict(cached=c, bank=b, slot=s, cache_flags=f, size=sz)
        for c, b, s, f, sz in itertools.product((0, 1), (0, 1), (0, 1), ([0, 1], [1, 1]), (0, 1))
    ]

    chain_traces = {}
    for blob_key, label, v1315, v131b in (
        ("stock", "ref_stock", 1, 0),
        ("modified13", "ref_m13", 1, 0),
        ("modified16", "m16_stock_1", 1, 0),
        ("modified16", "m16_jpg_bypass", 2, 3),
        ("modified16", "m16_astro_on", 2, 0),
    ):
        rig = Rig(blobs[blob_key], snap)
        u, p, g = rig.uc, rig.put, rig.get
        rows = []
        for cfg in cfgs:
            seed(rig, dict(cached=cfg["cached"], strength=2, owner_neutral=0, bank=cfg["bank"]), coefs, spatial)
            _set_astro_ram(rig, v1315, v131b)
            p(OWNER + 0x192, cfg["size"], "B")
            p(OWNER + 0x308 + 0x26, 256, "H")
            u.mem_write(OWNER + 0x308 + 0x28, struct.pack("<9H", *([256] * 9)))
            u.mem_write(OWNER + 0x308 + 0x3A, struct.pack("<4H", *([512] * 4)))
            u.mem_write(OWNER + 0x308 + 0x42, struct.pack("<5HB", 300, 300, 300, 300, 32000, 0))
            u.mem_write(OWNER + 0x378, struct.pack("<4B6i", *cfg["cache_flags"], 0, 0, *spatial))
            p(OWNER + 0x227C + 0x5A, 0, "B")
            p(P_REQ, FRAME)
            p(P_REQ + 4, CACHE)
            if cfg["cached"]:
                p(P_REQ + 8, OWNER + 0x308)
                p(P_REQ + 12, OWNER + 0x342)
                p(P_REQ + 16, OWNER + 0x34A)
            u.mem_write(P_REQ + 0x14, struct.pack("<2H", 6064, 4040))
            p(P_REQ + 0x18, 1)
            p(P_REQ + 0x1C, 0)
            p(P_REQ + 0x20, 0, "B")
            p(P_REQ + 0x21, cfg["cached"], "B")
            u.mem_write(P_OUT, struct.pack("<4I", STAGE + 0x3E8, STAGE + 0x468, OWNER + 0x85C, 0))
            for ptr, n in ((STAGE + 0x3E8, 0x34), (STAGE + 0x468, 0x6C), (SPATIAL, 68)):
                u.mem_write(ptr, b"\x6b" * n)

            rig.call(0x100C24D4, [P_REQ, P_OUT])
            for off, val in (
                (4, CACHE),
                (8, OWNER + 0x308 if cfg["cached"] else 0),
                (12, OWNER + 0x342 if cfg["cached"] else 0),
                (16, OWNER + 0x34A if cfg["cached"] else 0),
                (20, STAGE + 0x3E8),
                (24, STAGE + 0x468),
                (36, 1),
                (40, 0),
            ):
                p(MAINREQ + off, val)
            p(MAINREQ + 0x2E, cfg["cached"], "B")
            rig.call(0x100C2824, [MAINREQ, VECTOR])
            if not cfg["cached"]:
                p(OWNER + 0x227C, 0, "B")
            rig.call(0x100C29C6, [VREQ, VOUT])

            p(FLAGS + 0x2C, cfg["slot"], "B")
            for off, val in ((0, FLAGS), (4, SPATIAL), (8, 0), (12, MIXED), (20, TCTX)):
                p(VREQ + off, val)
            p(VREQ + 16, 1, "B")
            p(VREQ + 17, 0, "B")
            p(AUX, TABLES)
            p(AUX + 4, AUX + 0x100)
            p(AUX + 8, AUX + 0x200)
            rig.call(0x10171DBC, [VREQ, HISTORY, AUX])
            rig.call(0x100AE33E, [STAGE], until=0x100B4C78)
            rig.call(0x100B5716, [REQ, PACKET, STORAGE])
            bank = MMIO + cfg["bank"] * 0x40000
            u.mem_write(bank + 0x1200, b"\x5a" * 72)
            rig.call(0x100D5C86, [DRIVER, PACKET, 0, 0])
            rig.call(0x10305628)
            tag6, _ = serialize(rig, 6)
            tag7, _ = serialize(rig, 7)
            rig.call(0x100AE41E, until=0x100AE438, regs={4: FRAME, 5: REQ})
            enc = rig.call(0x100AF648, [STAGE], until=0x100A323E)

            selected_slot = 0x2A94 if cfg["slot"] else 0x2890
            rows.append(
                (
                    g(bank + 0x580),
                    g(bank + 0x584),
                    g(bank + 0x594),
                    g(bank + 0x67C),
                    bytes(u.mem_read(CURVE, 514)),
                    bytes(u.mem_read(bank + selected_slot, 516)),
                    bytes(u.mem_read(bank + 0x1200, 72)),
                    bytes(u.mem_read(OWNER + 0x1014, 18)),
                    tag6,
                    tag7,
                    g(REQ + 0x1A8),
                    g(FRAME + 0x1F8),
                    enc["registers"]["r0"],
                )
            )
        chain_traces[label] = rows
        rig.uc = None
        del rig
        gc.collect()

    assert chain_traces["m16_stock_1"] == chain_traces["ref_stock"], "Backend/spatial Stock mode diverged from Stock C3.80!"
    assert chain_traces["m16_jpg_bypass"] == chain_traces["ref_stock"], "Backend/spatial JPEG-only bypass diverged from Stock C3.80!"
    assert chain_traces["m16_astro_on"] == chain_traces["ref_m13"], "Backend/spatial Astro mode diverged from Modified13!"
    assert chain_traces["ref_stock"] != chain_traces["ref_m13"]

    return {
        "configs_per_mode": len(cfgs),
        "total_chain_executions": len(cfgs) * 5,
        "exact_stock_parity_when_off_or_jpeg": True,
        "exact_m13_parity_when_astro_on": True,
    }


def run_lossless_coercion_and_ui_string_tests(blobs: dict[str, bytes], snap: dict) -> dict:
    """Verify all 5 Lossless NEF coercion hooks (buffer size, codec, EXIF, owner, IPC) + 36-lang UI strings."""
    # 1. Buffer size & Hardware Codec coercion (0x101254bc + 0x100af648 + 0x101ca6c6 + 0x10108f8a)
    rig_s = Rig(blobs["stock"], snap)
    rig_m = Rig(blobs["modified16"], snap)
    for r in (rig_s, rig_m):
        r.uc.mem_map(rel.CODEC_MMIO, 4096)

    ALLOC = RAM + 0x45000
    MAPPED = RAM + 0x46000
    CODEC_CTX = RAM + 0x47000
    codec_cases = 0

    for area in (0, 1):
        for depth, wide in ((0, 0), (1, 0), (1, 1)):
            for size in (0, 1, 2):
                def _run_enc(rig: Rig, mode_in: int, astro_on: bool) -> dict:
                    rig.reset(dict(scalar=300, bank=0, cached=0, owner_mode=1))
                    _set_astro_ram(rig, 2 if astro_on else mode_in, 0)
                    u, p, g = rig.uc, rig.put, rig.get
                    for off, val in (
                        (0x88, 0),
                        (0x170, area),
                        (0x190, 1),
                        (0x192, size),
                        (0x194, mode_in),
                        (0x195, depth),
                        (0x252, wide),
                        (0x2811, 0),
                    ):
                        p(OWNER + off, val, "B")
                    p(OWNER + 0x1AF0, 0)
                    pre = rig.call(0x10124196, until=0x100D8868, regs={4: OWNER, 5: 2, 6: RAM + 0x48000})
                    fmt = int(pre["registers"]["r5"], 16)
                    cap = int(pre["registers"]["r2"], 16)
                    for h, ad, base_a in ((INPUT, ALLOC, 0x60000000), (OUTPUT, ALLOC + 0x20, 0x64000000), (ENCODED, ALLOC + 0x40, 0x68000000)):
                        p(h + 4, ad)
                        p(ad, base_a)
                        p(ad + 4, cap)
                    rig.call(0x10123E70, [INPUT, OWNER, fmt])
                    rig.call(0x10124224, [OUTPUT, OWNER])
                    rig.call(0x101254BC, [ENCODED, OWNER])
                    enc_mode_byte = g(ENCODED + 0x50, "B")
                    enc_buf_cap = g(ENCODED + 0x5C)  # bitstream allocation / stride metadata
                    encoded_snap = bytes(u.mem_read(ENCODED, 0x120))
                    rig.call(0x100AE33E, [STAGE], until=0x100B4C78)
                    rig.call(0x100AE41E, until=0x100AE438, regs={4: FRAME, 5: REQ})
                    queue = 0x101CAB2E if enc_mode_byte == 0 else 0x101CAAD8
                    rig.call(0x100AF648, [STAGE], until=queue)
                    codec_lossless_flag = g(rel.GLOBAL, "B") if enc_mode_byte != 0 else None
                    mmio_bytes = None
                    if enc_mode_byte != 0:
                        u.mem_write(rel.CODEC_MMIO, bytes(4096))
                        p(rel.CONTEXT + 0xC, rel.GLOBAL)
                        rig.call(0x101CA6C6, [MAPPED])
                        rig.call(0x10108F8A, [CODEC_CTX, MAPPED])
                        mmio_bytes = bytes(u.mem_read(rel.CODEC_MMIO, 0x100))
                    return {
                        "enc_mode": enc_mode_byte,
                        "owner_194_after": g(OWNER + 0x194, "B"),
                        "encoded_desc": encoded_snap,
                        "selected_handle": g(FRAME + 0x1F8),
                        "codec_lossless_flag": codec_lossless_flag,
                        "mmio": mmio_bytes,
                        "buf_cap_5c": enc_buf_cap,
                    }

                stock_lossless = _run_enc(rig_s, 1, False)
                stock_lossy = _run_enc(rig_s, 2, False)
                stock_uncomp = _run_enc(rig_s, 0, False)

                m16_lossless = _run_enc(rig_m, 1, False)
                m16_astro = _run_enc(rig_m, 2, size == 0)
                m16_uncomp = _run_enc(rig_m, 0, False)

                # Stock Lossy uses codec_lossless_flag == 0, whereas Stock Lossless uses 1!
                assert stock_lossless["codec_lossless_flag"] == 1 and stock_lossy["codec_lossless_flag"] == 0
                # Modified16 mode=1 and mode=0 are 100% identical to Stock!
                assert m16_lossless == stock_lossless
                assert m16_uncomp == stock_uncomp
                # Modified16 mode=2 (Astro Lossless) coerces owner+0x194 -> 1, enc_mode -> 1,
                # allocates IDENTICAL encoded_desc (including Lossless buffer size!) to Stock Lossless,
                # and drives hardware codec in genuine Lossless mode (codec_lossless_flag == 1)!
                assert m16_astro["enc_mode"] == 1 and m16_astro["owner_194_after"] == 1
                assert m16_astro["encoded_desc"] == stock_lossless["encoded_desc"]
                assert m16_astro["codec_lossless_flag"] == 1
                assert m16_astro["mmio"] == stock_lossless["mmio"]
                assert m16_astro["selected_handle"] == (INPUT if size == 0 else OUTPUT)
                codec_cases += 1

    # 2. Test EXIF MakerNote 0x0093 NEFCompression at 0x1028d2c8..0x1028d2ea
    exif_cases = 0
    EXIF_OWNER = RAM + 0x49000
    for comp_in, depth_in, exp_exif in (
        (1, 1, 3),   # Lossless 14-bit -> 3 (Lossless)
        (2, 1, 3),   # Astro Lossless 14-bit -> 3 (Lossless, coerced from 4!)
        (2, 0, 3),   # Astro Lossless 12-bit -> 3 (Lossless, coerced from 4!)
        (0, 1, 10),  # Uncompressed 14-bit -> 10 (Packed/Uncomp 14-bit)
        (0, 0, 6),   # Uncompressed 12-bit -> 6 (Uncompressed)
    ):
        _reset_rig(rig_m)
        rig_m.put(EXIF_OWNER + 0x194, comp_in, "B")
        rig_m.put(EXIF_OWNER + 0x195, depth_in, "B")
        res = rig_m.call(0x1028D2C8, until=0x1028D22E, regs={6: EXIF_OWNER})
        got_exif = int(res["registers"]["r0"], 16)
        assert got_exif == exp_exif, f"EXIF NEFCompression({comp_in},{depth_in}) -> {got_exif} != {exp_exif}"
        exif_cases += 1

    # 3. Test 0x10312c24 main capture owner+0x194 coercion + APSR flag preservation
    SRC_4C = RAM + 0x49200
    DST_OWN = RAM + 0x49400
    for comp_in, exp_out in ((0, 0), (1, 1), (2, 1)):
        for flags in range(16):
            _reset_rig(rig_m)
            rig_m.put(SRC_4C + 0x4C, comp_in, "B")
            rig_m.put(DST_OWN + 0x194, 0xAA, "B")
            cpsr_in = (rig_m.uc.reg_read(UC_ARM_REG_CPSR) & 0x0FFFFFFF) | (flags << 28)
            rig_m.uc.reg_write(UC_ARM_REG_CPSR, cpsr_in)
            rig_m.call(0x10312C24, until=0x10312C2C, regs={0: SRC_4C, 5: DST_OWN})
            assert rig_m.get(DST_OWN + 0x194, "B") == exp_out
            assert (rig_m.uc.reg_read(UC_ARM_REG_CPSR) >> 28) == flags, "0x10312c24 clobbered APSR flags!"

    # 4. Test 0x10142396 & 0x10144c30 property getter coercion (stubbing 0x10164bfa)
    prop_ret_val = [0]

    def stub_164bfa(uc, pc, size, _):
        uc.reg_write(UC_ARM_REG_R0, prop_ret_val[0])
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    rig_m.uc.hook_add(un.UC_HOOK_CODE, stub_164bfa, begin=0x10164BFA, end=0x10164BFA)
    for raw_v, exp_v in ((0, 0), (1, 1), (2, 1)):
        prop_ret_val[0] = raw_v
        # Test 0x10144c2c..0x10144c38: writes [sp, #6]
        _reset_rig(rig_m)
        rig_m.call(0x10144C2C, until=0x10144C38)
        assert rig_m.get(STACK + 0xF000 + 6, "B") == exp_v
        # Test 0x10142392..0x101423a2: writes [r4->0x3a4 + 0x194]
        _reset_rig(rig_m)
        rig_m.put(FRAME + 0x3A4, DST_OWN)
        rig_m.put(DST_OWN + 0x194, 0xEE, "B")
        rig_m.call(0x10142392, until=0x101423A2, regs={4: FRAME})
        assert rig_m.get(DST_OWN + 0x194, "B") == exp_v

    # 5. Verify SD Lossy NEF Playback / Retouch code (0x102dd088..0x102dd184) & U1/U2/U3 Save/Load (0x103c68ce) are untouched Stock
    for untouched_va, span_n in ((0x102DD088, 0xFC), (0x103C68CE, 0x10)):
        off = untouched_va - BASE
        assert blobs["modified16"][off : off + span_n] == blobs["stock"][off : off + span_n]

    # 6. Native UI Localized String Resolver 0x104c0104 across ALL 36 languages (0..35)
    ui_global_ptr = struct.unpack_from("<I", blobs["stock"], 0x104C0224 - BASE)[0] - 0x1C
    ui_page = ui_global_ptr & ~0xFFF
    for r in (rig_s, rig_m):
        r.put(ui_global_ptr + 0x0, 0x112C2A98)   # pool_tbl
        r.put(ui_global_ptr + 0x8, 0x112C2A08)   # idx_tbl
        r.put(ui_global_ptr + 0x14, 2291)        # string count limit for 0x104bfe34

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
        _, l_len, l_txt = resolve_ui_str(rig_m, lang, UI_STR_ID_LABEL)
        _, h_len, h_txt = resolve_ui_str(rig_m, lang, UI_STR_ID_HELP)
        if lang == LANG_ZH_CN:
            assert l_txt == LABEL_ZH_CN and l_len == len(LABEL_ZH_CN.encode("utf-16le"))
            assert h_txt == HELP_ZH_CN and h_len == len(HELP_ZH_CN.encode("utf-16le"))
        elif lang == LANG_ZH_TW:
            assert l_txt == LABEL_ZH_TW and l_len == len(LABEL_ZH_TW.encode("utf-16le"))
            assert h_txt == HELP_ZH_TW and h_len == len(HELP_ZH_TW.encode("utf-16le"))
        else:
            assert l_txt == LABEL_EN and l_len == len(LABEL_EN.encode("utf-16le"))
            assert h_txt == HELP_EN and h_len == len(HELP_EN.encode("utf-16le"))

        # Neighbor string IDs (Lossless compressed 0x0363, 12-bit 0x0365, Lossless help 0x057d, Uncomp help 0x057f)
        # must match Stock C3.80 pointer-for-pointer and byte-for-byte!
        for neighbor_sid in (0x0363, 0x0365, 0x057D, 0x057F):
            assert resolve_ui_str(rig_m, lang, neighbor_sid) == resolve_ui_str(rig_s, lang, neighbor_sid)
            ui_checks += 1
        ui_checks += 2

    rig_s.uc = None
    rig_m.uc = None
    del rig_s, rig_m
    gc.collect()

    return {
        "lossless_codec_and_buffer_cases": codec_cases,
        "exif_makernote_0x0093_cases": exif_cases,
        "owner_and_ipc_coercion_verified": True,
        "sd_lossy_playback_and_u1_u3_untouched": True,
        "ui_36_languages_string_checks": ui_checks,
        "sample_labels": {"zh_cn": LABEL_ZH_CN, "zh_tw": LABEL_ZH_TW, "en": LABEL_EN},
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--candidate",
        type=Path,
        default=ROOT / "analysis/modified16-preflash-2026-11-15/lab-build/modified16-candidate.bi",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified16-preflash-2026-11-15/native-probe",
    )
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    stock = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()
    m10 = (ROOT / "outputs/Z6-C380-modified10-reviewed-2026-11-13/01_TEST_MODIFIED10/EG162080.BIN").read_bytes()
    m12 = (ROOT / "outputs/Z6-C380-modified12-reviewed-2026-11-14/01_TEST_MODIFIED12/EG162080.BIN").read_bytes()
    m13 = (ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN").read_bytes()
    m14 = (ROOT / "analysis/modified14-preflash-2026-11-14/lab-build/modified14-candidate.bi").read_bytes()
    m15 = (ROOT / "outputs/Z6-C380-modified15-reviewed-2026-11-15/01_TEST_MODIFIED15/EG162080.BIN").read_bytes()
    m16 = args.candidate.read_bytes()

    assert sha(stock) == STOCK_SHA
    assert sha(m10) == M10_SHA
    assert sha(m12) == M12_SHA
    assert sha(m13) == M13_SHA
    assert sha(m14) == M14_SHA
    assert sha(m15) == M15_SHA
    assert sha(m16) == M16_SHA

    blobs = {"stock": stock, "modified10": m10, "modified12": m12, "modified13": m13, "modified15": m15, "modified16": m16}
    snap = json.loads((ROOT / "analysis/raw-vignette-state-2026-11-08/native-selector/result.json").read_text(encoding="utf8"))["final"]
    cal = (ROOT / "analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/CAL38.bin").read_bytes()
    fixed = (ROOT / "analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/ID35.bin").read_bytes()
    ev = json.loads((ROOT / "analysis/raw-front-calibration-2026-11-09/native-calibration-watch/events.json").read_text(encoding="utf8"))
    ctx_bytes = bytes.fromhex(next(e for e in ev if e["event"] == "static_front_builder")["memory"]["context"]["bytes"])
    _, syms = build_astro_ui_cave()

    print("1/6 Running 0x1315 native derived property builder & dynamic predicate matrix...")
    pred_res = run_predicate_and_0x1315_builder_tests(m16, snap, syms)

    print("2/6 Running dual-path frontend 2D polynomial sanitizer & 507-MMIO parity suite...")
    front_res = run_dual_frontend_sanitizer_tests(blobs, snap, cal, fixed, ctx_bytes)

    print("3/6 Running dual-path digital gain (0x10122cbc) & CAL33 Group 4 (0x1011e2dc) parity suite...")
    gain_cal_res = run_dual_digital_gain_and_cal33_tests(blobs, snap, cal)

    print("4/6 Running dual-path backend dark preserve, vignette, spatial17 & front RAW handle suite...")
    back_res = run_dual_backend_spatial_and_raw_preserve_tests(blobs, snap)

    print("5/6 Running Lossless NEF coercion (buffer/codec/EXIF/owner/IPC) & 36-language UI string suite...")
    ui_lossless_res = run_lossless_coercion_and_ui_string_tests(blobs, snap)

    print("6/6 Running permanent 30-600s v2 extended shutter E2E + Modified14 negative-control suite...")
    m600_res = run_all_m600_v2_tests(m16, m14)

    report = {
        "ok": True,
        "candidate": "modified16",
        "sha256": M16_SHA,
        "parent_modified15_sha256": M15_SHA,
        "reference_modified13_sha256": M13_SHA,
        "predicate_and_0x1315_builder": pred_res,
        "dual_frontend_sanitizer": front_res,
        "dual_digital_gain_and_cal33": gain_cal_res,
        "dual_backend_spatial_and_raw_preserve": back_res,
        "lossless_coercion_and_36lang_ui": ui_lossless_res,
        "permanent_m600_v2_extended_shutter": m600_res,
    }
    out_file = args.output / "native_report.json"
    out_file.write_text(json.dumps(report, indent=2), encoding="utf8")
    (args.output / "probe_modified16_native.py").write_bytes(Path(__file__).read_bytes())
    print(f"Modified16 native verification PASSED -> {out_file}")


if __name__ == "__main__":
    main()

"""Comprehensive Unicorn ARM/Thumb native verification for Modified18 (Design A1: Color Space Switchable Astro RAW + Permanent 30-600s v2)."""
from __future__ import annotations
import argparse
import gc
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
    BASE,
    RAM,
    Rig,
    sha,
)
from z6_astro_ui_color_space import (
    ADDR_M18_CAVE,
    ADDR_M9_SANITIZER,
    HELP_EN,
    HELP_ZH_CN,
    HELP_ZH_TW,
    LABEL_EN,
    LABEL_ZH_CN,
    LABEL_ZH_TW,
    LANG_ZH_CN,
    LANG_ZH_TW,
    RAM_PROP_0508,
    RAM_PROP_131B,
    UI_STR_ID_HELP,
    UI_STR_ID_LABEL,
)

ROOT = THIS_DIR.parents[1]


def _reset_rig(rig: Rig) -> None:
    rig.uc.reg_write(UC_ARM_REG_CPSR, 0x20)  # Thumb mode
    rig.uc.reg_write(UC_ARM_REG_SP, RAM + 0x30000)
    rig.uc.reg_write(UC_ARM_REG_LR, 0x10020001)


def _set_astro_ram(rig: Rig, color_space: int, effective_rec: int) -> None:
    rig.put(RAM_PROP_0508, color_space, "B")
    rig.put(RAM_PROP_131B, effective_rec)


def run_predicate_tests(m18: bytes, snap: dict, syms: dict[str, int]) -> dict:
    """Verify fn_is_astro_r0 gate matrix across Color space in {0,1,2} and 0x131b in {0,1,2,3,0xff}."""
    rig = Rig(m18, snap)
    fn_addr = syms["fn_is_astro_r0"]
    pred_cases = 0

    for cs in (0, 1, 2):
        for rec in (0, 1, 2, 3, 0xFF):
            _reset_rig(rig)
            _set_astro_ram(rig, cs, rec)
            res = rig.call(fn_addr)
            got = int(res["registers"]["r0"], 16)
            # Active iff Color space == 1 AND recording format <= 1 (RAW or RAW+JPEG)
            exp = 1 if (cs == 1 and rec in (0, 1)) else 0
            assert got == exp, f"fn_is_astro_r0(cs={cs}, rec={rec}) -> {got} != {exp}"
            pred_cases += 1

    rig.uc = None
    del rig
    gc.collect()
    return {"predicate_matrix_cases": pred_cases}


def run_color_space_srgb_lock_tests(m18: bytes, snap: dict) -> dict:
    """Verify 0x1040AD00 (IsColorSpace_sRGB) unconditionally returns 1 to keep DSC_xxxx prefix & sRGB EXIF."""
    rig = Rig(m18, snap)
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


def run_ui_string_tests(blobs: dict[str, bytes], snap: dict, syms: dict[str, int]) -> dict:
    """Verify GetLanguageString (0x104C0104) across ALL 36 languages overrides 0x03B5 & 0x082C, leaving neighbors untouched."""
    rig_s = Rig(blobs["stock"], snap)
    rig_m = Rig(blobs["m18"], snap)

    ui_ptr_resolver = struct.unpack_from("<I", blobs["stock"], 0x104C0224 - BASE)[0] - 0x1C
    ui_ptr_limit    = struct.unpack_from("<I", blobs["stock"], 0x104C0220 - BASE)[0]
    for r in (rig_s, rig_m):
        r.put(ui_ptr_resolver + 0x0, 0x112C2A98)   # pool_tbl
        r.put(ui_ptr_resolver + 0x8, 0x112C2A08)   # idx_tbl
        r.put(ui_ptr_limit + 0x14, 2291)          # string count limit for 0x104bfe34

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

        # Neighbor string IDs (sRGB 0x03B4, sRGB help 0x082B) must match Stock C3.80 pointer-for-pointer!
        for neighbor_sid in (0x03B4, 0x082B):
            assert resolve_ui_str(rig_m, lang, neighbor_sid) == resolve_ui_str(rig_s, lang, neighbor_sid)
            ui_checks += 1
        ui_checks += 2

    rig_s.uc = None
    rig_m.uc = None
    del rig_s, rig_m
    gc.collect()
    return {"ui_36_languages_string_checks": ui_checks}


def run_dual_branch_trampoline_tests(blobs: dict[str, bytes], snap: dict, syms: dict[str, int]) -> dict:
    """Verify the dual-branch trampolines execute Stock target when cs=0 and Astro target when cs=1."""
    m18 = blobs["m18"]
    rig = Rig(m18, snap)
    u = rig.uc
    tramp_cases = 0

    # 1. Tramp 0x100ae3a4 (fullsize raw preserve) -> 0x101BA474 (Stock) vs 0x101BA4B6 (Astro)
    for cs, exp_target in [(0, 0x101BA474), (1, 0x101BA4B6)]:
        _reset_rig(rig)
        _set_astro_ram(rig, cs, 0)
        rig.call(syms["tramp_ae3a4"], args=[0x1234, 0x5678, 0x9ABC], until=exp_target)
        assert u.reg_read(UC_ARM_REG_PC) == exp_target, f"Tramp ae3a4 did not branch to {exp_target:#x}"
        assert u.reg_read(UC_ARM_REG_R0) == 0x1234
        assert u.reg_read(UC_ARM_REG_R1) == 0x5678
        assert u.reg_read(UC_ARM_REG_R2) == 0x9ABC
        tramp_cases += 1

    # 2. Tramp 0x100c28b2 (vignette neutral site 1) -> 0x100C28B6
    #    Executes `strb.w r0, [r4, #0x62]` (Stock) vs `strb.w sb, [r4, #0x62]` (Astro)
    DUMMY_OWNER = RAM + 0x20000
    for cs in (0, 1):
        _reset_rig(rig)
        _set_astro_ram(rig, cs, 0)
        TARGET = 0x100C28B6
        rig.call(syms["tramp_c28b2"], regs={4: DUMMY_OWNER, 9: 0x55}, until=TARGET)
        assert u.reg_read(UC_ARM_REG_PC) == TARGET
        val_written = u.mem_read(DUMMY_OWNER + 0x62, 1)[0]
        # When cs=0 (Stock), writes r0 (0); when cs=1 (Astro), writes sb/r9 (0x55)
        assert val_written == (0x55 if cs == 1 else 0)
        tramp_cases += 1

    # 3. Tramp 0x1017d834 (frontend sanitizer) -> 0x1011D548 (Stock) vs 0x1002D884 (Astro)
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


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "analysis/modified18-preflash-2026-11-15/lab-build/modified18-manifest.json",
    )
    args = ap.parse_args()

    manifest_p = args.manifest.resolve()
    assert manifest_p.is_file(), f"Missing manifest: {manifest_p}"
    manifest = json.loads(manifest_p.read_text(encoding="utf-8"))

    m18_bi = manifest_p.parent / "modified18-candidate.bi"
    m18_bytes = m18_bi.read_bytes()
    stock_bytes = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()

    syms = {k: int(v, 16) for k, v in manifest["cave_symbols"].items()}
    snap_p = ROOT / "analysis/modified16-preflash-2026-11-15/native-probe/probe-snap.json"
    if not snap_p.is_file():
        snap_p = ROOT / "analysis/modified15-preflash-2026-11-15/native-probe/probe-snap.json"
    snap = json.loads(snap_p.read_text(encoding="utf-8")) if snap_p.is_file() else {}

    print("Running Modified18 Native ARM/Thumb Unicorn Verification...")

    # 1. Predicate matrix
    res_pred = run_predicate_tests(m18_bytes, snap, syms)
    print(f"  [PASS] Predicate Matrix ({res_pred['predicate_matrix_cases']} cases)")

    # 2. sRGB lock tests
    res_lock = run_color_space_srgb_lock_tests(m18_bytes, snap)
    print(f"  [PASS] sRGB Color/EXIF Safety Lock ({res_lock['srgb_lock_cases']} cases)")

    # 3. UI String override tests across all 36 languages
    blobs = {"m18": m18_bytes, "stock": stock_bytes}
    res_ui = run_ui_string_tests(blobs, snap, syms)
    print(f"  [PASS] Localized UI String Override ({res_ui['ui_36_languages_string_checks']} checks across all 36 languages)")

    # 4. Trampoline tests
    res_tramp = run_dual_branch_trampoline_tests(blobs, snap, syms)
    print(f"  [PASS] Dual-Branch RAW Trampolines ({res_tramp['dual_branch_trampoline_cases']} cases)")

    out_json = manifest_p.parent / "probe_modified18_native_result.json"
    report = {
        "candidate": manifest["candidate"],
        "design": manifest["design"],
        "modified18_sha256": manifest["modified18_sha256"],
        "tests": {
            **res_pred,
            **res_lock,
            **res_ui,
            **res_tramp,
        },
        "verdict": "100% PASS",
    }
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nAll Unicorn ARM/Thumb Native Tests Passed! Saved report to: {out_json}")


if __name__ == "__main__":
    main()

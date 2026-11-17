"""Unicorn native emulation probe for Modified21.

Verifies:
  1. End-to-end native Menu mapping (0x1033F75E @ 0x115501AC) -> native GetProperty (0x100700A0)
     RAM slot discovery -> fn_is_astro_r0 predicate matrix, plus direct reproduction of Modified20's
     0xC24CDDC4 bug vs Modified21's 0xC24CDE28 fix.
  2. Native Photo-mode Effective Color Space evaluator (0x1014F638) locking 0x1381 = 0 (sRGB) across
     all exposure modes while keeping 0x0508 = 0/1 intact, plus 0x1040AD00 sRGB lock.
  3. All 13 patched Astro RAW firmware hook sites (26 dual-branch Stock vs Astro paths + NZCV/register
     preservation).
  4. 36-language GetLanguageString (0x104C0104) verification for '标准 (sRGB)' / '直通RAW (sRGB)'
     wording + 5 untouched neighbor String IDs (360 checks).
  5. Post-exposure Interval Timer sequences & 37-case native End day/time (0x1049C19A) matrix.
"""
from __future__ import annotations
import argparse
import gc
import json
import struct
from pathlib import Path
import sys

from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_MODE_THUMB
from unicorn.arm_const import (
    UC_ARM_REG_CPSR,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R6,
    UC_ARM_REG_R9,
    UC_ARM_REG_SP,
)

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from probe_modified20_native import run_interval_endtime_tests, run_interval_timer_tests
from probe_raw_candidates import BASE, RAM, Rig
from z6_astro_ui_color_space_v2 import (
    ADDR_M9_SANITIZER,
    LANG_ZH_CN,
    LANG_ZH_TW,
    RAM_PROP_0508,
    RAM_PROP_0508_REAL,
    RAM_PROP_131B,
    RAM_PROP_1381,
    UI_OVERRIDES_M21,
)

ROOT = THIS_DIR.parents[1]


def _reset_rig(rig: Rig) -> None:
    rig.uc.reg_write(UC_ARM_REG_CPSR, 0x20)
    rig.uc.reg_write(UC_ARM_REG_SP, RAM + 0x30000)
    rig.uc.reg_write(UC_ARM_REG_LR, 0x10020001)


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


def run_e2e_predicate_and_regression_tests(
    m21: bytes, m20: bytes, snap: dict, syms21: dict[str, int], syms20: dict[str, int]
) -> dict:
    rig = Rig(m21, snap)
    for m_addr in range(0xC2400000, 0xC2600000, 0x100000):
        try:
            rig.uc.mem_map(m_addr, 0x100000)
        except Exception:
            pass

    # 1. Discover genuine RAM addresses via native 0x100700A0 (never trust Python constants blindly!)
    native_0508_ram = _discover_native_prop_ram(rig, 0x0508)
    native_131b_ram = _discover_native_prop_ram(rig, 0x131B)
    native_1381_ram = _discover_native_prop_ram(rig, 0x1381)
    native_0440_ram = _discover_native_prop_ram(rig, 0x0440)
    assert native_0508_ram == RAM_PROP_0508_REAL == 0xC24CDE28
    assert native_131b_ram == RAM_PROP_131B == 0xC24CC798
    assert native_1381_ram == RAM_PROP_1381 == 0xC24CC948
    assert native_0440_ram == RAM_PROP_0508 == 0xC24CDDC4

    # 2. Execute native menu mapping 0x1033F75E(0x115501AC, 2, ui_val, -1) & inverse 0x1033F77C
    for ui_opt, exp_prop in ((0, 0), (1, 1)):
        _reset_rig(rig)
        r_fwd = rig.call(0x1033F75E, [0x115501AC, 2, ui_opt])
        assert int(r_fwd["registers"]["r0"], 16) == exp_prop
        _reset_rig(rig)
        r_rev = rig.call(0x1033F77C, [0x115501AC, 2, exp_prop])
        assert int(r_rev["registers"]["r0"], 16) == ui_opt

    # 3. Put Focus Shift default (0x0440 = 100) into 0xC24CDDC4 and test full 25-case matrix via native RAM slots
    rig.put(native_0440_ram, 100)
    fn_addr = syms21["fn_is_astro_r0"]
    out_p = RAM + 0x49000
    pred_cases = 0
    for cs in (0, 1, 2, 0x101, 0xFFFFFFFF):
        for rec in (0, 1, 2, 3, 0xFF):
            rig.put(native_0508_ram, cs)
            rig.put(native_131b_ram, rec)
            _reset_rig(rig)
            rig.call(0x100700A0, [0x0508, out_p])
            assert rig.get(out_p) == cs
            _reset_rig(rig)
            res = rig.call(fn_addr)
            got = int(res["registers"]["r0"], 16)
            exp = 1 if (cs == 1 and rec in (0, 1)) else 0
            assert got == exp, f"fn_is_astro_r0(cs={cs:#x}, rec={rec:#x}) -> {got} != {exp}"
            pred_cases += 1

    # 4. Prove Modified20 failed on exact camera state (0x0440=100, 0x0508=1, 0x131B=0) while Modified21 succeeds
    rig20 = Rig(m20, snap)
    for m_addr in range(0xC2400000, 0xC2600000, 0x100000):
        try:
            rig20.uc.mem_map(m_addr, 0x100000)
        except Exception:
            pass
    rig20.put(native_0440_ram, 100)  # Focus shift default = 100 shots
    rig20.put(native_0508_ram, 1)    # User selected Astro RAW in Color space menu
    rig20.put(native_131b_ram, 0)    # User shooting RAW
    _reset_rig(rig20)
    m20_got = int(rig20.call(syms20["fn_is_astro_r0"])["registers"]["r0"], 16)
    assert m20_got == 0, "Expected Modified20 regression reproduction (returned 0)"

    rig.put(native_0440_ram, 100)
    rig.put(native_0508_ram, 1)
    rig.put(native_131b_ram, 0)
    _reset_rig(rig)
    m21_got = int(rig.call(fn_addr)["registers"]["r0"], 16)
    assert m21_got == 1, "Modified21 must return 1 when 0x0508=1 and 0x131B=0!"

    rig.uc = None
    rig20.uc = None
    del rig, rig20
    gc.collect()
    return {
        "e2e_native_predicate_cases": pred_cases,
        "m20_regression_reproduced_and_fixed": True,
    }


def run_color_space_srgb_lock_tests(m21: bytes, snap: dict) -> dict:
    rig = Rig(m21, snap)
    u = rig.uc
    for m_addr in range(0xC2400000, 0xC2600000, 0x100000):
        try:
            u.mem_map(m_addr, 0x100000)
        except Exception:
            pass

    lock_cases = 0
    # 1. UI gray-out condition 0x18 (0x1040AD00) -> always 1 (sRGB)
    for cs in (0, 1, 2):
        _reset_rig(rig)
        rig.put(RAM_PROP_0508_REAL, cs)
        res = rig.call(0x1040AD00)
        assert int(res["registers"]["r0"], 16) == 1
        lock_cases += 1

    # 2. Native Photo-mode Effective Color Space evaluator 0x1014F638:
    #    Verify that across all Photo modes (M=4, S=3, A=2, P=1, AUTO=0x21) and 0x0508 in (0, 1),
    #    whenever 0x1014F638 updates 0x1381 via 0x1014A6E0(count=1, pid_ptr, val_ptr, ctx),
    #    the evaluated value for 0x1381 is ALWAYS 0 (sRGB), while 0x0508 in RAM stays untouched!
    written_1381: list[tuple[int, int]] = []

    def _hook_set_eval(uc, address, _size, _user):
        if address == 0x1014A6E0:
            pid_p = uc.reg_read(UC_ARM_REG_R1)
            val_p = uc.reg_read(UC_ARM_REG_R2)
            pid = struct.unpack("<I", uc.mem_read(pid_p, 4))[0]
            val = struct.unpack("<I", uc.mem_read(val_p, 4))[0]
            written_1381.append((pid, val))
            uc.reg_write(UC_ARM_REG_R0, 1)
            lr = uc.reg_read(UC_ARM_REG_LR)
            uc.reg_write(UC_ARM_REG_PC, lr)

    h = u.hook_add(UC_HOOK_CODE, _hook_set_eval, begin=0x1014A6E0, end=0x1014A6E4)
    try:
        IN_STRUCT = RAM + 0x48000
        CTX_STRUCT = RAM + 0x48100
        for cs_0508 in (0, 1):
            for exp_mode in (1, 2, 3, 4, 0x21):
                written_1381.clear()
                u.mem_write(IN_STRUCT, b"\x00" * 0x40)
                u.mem_write(CTX_STRUCT, b"\x00" * 0x100)
                rig.put(RAM_PROP_0508_REAL, cs_0508)
                # [r1+0x00]=r5 (0x180C=1), [r1+0x04]=0x0508, [r1+0x08]=old 0x1381 (set 1 to force write),
                # [r1+0x14]=r6 (mode), Photo mode -> [r1+0x1c]=0, [r1+0x24]=0, [r1+0x28]=0
                rig.put(IN_STRUCT + 0x00, 1)
                rig.put(IN_STRUCT + 0x04, cs_0508)
                rig.put(IN_STRUCT + 0x08, 1)  # pretend old 0x1381 was 1 -> forces 0x1014A6E0 update to 0!
                rig.put(IN_STRUCT + 0x14, exp_mode)
                _reset_rig(rig)
                rig.call(0x1014F638, [0, IN_STRUCT, CTX_STRUCT])
                assert written_1381 == [(0x1381, 0)], (
                    f"0x1014F638(cs={cs_0508}, mode={exp_mode:#x}) wrote {written_1381}, expected [(0x1381, 0)]"
                )
                assert rig.get(RAM_PROP_0508_REAL) == cs_0508, "0x0508 RAM slot was unexpectedly mutated!"
                lock_cases += 1
    finally:
        u.hook_del(h)

    rig.uc = None
    del rig
    gc.collect()
    return {"srgb_lock_and_1381_eval_cases": lock_cases}


def run_all_13_hook_site_tests(blobs: dict[str, bytes], snap: dict) -> dict:
    """Execute ALL 13 patched Astro RAW firmware call-sites directly in Unicorn (Stock vs Astro)."""
    m21 = blobs["m21"]
    rig = Rig(m21, snap)
    u = rig.uc
    for m_addr in range(0xC2400000, 0xC2600000, 0x100000):
        try:
            u.mem_map(m_addr, 0x100000)
        except Exception:
            pass

    def _prep(cs: int) -> None:
        _reset_rig(rig)
        rig.put(RAM_PROP_0508_REAL, cs)
        rig.put(RAM_PROP_131B, 0)

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
        u.reg_write(UC_ARM_REG_CPSR, 0xA0000020)  # N=1, Z=0, C=1, V=0
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

    # 8. 0x1011E2DC (B.W): stock 'mov r6, r7; cbnz r0, #0x1011e322' -> r0!=0 jumps 0x1011E322 vs Astro 0x1011E30C; r0==0 -> 0x1011E2E0
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
    """Verify GetLanguageString (0x104C0104) across all 36 languages for Modified21 wording + 5 neighbors."""
    rig_s = Rig(blobs["stock"], snap)
    rig_m = Rig(blobs["m21"], snap)

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

    # Explicitly assert exact user-requested ZH_CN strings:
    assert resolve_ui_str(rig_m, LANG_ZH_CN, 0x03B4)[2] == "标准 (sRGB)"
    assert resolve_ui_str(rig_m, LANG_ZH_CN, 0x03B5)[2] == "直通RAW (sRGB)"

    rig_s.uc = None
    rig_m.uc = None
    del rig_s, rig_m
    gc.collect()
    return {"ui_36_languages_string_checks": ui_checks}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "analysis/modified21-preflash-2026-11-16/lab-build/modified21-manifest.json",
    )
    args = ap.parse_args()

    manifest_p = args.manifest.resolve()
    assert manifest_p.is_file(), f"Missing manifest: {manifest_p}"
    manifest = json.loads(manifest_p.read_text(encoding="utf-8"))

    m20_manifest = json.loads(
        (ROOT / "analysis/modified20-preflash-2026-11-16/lab-build/modified20-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    m21_bytes = (manifest_p.parent / "modified21-candidate.bi").read_bytes()
    m20_bytes = (ROOT / "outputs/Z6-C380-modified20-reviewed-2026-11-16/01_TEST_MODIFIED20/EG162080.BIN").read_bytes()
    stock_bytes = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()

    syms21 = {k: int(v, 16) for k, v in manifest["cave_symbols"].items()}
    syms20 = {k: int(v, 16) for k, v in m20_manifest["cave_symbols"].items()}
    snap_p = ROOT / "analysis/modified16-preflash-2026-11-15/native-probe/probe-snap.json"
    if not snap_p.is_file():
        snap_p = ROOT / "analysis/modified15-preflash-2026-11-15/native-probe/probe-snap.json"
    snap = json.loads(snap_p.read_text(encoding="utf-8")) if snap_p.is_file() else {}

    blobs = {"m21": m21_bytes, "m20": m21_bytes, "stock": stock_bytes}
    res_pred = run_e2e_predicate_and_regression_tests(m21_bytes, m20_bytes, snap, syms21, syms20)
    res_lock = run_color_space_srgb_lock_tests(m21_bytes, snap)
    res_hooks = run_all_13_hook_site_tests(blobs, snap)
    res_ui = run_ui_string_tests(blobs, snap)
    res_iv = run_interval_timer_tests(blobs)
    res_end = run_interval_endtime_tests(blobs)

    out_json = manifest_p.parent / "probe_modified21_native_result.json"
    report = {
        "candidate": manifest["candidate"],
        "design": manifest["design"],
        "modified21_sha256": manifest["modified21_sha256"],
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

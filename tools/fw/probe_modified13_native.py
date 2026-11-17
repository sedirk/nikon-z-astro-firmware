"""Comprehensive Unicorn ARM/Thumb native verification for Modified13 vs Modified12, Modified10, and Stock C3.80."""
from pathlib import Path
import argparse, gc, itertools, json, struct, traceback
import unicorn as un
from unicorn.arm_const import (
    UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R6, UC_ARM_REG_SP
)
from probe_raw_candidates import (
    Rig, ROOT, BASE, RAM, STACK, CAL, REGS, OWNER, FRAME, A, DRIVER, MMIO,
    MAINREQ, VECTOR, SPATIAL, FLAGS, TABLES, STAGE, REQ, PACKET, STORAGE,
    INPUT, OUTPUT, ENCODED, CACHE, sha,
)

STOCK_SHA = "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c"
M10_SHA = "85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4"
M12_SHA = "9734012be0e063fa8f2ccbf77c2dd5a63a76be2f45887aa6b806b97b441cb67c"
M13_SHA = "3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749"


def run_digital_gain_unity_cases(blobs: dict[str, bytes], snap: dict) -> dict:
    """Test packet builder 0x10122ca2 across Stock, Modified10, Modified12, and Modified13."""
    out = dict(total_cases=0, stock_multipliers=[], m10_multipliers=[], m12_multipliers=[], m13_multipliers=[])
    
    test_vectors = [
        (None, 0),
        ([4096, 4096, 4096, 4096], 0x12),
        ([5305, 4176, 4180, 5171], 0x4d),
        ([8192, 4096, 4096, 2048], 0x00),
        ([1000, 2000, 3000, 4000], 0xff),
    ]

    for name in ("stock", "modified10", "modified12", "modified13"):
        rig = Rig(blobs[name], snap)
        u = rig.uc
        PKT_BUF = 0xc29a3868
        DESC_PTR = 0xc29a34c0
        RECORD_ADDR = RAM + 0x1000
        COEFFS_ADDR = RAM + 0x1100

        u.mem_write(RECORD_ADDR, struct.pack('<10H', 1, 2, 3, 4, 5, 6, 7, 8, 9, 10))

        for coeffs, ctrl in test_vectors:
            u.mem_write(PKT_BUF, b'\xaa' * 32)
            u.mem_write(PKT_BUF, struct.pack('<4I', 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef))
            r1_val = 0
            if coeffs is not None:
                r1_val = COEFFS_ADDR
                u.mem_write(COEFFS_ADDR, struct.pack('<4I', *coeffs))

            u.reg_write(UC_ARM_REG_R0, RECORD_ADDR)
            u.reg_write(UC_ARM_REG_R1, r1_val)
            u.reg_write(UC_ARM_REG_R2, ctrl)
            u.reg_write(UC_ARM_REG_SP, STACK + 0xf000)
            u.reg_write(UC_ARM_REG_LR, 0x0)

            u.emu_start(0x10122ca2 | 1, 0x0)

            published = struct.unpack('<I', u.mem_read(DESC_PTR + 0x38, 4))[0]
            assert published == PKT_BUF, "Descriptor must point to PKT_BUF"

            res = struct.unpack('<4I', u.mem_read(PKT_BUF, 16))
            if name == "stock":
                out["stock_multipliers"].append(res)
            elif name == "modified10":
                out["m10_multipliers"].append(res)
            elif name == "modified12":
                out["m12_multipliers"].append(res)
            else:
                out["m13_multipliers"].append(res)
                ctrl_written = struct.unpack("B", u.mem_read(PKT_BUF + 0x18, 1))[0]
                if coeffs is None:
                    assert res == (0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)
                    assert ctrl_written == 0xaa
                else:
                    assert res == (4096, 4096, 4096, 4096)
                    assert ctrl_written == ctrl
            out["total_cases"] += 1

        rig.uc = None
        rig = None
        gc.collect()

    return out


def run_cal33_group_selector_cases(blobs: dict[str, bytes], snap: dict) -> dict:
    """Test CAL33 group selector 0x1011e2ce across Stock, Modified12, and Modified13."""
    cal_path = ROOT / "analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/CAL38.bin"
    cal_bytes = cal_path.read_bytes()

    out = {
        "still_cases": {},
        "non_still_modes": {},
        "all_non_still_match": True,
        "m13_still_all_16384": False,
    }

    def eval_selector(blob: bytes, is_still: bool, mode_byte: int = 0):
        rig = Rig(blob, snap)
        u = rig.uc

        u.mem_map(CAL + 0x100000, 0x100000)
        rig.regions += ((CAL + 0x100000, 0x100000),)
        u.mem_write(CAL, cal_bytes)

        CTX = 0xc18fa844
        STATE = 0xc18fa954
        PKT_DESC = 0xc29a34c0
        TABLE_BUF = 0xc29a3be0

        u.mem_write(CTX, b'\x00' * 0x100)
        u.mem_write(STATE + 0x14, struct.pack('<I', CAL))
        u.mem_write(PKT_DESC, b'\x00' * 0x100)
        u.mem_write(TABLE_BUF, b'\x00' * 300)

        if is_still:
            u.mem_write(CTX + 0x84, struct.pack('<I', 1))
            u.mem_write(CTX + 0xdc, struct.pack('<I', 1))
        else:
            u.mem_write(CTX + 0x84, struct.pack('<I', 0))
            u.mem_write(CTX + 0xdc, struct.pack('<I', 0))
            u.mem_write(CTX, struct.pack('B', mode_byte))

        u.reg_write(UC_ARM_REG_R0, CTX)
        u.reg_write(UC_ARM_REG_SP, STACK + 0x8000)
        u.reg_write(UC_ARM_REG_LR, 0x0)

        recorded = []
        group_selected = [None]
        def hook_group(uc, address, size, user_data):
            if address == 0x1011e326:
                group_selected[0] = uc.reg_read(UC_ARM_REG_R4)
            elif address == 0x1011e362:
                r0 = uc.reg_read(UC_ARM_REG_R0)
                r6 = uc.reg_read(UC_ARM_REG_R6)
                recorded.append((r0, r0 - CAL, group_selected[0], r6))

        hh = u.hook_add(un.UC_HOOK_CODE, hook_group, begin=0x1011e326, end=0x1011e364)
        u.emu_start(0x1011e2ce | 1, 0x0)
        u.hook_del(hh)

        table_vals = struct.unpack('<132H', u.mem_read(TABLE_BUF, 264))

        rig.uc = None
        rig = None
        gc.collect()

        return {
            "cal_offset": hex(recorded[0][1]) if recorded else None,
            "group": recorded[0][2] if recorded else None,
            "cat": recorded[0][3] if recorded else None,
            "all_16384": all(v == 16384 for v in table_vals),
            "min_val": min(table_vals),
            "max_val": max(table_vals),
        }

    for name in ("stock", "modified12", "modified13"):
        out["still_cases"][name] = eval_selector(blobs[name], is_still=True)

    assert out["still_cases"]["modified13"]["group"] == 4
    assert out["still_cases"]["modified13"]["cal_offset"] == "0x47c0c"
    assert out["still_cases"]["modified13"]["all_16384"] is True
    out["m13_still_all_16384"] = True

    for mode in range(13):
        m12_res = eval_selector(blobs["modified12"], is_still=False, mode_byte=mode)
        m13_res = eval_selector(blobs["modified13"], is_still=False, mode_byte=mode)
        match = (m12_res["cal_offset"] == m13_res["cal_offset"]) and (m12_res["group"] == m13_res["group"])
        if not match:
            out["all_non_still_match"] = False
        out["non_still_modes"][str(mode)] = {
            "m12": m12_res,
            "m13": m13_res,
            "match": match
        }

    assert out["all_non_still_match"] is True
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--candidate", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    stock = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()
    m10 = (ROOT / "outputs/Z6-C380-modified10-reviewed-2026-11-13/01_TEST_MODIFIED10/EG162080.BIN").read_bytes()
    m12 = (ROOT / "outputs/Z6-C380-modified12-reviewed-2026-11-14/01_TEST_MODIFIED12/EG162080.BIN").read_bytes()
    m13 = args.candidate.read_bytes()

    assert sha(stock) == STOCK_SHA
    assert sha(m10) == M10_SHA
    assert sha(m12) == M12_SHA
    assert sha(m13) == M13_SHA

    blobs = dict(stock=stock, modified10=m10, modified12=m12, modified13=m13)
    snap = json.loads((ROOT / "analysis/raw-vignette-state-2026-11-08/native-selector/result.json").read_text(encoding="utf8"))["final"]

    print("Running digital gain unity cases (0x10122ca2)...")
    gain_res = run_digital_gain_unity_cases(blobs, snap)
    print(f"Digital gain cases passed: {gain_res['total_cases']} cases. Modified13 locked to (4096, 4096, 4096, 4096) on all non-null vectors!")

    print("Running CAL33 group selector cases (0x1011e2ce)...")
    cal33_res = run_cal33_group_selector_cases(blobs, snap)
    print(f"CAL33 Still Mode: Group={cal33_res['still_cases']['modified13']['group']}, Offset={cal33_res['still_cases']['modified13']['cal_offset']}, All 16384={cal33_res['m13_still_all_16384']}")
    print(f"CAL33 Non-Still Modes (0..12): All Match={cal33_res['all_non_still_match']}")

    report = {
        "ok": True,
        "candidate": "modified13",
        "sha256": M13_SHA,
        "digital_gain_unity": gain_res,
        "cal33_group_selector": cal33_res,
    }
    (args.output / "native_report.json").write_text(json.dumps(report, indent=2), encoding="utf8")
    print("Native probe successfully completed and verified.")


if __name__ == "__main__":
    main()

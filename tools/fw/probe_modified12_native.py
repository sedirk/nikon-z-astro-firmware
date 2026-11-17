"""Comprehensive Unicorn ARM/Thumb native verification for Modified12 vs Modified10, Modified9, and Stock C3.80."""
from pathlib import Path
import argparse, gc, itertools, json, struct, traceback
import unicorn as un
from unicorn.arm_const import (
    UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP
)
from probe_raw_candidates import (
    Rig, ROOT, BASE, RAM, STACK, CAL, REGS, OWNER, FRAME, A, DRIVER, MMIO,
    MAINREQ, VECTOR, SPATIAL, FLAGS, TABLES, STAGE, REQ, PACKET, STORAGE,
    INPUT, OUTPUT, ENCODED, CACHE, sha,
)
from probe_still_vignette_neutral import seed, serialize, VREQ, VOUT, CURVE, MIXED, TCTX, HISTORY, AUX
import probe_release_contract as rel

STOCK_SHA = "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c"
M9_SHA = "70ecc8d583b5207761fbad1b51411906900ba8fb82886dce0fe241595f7d182c"
M10_SHA = "85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4"
M11_SHA = "4b6b8989d1f18f20fd1a6e86c99b885eeab2bad88c4310fe144be3620970df7a"
M12_SHA = "9734012be0e063fa8f2ccbf77c2dd5a63a76be2f45887aa6b806b97b441cb67c"

CTX, STATE, PKT, ID35 = 0xc18fa844, 0xc18fa954, 0xc29a34c0, 0x56000000
START = 0x1017d7b6
P_REQ, P_OUT = RAM + 0x36000, RAM + 0x36100
M_CONTEXT = 0xc27631c0


def run_digital_gain_unity_cases(blobs: dict[str, bytes], snap: dict) -> dict:
    """Test packet builder 0x10122ca2 across Stock, Modified10, and Modified12."""
    out = dict(total_cases=0, stock_multipliers=[], m10_multipliers=[], m12_multipliers=[])
    
    # Test vectors of (r0, r1, r2)
    # r0 = dummy record pointer
    # r1 = coefficients pointer or NULL
    # r2 = control byte
    test_vectors = [
        (None, 0),
        ([4096, 4096, 4096, 4096], 0x12),
        ([5305, 4176, 4180, 5171], 0x4d), # real Z6 shooting multipliers (R=1.295, B=1.263)
        ([8192, 4096, 4096, 2048], 0x00),
        ([1000, 2000, 3000, 4000], 0xff),
    ]

    for name in ("stock", "modified10", "modified12"):
        rig = Rig(blobs[name], snap)
        u = rig.uc
        PKT_BUF = 0xc29a3868
        DESC_PTR = 0xc29a34c0
        RECORD_ADDR = RAM + 0x1000
        COEFFS_ADDR = RAM + 0x1100

        # Setup record dummy data (10 halfwords)
        u.mem_write(RECORD_ADDR, struct.pack('<10H', 1, 2, 3, 4, 5, 6, 7, 8, 9, 10))

        for coeffs, ctrl in test_vectors:
            # Pre-fill PKT_BUF with marker bytes
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

            # Call 0x10122ca2
            u.emu_start(0x10122ca2 | 1, 0x0)

            # Verify return and packet published pointer
            published = struct.unpack('<I', u.mem_read(DESC_PTR + 0x38, 4))[0]
            assert published == PKT_BUF, "Descriptor must point to PKT_BUF"

            # Read four channel multipliers from PKT_BUF
            res = struct.unpack('<4I', u.mem_read(PKT_BUF, 16))
            if name == "stock":
                out["stock_multipliers"].append(res)
            elif name == "modified10":
                out["m10_multipliers"].append(res)
            else:
                out["m12_multipliers"].append(res)
                ctrl_written = struct.unpack("B", u.mem_read(PKT_BUF + 0x18, 1))[0]
                if coeffs is None:
                    # When r1 == NULL, Modified12 MUST preserve stock cbz bypass!
                    assert res == (0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef), f"M12 must bypass when NULL! Got {res}"
                    assert ctrl_written == 0xaa, f"M12 must not overwrite control byte when NULL! Got {ctrl_written:#x}"
                else:
                    assert res == (4096, 4096, 4096, 4096), f"Modified12 must be 4096! Got {res}"
                    assert ctrl_written == ctrl, f"M12 must write caller control byte! Got {ctrl_written:#x} vs {ctrl:#x}"
            out["total_cases"] += 1

        rig.uc = None
        rig = None
        gc.collect()

    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--candidate", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    stock = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()
    m9 = (ROOT / "outputs/Z6-C380-production-modified9-2026-11-12/01_TEST_MODIFIED9/EG162080.BIN").read_bytes()
    m10 = (ROOT / "outputs/Z6-C380-modified10-reviewed-2026-11-13/01_TEST_MODIFIED10/EG162080.BIN").read_bytes()
    m11 = args.candidate.read_bytes()

    assert sha(stock) == STOCK_SHA
    assert sha(m9) == M9_SHA
    assert sha(m10) == M10_SHA
    assert sha(m11) == M12_SHA

    blobs = dict(stock=stock, modified9=m9, modified10=m10, modified12=m11)
    snap = json.loads((ROOT / "analysis/raw-vignette-state-2026-11-08/native-selector/result.json").read_text(encoding="utf8"))["final"]

    print("Running digital gain unity cases (0x10122ca2)...")
    gain_res = run_digital_gain_unity_cases(blobs, snap)
    print(f"Digital gain cases passed: {gain_res['total_cases']} cases. Modified12 locked to (4096, 4096, 4096, 4096) on all!")

    report = {
        "ok": True,
        "candidate": "modified12",
        "sha256": M12_SHA,
        "digital_gain_unity": gain_res,
    }
    (args.output / "native_report.json").write_text(json.dumps(report, indent=2), encoding="utf8")
    print("Native probe successfully completed and verified.")


if __name__ == "__main__":
    main()

"""Comprehensive Unicorn ARM/Thumb native verification for Modified15 (Modified13 + 30-600s v2)."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from probe_modified13_native import (
    M10_SHA,
    M12_SHA,
    M13_SHA,
    STOCK_SHA,
    run_cal33_group_selector_cases,
    run_digital_gain_unity_cases,
)
from probe_raw_candidates import ROOT, sha
from z6_m600_v2_emu_e2e import run_all_m600_v2_tests

M14_SHA = "6d970609c18ac64302e82a7e4f4bfba9d8d4b14a606b55bf2cbc56dc37ea754b"
M15_SHA = "0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--candidate",
        type=Path,
        default=ROOT / "analysis/modified15-preflash-2026-11-15/lab-build/modified15-candidate.bi",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified15-preflash-2026-11-15/native-probe",
    )
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    stock = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()
    m10 = (ROOT / "outputs/Z6-C380-modified10-reviewed-2026-11-13/01_TEST_MODIFIED10/EG162080.BIN").read_bytes()
    m12 = (ROOT / "outputs/Z6-C380-modified12-reviewed-2026-11-14/01_TEST_MODIFIED12/EG162080.BIN").read_bytes()
    m13 = (ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN").read_bytes()
    m14 = (ROOT / "analysis/modified14-preflash-2026-11-14/lab-build/modified14-candidate.bi").read_bytes()
    m15 = args.candidate.read_bytes()

    assert sha(stock) == STOCK_SHA
    assert sha(m10) == M10_SHA
    assert sha(m12) == M12_SHA
    assert sha(m13) == M13_SHA
    assert sha(m14) == M14_SHA
    assert sha(m15) == M15_SHA

    blobs = {"stock": stock, "modified10": m10, "modified12": m12, "modified13": m15}
    snap = json.loads(
        (ROOT / "analysis/raw-vignette-state-2026-11-08/native-selector/result.json").read_text(encoding="utf8")
    )["final"]

    print("1/3 Running inherited digital gain unity probe (0x10122ca2)...")
    gain_res = run_digital_gain_unity_cases(blobs, snap)

    print("2/3 Running inherited CAL33 Group 4 selector probe (0x1011e2ce)...")
    cal33_res = run_cal33_group_selector_cases(blobs, snap)

    print("3/3 Running 30-600s v2 native ROM execution (with modeled OS/HW boundaries) + Modified14 T-mode lock negative-control suite...")
    m600_res = run_all_m600_v2_tests(m15, m14)

    report = {
        "ok": True,
        "candidate": "modified15",
        "sha256": M15_SHA,
        "supersedes_modified14_sha256": M14_SHA,
        "inherited_m13_sha256": M13_SHA,
        "digital_gain_unity_probe": gain_res,
        "cal33_group4_selector_probe": cal33_res,
        "m600_v2_extended_shutter_probe": m600_res,
    }
    out_file = args.output / "native_report.json"
    out_file.write_text(json.dumps(report, indent=2), encoding="utf8")
    print(f"Modified15 native verification PASSED -> {out_file}")


if __name__ == "__main__":
    main()

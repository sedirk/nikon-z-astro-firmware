"""Comprehensive Unicorn ARM/Thumb native verification for Modified14 (Modified13 + 30-600s M-still exposure)."""
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
from z6_m600_emu import run_all_m600_tests

M14_SHA = "6d970609c18ac64302e82a7e4f4bfba9d8d4b14a606b55bf2cbc56dc37ea754b"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--candidate",
        type=Path,
        default=ROOT / "analysis/modified14-preflash-2026-11-14/lab-build/modified14-candidate.bi",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified14-preflash-2026-11-14/native-probe",
    )
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    stock = (ROOT / "firmware/decoded/eg1620_038000.bi").read_bytes()
    m10 = (ROOT / "outputs/Z6-C380-modified10-reviewed-2026-11-13/01_TEST_MODIFIED10/EG162080.BIN").read_bytes()
    m12 = (ROOT / "outputs/Z6-C380-modified12-reviewed-2026-11-14/01_TEST_MODIFIED12/EG162080.BIN").read_bytes()
    m14 = args.candidate.read_bytes()

    assert sha(stock) == STOCK_SHA
    assert sha(m10) == M10_SHA
    assert sha(m12) == M12_SHA
    assert sha(m14) == M14_SHA

    # Pass Modified14 in the "modified13" slot of inherited RAW convergence probes
    blobs = {"stock": stock, "modified10": m10, "modified12": m12, "modified13": m14}
    snap = json.loads(
        (ROOT / "analysis/raw-vignette-state-2026-11-08/native-selector/result.json").read_text(encoding="utf8")
    )["final"]

    print("1/3 Running inherited digital gain unity probe (0x10122ca2)...")
    gain_res = run_digital_gain_unity_cases(blobs, snap)

    print("2/3 Running inherited CAL33 Group 4 selector probe (0x1011e2ce)...")
    cal33_res = run_cal33_group_selector_cases(blobs, snap)

    print("3/3 Running 30-600s M-still native ARM/Thumb execution suite...")
    m600_res = run_all_m600_tests(m14)

    report = {
        "ok": True,
        "candidate": "modified14",
        "sha256": M14_SHA,
        "parent_m13_sha256": M13_SHA,
        "digital_gain_unity": gain_res,
        "cal33_group_selector": cal33_res,
        "m600_extended_shutter": m600_res,
    }
    (args.output / "native_report.json").write_text(json.dumps(report, indent=2), encoding="utf8")
    print("Modified14 native probe PASSED all RAW convergence + 30-600s checks.")


if __name__ == "__main__":
    main()

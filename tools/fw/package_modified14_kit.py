"""Assess offline preflash reviews, package Modified14 (Modified13 + 30-600s) kit, and run self-checks."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import sys
import zipfile

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from verify_modified14_kit import DIGESTS, PATHS, RECIPE_SHA, check_kit, need, sha

ROOT = THIS_DIR.parents[1]
ROUND = ROOT / "analysis/modified14-preflash-2026-11-14"

INPUT_SOURCES = {
    "modified14": ROUND / "lab-build/modified14-candidate.bi",
    "modified13": ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN",
    "modified12": ROOT / "outputs/Z6-C380-modified12-reviewed-2026-11-14/01_TEST_MODIFIED12/EG162080.BIN",
    "modified10": ROOT / "outputs/Z6-C380-modified10-reviewed-2026-11-13/01_TEST_MODIFIED10/EG162080.BIN",
    "stock": ROOT / "firmware/decoded/eg1620_038000.bi",
}


def read_json(path: Path) -> dict:
    need(path.is_file(), f"Missing required JSON audit file: {path}")
    return json.loads(path.read_text(encoding="utf8"))


def verify_release_gates() -> dict:
    for name, src_path in INPUT_SOURCES.items():
        need(src_path.is_file(), f"Input binary missing: {src_path}")
        file_sha = sha(src_path.read_bytes())
        need(file_sha == DIGESTS[name], f"Input hash mismatch for {name}: {file_sha} != {DIGESTS[name]}")

    recipe_path = ROOT / "patches/z6-c380-modified14-production-600s.json"
    need(recipe_path.is_file() and sha(recipe_path.read_bytes()) == RECIPE_SHA, "Recipe JSON missing or hash mismatch")

    probe_report_path = ROUND / "native-probe/native_report.json"
    probe_report = read_json(probe_report_path)
    need(probe_report.get("ok") is True, "Native probe audit failed or incomplete")
    need(probe_report.get("sha256") == DIGESTS["modified14"], "Native probe candidate hash mismatch")

    updater_report_path = ROUND / "updater-audit/result.json"
    updater_report = read_json(updater_report_path)
    need(updater_report.get("ok") is True, "Updater audit failed or incomplete")

    lab_manifest_path = ROUND / "lab-build/manifest.json"
    manifest = read_json(lab_manifest_path)
    need(manifest.get("ok") is True and manifest.get("sha256") == DIGESTS["modified14"], "Lab build manifest invalid")

    return {
        "recipe": recipe_path,
        "native_probe": probe_report_path,
        "updater_audit": updater_report_path,
        "manifest": lab_manifest_path,
    }


def package(dest: Path) -> None:
    print("Checking Modified14 packaging inputs and release gates...")
    gates = verify_release_gates()
    print("Release gates passed: 5 binaries + recipe + Unicorn probe + updater audit verified.")

    staging_dir = dest.parent / f".staging_{dest.name}"
    staging_zip = dest.parent / f".staging_{dest.name}.zip"
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    if staging_zip.exists():
        staging_zip.unlink()

    staging_dir.mkdir(parents=True, exist_ok=False)
    for folder in (
        "01_TEST_MODIFIED14",
        "02_BACK_TO_MODIFIED13",
        "03_BACK_TO_MODIFIED12",
        "04_BACK_TO_MODIFIED10",
        "05_STOCK_C380",
        "reports",
    ):
        (staging_dir / folder).mkdir()

    for name, rel_path in PATHS.items():
        shutil.copy2(INPUT_SOURCES[name], staging_dir / rel_path)

    shutil.copy2(gates["recipe"], staging_dir / "reports/recipe.json")
    shutil.copy2(gates["native_probe"], staging_dir / "reports/native_probe.json")
    shutil.copy2(gates["updater_audit"], staging_dir / "reports/updater_audit.json")
    shutil.copy2(gates["manifest"], staging_dir / "reports/manifest.json")
    shutil.copy2(THIS_DIR / "verify_modified14_kit.py", staging_dir / "verify.py")

    readme_text = """Nikon Z6 C3.80 Astro Convergence + 30-600s Extended Shutter Firmware (Modified14)
=================================================================================

Model: Nikon Z6 (first generation)
Base Firmware: Official C3.80 (EG162080.BIN)
Status: Preflash Candidate (Offline Unicorn ARM/Thumb + Updater Verified; Pending Real-Camera Test)

Package Contents:
  - 01_TEST_MODIFIED14/EG162080.BIN    : Modified14 (Modified13 astro RAW convergence + 60"-600" M-still shutter)
  - 02_BACK_TO_MODIFIED13/EG162080.BIN : [RECOMMENDED RECOVERY FALLBACK 1] Camera-verified Modified13 baseline
  - 03_BACK_TO_MODIFIED12/EG162080.BIN : [RECOMMENDED RECOVERY FALLBACK 2] Camera-verified Modified12 baseline
  - 04_BACK_TO_MODIFIED10/EG162080.BIN : Camera-verified Modified10 baseline
  - 05_STOCK_C380/EG162080.BIN         : Official factory stock firmware C3.80
  - reports/                           : Canonical recipe.json, Unicorn native_probe.json, updater_audit.json, manifest.json
  - verify.py                          : Standalone stdlib-only offline integrity & dual-build verifier

Modified14 Key Features:
  1. Native ROM 30-600s Extended Shutter Speeds (Strictly M Still Mode Only):
     Adds 8 extended steps between 30" and Time/Bulb on the M-mode command dial and PTP/USB (0x500D / 0xD100):
       60", 90", 120", 180", 240", 300", 480", 600"
     - Exact wall-clock microsecond/nanosecond exposure timers (60,000,000 us .. 600,000,000 us)
     - Exact EXIF ExposureTime rationals (600/10 .. 6000/10)
     - Rear LCD, EVF, and top-OLED 3-digit seconds display ("60"" .. "600"")
     - Multi-click command dial boundary stops at 30" and 60" to prevent accidental overshoot
     - Strict M-still isolation: P/A/S, Auto, and Movie modes keep 100% stock shutter limits and reject >30s PTP writes (0x201C)
     - Zero SD-card plugin files required (baked directly into ROM XIP alignment holes)
  2. Full Modified13 Astro RAW Convergence Inherited Unchanged (14 sites):
     - Frontend CAL33 static Group 4 unity routing (all 33x4 = 16384 in still capture; 13 non-still modes stock)
     - Frontend digital gain unity lock (4096) + 2D polynomial zeroing
     - Backend 257-entry vignette & dual-17 spatial table bypass
     - Dark current / negative sub-black readout preservation (star-eater suppression disabled)

Verification:
  Run `python verify.py` inside this folder to verify all SHA-256 digests, CRC16-HQX checksums,
  and 98-site dual reconstruction from both Stock C3.80 and Modified13.
"""
    (staging_dir / "README.txt").write_text(readme_text, encoding="utf8")

    flash_text = """FLASHING AND RECOVERY INSTRUCTIONS
==================================

CRITICAL SAFETY WARNING:
  - NEVER TURN OFF THE CAMERA OR REMOVE THE BATTERY WHILE AN UPDATE IS IN PROGRESS.
  - Wait at least 15 minutes if the progress bar appears paused.
  - Cutting power during erase/write phases risks permanent hardware bricking.

Prerequisites:
  1. Nikon EN-EL15b/c battery charged >= 80%.
  2. Reliable XQD / CFexpress Type B card formatted in-camera.
  3. Place ONLY ONE EG162080.BIN in the card root directory at a time.

Flashing Steps:
  1. Copy 01_TEST_MODIFIED14/EG162080.BIN to the root directory of the memory card.
  2. Insert card into camera, power ON -> Menu -> Setup (Wrench) -> Firmware version -> Update.
  3. Wait until 'Update complete. Turn camera off.' appears, then power cycle the camera.

Post-Flash Test Checklist for 30-600s:
  1. Switch mode dial to M (Photo mode), turn main command dial past 30":
     verify 60" -> 90" -> 120" -> 180" -> 240" -> 300" -> 480" -> 600" -> Time -> Bulb on EVF/LCD and top OLED.
  2. Test a 60" capture and verify wall-clock shutter duration (~60s) and EXIF ExposureTime = 60s.
  3. Switch to A / S / P and Movie mode: verify shutter speed never exceeds 30".

Standard Rollback Procedure (requires normal camera boot):
  Replace EG162080.BIN on card root with 02_BACK_TO_MODIFIED13/EG162080.BIN (or 05_STOCK_C380/EG162080.BIN)
  and run Setup -> Firmware version -> Update.
"""
    (staging_dir / "FLASH_INSTRUCTIONS.txt").write_text(flash_text, encoding="utf8")

    res = check_kit(staging_dir)
    print(f"Staged kit self-check passed: {res}")

    with zipfile.ZipFile(staging_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(staging_dir.rglob("*")):
            if f.is_file():
                zf.write(f, f.relative_to(staging_dir))

    if dest.exists():
        shutil.rmtree(dest)
    staging_dir.rename(dest)
    dest_zip = dest.with_suffix(".zip")
    if dest_zip.exists():
        dest_zip.unlink()
    staging_zip.rename(dest_zip)

    final_res = check_kit(dest)
    print(f"Final Modified14 delivery kit ready: {dest.name} + {dest_zip.name} -> {final_res}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dest", type=Path, default=ROOT / "outputs/Z6-C380-modified14-reviewed-2026-11-14")
    args = ap.parse_args()
    package(args.dest)


if __name__ == "__main__":
    main()

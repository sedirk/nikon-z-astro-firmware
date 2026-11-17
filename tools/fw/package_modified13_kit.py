"""Assess offline preflash reviews, package Modified13 kit, and generate review report."""
from pathlib import Path
import argparse, datetime, json, shutil, zipfile
from verify_modified13_kit import DIGESTS, PATHS, need, sha, check_kit

ROOT = Path(__file__).resolve().parents[2]
ROUND = ROOT / "analysis/modified13-preflash-2026-11-14"

INPUT_SOURCES = {
    "modified13": ROUND / "lab-build/modified13-candidate.bi",
    "modified12": ROOT / "outputs/Z6-C380-modified12-reviewed-2026-11-14/01_TEST_MODIFIED12/EG162080.BIN",
    "modified10": ROOT / "outputs/Z6-C380-modified10-reviewed-2026-11-13/01_TEST_MODIFIED10/EG162080.BIN",
    "modified1": ROOT / "outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN",
    "stock": ROOT / "firmware/decoded/eg1620_038000.bi",
}


def read_json(path: Path) -> dict:
    need(path.is_file(), f"Missing required JSON audit file: {path}")
    return json.loads(path.read_text(encoding="utf8"))


def verify_release_gates() -> dict:
    """Strict pre-packaging quality gates: verify all inputs, hashes, and audit reports exist and passed."""
    for name, src_path in INPUT_SOURCES.items():
        need(src_path.is_file(), f"Input binary missing: {src_path}")
        file_sha = sha(src_path.read_bytes())
        need(file_sha == DIGESTS[name], f"Input hash mismatch for {name}: {file_sha} != {DIGESTS[name]}")

    probe_report_path = ROUND / "native-probe/native_report.json"
    probe_report = read_json(probe_report_path)
    need(probe_report.get("ok") is True, f"Native probe audit failed or incomplete: {probe_report_path}")
    need(probe_report.get("sha256") == DIGESTS["modified13"], "Native probe candidate hash mismatch!")

    updater_report_path = ROUND / "updater-audit/result.json"
    updater_report = read_json(updater_report_path)
    need(updater_report.get("ok") is True, f"Updater audit failed or incomplete: {updater_report_path}")

    lab_manifest_path = ROUND / "lab-build/manifest.json"
    manifest = read_json(lab_manifest_path)
    need(manifest.get("ok") is True, f"Lab build manifest invalid: {lab_manifest_path}")
    need(manifest.get("sha256") == DIGESTS["modified13"], "Lab build candidate hash mismatch!")

    return {
        "native_probe": probe_report_path,
        "updater_audit": updater_report_path,
        "manifest": lab_manifest_path,
    }


def package(dest: Path) -> None:
    print("Checking packaging inputs and release gates...")
    gates = verify_release_gates()
    print("Release gates passed: all 5 binary inputs verified, native probe OK, updater audit OK.")

    staging_dir = dest.parent / f".staging_{dest.name}"
    staging_zip = dest.parent / f".staging_{dest.name}.zip"

    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    if staging_zip.exists():
        staging_zip.unlink()

    staging_dir.mkdir(parents=True, exist_ok=False)
    for p in ("01_TEST_MODIFIED13", "02_BACK_TO_MODIFIED12", "03_BACK_TO_MODIFIED10", "04_DARK_ONLY_MODIFIED1", "05_STOCK_C380", "reports"):
        (staging_dir / p).mkdir()

    for name, rel_path in PATHS.items():
        shutil.copy2(INPUT_SOURCES[name], staging_dir / rel_path)

    shutil.copy2(gates["native_probe"], staging_dir / "reports/native_probe.json")
    shutil.copy2(gates["updater_audit"], staging_dir / "reports/updater_audit.json")
    shutil.copy2(gates["manifest"], staging_dir / "reports/manifest.json")

    verify_script = (ROOT / "tools/fw/verify_modified13_kit.py").read_text(encoding="utf8")
    (staging_dir / "verify.py").write_text(verify_script, encoding="utf8")

    readme_text = """Nikon Z6 C3.80 Production Convergence Astro Firmware (Modified13)
========================================================================

Author: Antigravity Assistant & Independent Reviewer
Date: 2026-11-14
Model: Nikon Z6
Base Firmware: Official C3.80 (EG162080.BIN)
Status: Preflash Production Convergence Candidate

Package Contents:
  - 01_TEST_MODIFIED13/EG162080.BIN   : Production candidate Modified13 firmware
  - 02_BACK_TO_MODIFIED12/EG162080.BIN : [RECOMMENDED RECOVERY FALLBACK 1]
        Verified safe baseline from 11.14 real-shooting audit with digital gain comb fixed.
  - 03_BACK_TO_MODIFIED10/EG162080.BIN : [RECOMMENDED RECOVERY FALLBACK 2]
        Verified safe baseline from 11.13 with full dark preserve and backend ISP bypass.
  - 04_DARK_ONLY_MODIFIED1/EG162080.BIN: Pure dark current preservation (Modified1)
  - 05_STOCK_C380/EG162080.BIN         : Official factory stock firmware C3.80
  - reports/                           : Complete offline audit evidence (Unicorn probe, updater audit, manifest)
  - verify.py                          : Self-contained independent verification script

Modified13 Key Enhancements & Root-Cause Convergence:
  1. Frontend CAL33 33x4 Spatial Gain Elimination:
     In static capture (is_still=True), branch instruction at 0x1011e2de (00bb -> a8b9)
     routes to factory Group 4 (offset 0x47c0c in CAL38), where all 33 rows x 4 channels
     are strictly 16384 (1.000000x Q14 gain in CAL38 offline model).
     NOTE: Physical elimination of concentric color rings in NEFs is the theoretical target
     and must be empirically verified via post-flash flat-field captures.
  2. Complete Non-Still Isolation:
     All 13 non-still modes (LiveView, Movie, EVF, Focus) strictly retain factory routing
     and tables (100% bit-exact match with stock).
  3. Digital Gain Multipliers Unity Lock (from Modified12):
     Hardware digital gains safely locked to 4096 with NULL-pointer bypass preserved.
  4. Frontend 2D Unity Sanitizer (from Modified9):
     Cleans 2D radial polynomials and stage gain matrices.
  5. Backend ISP 257-entry Vignette & Dual-17 Spatial Tables Bypass (from Modified10).
  6. Dark Current Preservation (from Modified1):
     Disables star-eater / hot-pixel neighborhood suppression, preserves negative sub-black readouts.

Verification:
  Run `python verify.py` inside this folder to verify all SHA-256 digests, CRC16-HQX checksums,
  and site-by-site binary patch assertions.
"""
    (staging_dir / "README.txt").write_text(readme_text, encoding="utf8")

    flash_text = """FLASHING AND RECOVERY INSTRUCTIONS
==================================

CRITICAL SAFETY WARNING:
  - NEVER TURN OFF THE CAMERA OR REMOVE THE BATTERY WHILE AN UPDATE IS IN PROGRESS.
  - A paused progress bar does NOT mean the camera has failed. Wait at least 15 minutes
    if progress appears frozen.
  - Cutting power during write/erase phases risks bricking the boot ROM/flash controller.

Prerequisites:
  1. Nikon EN-EL15b/c battery fully charged (>= 80%).
  2. Reliable XQD / CFexpress Type B card formatted in-camera.
  3. Only ONE EG162080.BIN file placed on the card at a time.

Flashing Steps:
  1. Copy 01_TEST_MODIFIED13/EG162080.BIN to the root directory of the memory card.
  2. Insert card into camera, power ON.
  3. Enter Menu -> Setup (Wrench) -> Firmware version.
  4. Select 'Update' and follow on-screen prompts.
  5. DO NOT TOUCH THE CAMERA UNTIL the screen explicitly displays:
     'Update complete. Turn camera off.'
  6. Turn camera off, wait 5 seconds, and turn back on.

Standard Post-Flash Rollback Procedure (Only after normal boot and with a working camera):
  If Modified13 exhibits any functional issue after booting successfully:
  1. Delete EG162080.BIN from the card on your PC.
  2. Copy 02_BACK_TO_MODIFIED12/EG162080.BIN (or 05_STOCK_C380/EG162080.BIN) to card root.
  3. Power ON the camera, navigate to Setup Menu -> Firmware version -> Update.
  4. Complete the official firmware update process normally to return to baseline.
  (NOTE: Rollback files require an operational camera and functioning updater; they cannot
   recover a device damaged by power loss during flashing.)
"""
    (staging_dir / "FLASH_INSTRUCTIONS.txt").write_text(flash_text, encoding="utf8")

    print("Verifying staged kit via self-check...")
    res = check_kit(staging_dir)
    print(f"Staged kit self-check passed: {res}")

    with zipfile.ZipFile(staging_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in staging_dir.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(staging_dir))
    print(f"Staged ZIP archive created: {staging_zip.name} ({staging_zip.stat().st_size} bytes)")

    if dest.exists():
        shutil.rmtree(dest)
    staging_dir.rename(dest)
    dest_zip = dest.with_suffix(".zip")
    if dest_zip.exists():
        dest_zip.unlink()
    staging_zip.rename(dest_zip)

    final_res = check_kit(dest)
    print(f"Final delivery kit verification SUCCESS: {dest} -> {final_res}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dest", type=Path, default=ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14")
    args = ap.parse_args()
    package(args.dest)


if __name__ == "__main__":
    main()

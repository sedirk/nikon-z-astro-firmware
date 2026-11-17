"""Assess offline preflash reviews, package Modified12 kit, and generate review report."""
from pathlib import Path
import argparse, datetime, json, shutil, zipfile
from verify_modified12_kit import DIGESTS, PATHS, need, sha, check_kit

ROOT = Path(__file__).resolve().parents[2]
ROUND = ROOT / "analysis/modified12-preflash-2026-11-14"

INPUT_SOURCES = {
    "modified12": ROUND / "lab-build/modified12-candidate.bi",
    "modified11": ROOT / "outputs/Z6-C380-modified11-reviewed-2026-11-14/01_TEST_MODIFIED11/EG162080.BIN",
    "modified10": ROOT / "outputs/Z6-C380-modified10-reviewed-2026-11-13/01_TEST_MODIFIED10/EG162080.BIN",
    "modified1": ROOT / "outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN",
    "stock": ROOT / "firmware/decoded/eg1620_038000.bi",
}


def read_json(path: Path) -> dict:
    need(path.is_file(), f"Missing required JSON audit file: {path}")
    return json.loads(path.read_text(encoding="utf8"))


def verify_release_gates() -> dict:
    """Strict pre-packaging quality gates: verify all inputs, hashes, and audit reports exist and passed."""
    # 1. Verify all input binaries exist and match required SHA-256
    for name, src_path in INPUT_SOURCES.items():
        need(src_path.is_file(), f"Input binary missing: {src_path}")
        file_sha = sha(src_path.read_bytes())
        need(file_sha == DIGESTS[name], f"Input hash mismatch for {name}: {file_sha} != {DIGESTS[name]}")

    # 2. Verify Native Unicorn Probe report
    probe_report_path = ROUND / "native-probe/native_report.json"
    probe_report = read_json(probe_report_path)
    need(probe_report.get("ok") is True, f"Native probe audit failed or incomplete: {probe_report_path}")
    need(probe_report.get("sha256") == DIGESTS["modified12"], "Native probe candidate hash mismatch!")

    # 3. Verify Updater / Flash Scheduler Audit report
    updater_report_path = ROUND / "updater-audit/result.json"
    updater_report = read_json(updater_report_path)
    need(updater_report.get("ok") is True, f"Updater audit failed or incomplete: {updater_report_path}")

    # 4. Verify Recipe Manifest exists
    manifest_path = ROUND / "lab-build/manifest.json"
    manifest = read_json(manifest_path)
    need(manifest.get("sha256") == DIGESTS["modified12"], "Manifest SHA256 mismatch!")

    return {
        "native_probe": probe_report_path,
        "updater_audit": updater_report_path,
        "manifest": manifest_path,
    }


def package(dest: Path) -> None:
    # --- PHASE 1: PRE-CHECK AND RELEASE GATES (Non-destructive) ---
    print("Checking packaging inputs and release gates...")
    gates = verify_release_gates()
    print("Release gates passed: all 5 binary inputs verified, native probe OK, updater audit OK.")

    # --- PHASE 2: ATOMIC STAGING (Build in temporary folder, do NOT touch dest yet) ---
    staging_dir = dest.parent / f".staging_{dest.name}"
    staging_zip = dest.parent / f".staging_{dest.name}.zip"

    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    if staging_zip.exists():
        staging_zip.unlink()

    staging_dir.mkdir(parents=True, exist_ok=False)
    for p in ("01_TEST_MODIFIED12", "02_BACK_TO_MODIFIED11", "03_BACK_TO_MODIFIED10", "04_DARK_ONLY_MODIFIED1", "05_STOCK_C380", "reports"):
        (staging_dir / p).mkdir()

    # Copy firmware binaries to staging
    for name, rel_path in PATHS.items():
        shutil.copy2(INPUT_SOURCES[name], staging_dir / rel_path)

    # Archive verified audit reports to staging
    shutil.copy2(gates["native_probe"], staging_dir / "reports/native_probe.json")
    shutil.copy2(gates["updater_audit"], staging_dir / "reports/updater_audit.json")
    shutil.copy2(gates["manifest"], staging_dir / "reports/manifest.json")

    # verify.py in kit
    verify_script = (ROOT / "tools/fw/verify_modified12_kit.py").read_text(encoding="utf8")
    (staging_dir / "verify.py").write_text(verify_script, encoding="utf8")

    # Documentation with explicit safety warnings
    readme_text = """Nikon Z6 C3.80 Production Convergence Astro Firmware (Modified12)
========================================================================

Author: Antigravity Assistant & Independent GPT Reviewer
Date: 2026-11-14
Model: Nikon Z6
Base Firmware: Official C3.80 (EG162080.BIN)
Status: Preflash Candidate (Offline Rigorous Native & Updater Audited)

Package Contents:
  - 01_TEST_MODIFIED12/EG162080.BIN : Production candidate Modified12 firmware
  - 02_BACK_TO_MODIFIED11/EG162080.BIN : [HISTORICAL REFERENCE ONLY - KNOWN REGRESSION]
        WARNING: Modified11 contains a confirmed control-byte overwrite regression at 0x10122cba
        when r1 == NULL. DO NOT USE MODIFIED11 AS DEFAULT RECOVERY FIRMWARE.
  - 03_BACK_TO_MODIFIED10/EG162080.BIN : [RECOMMENDED STABLE FALLBACK]
        Verified safe fallback containing full dark current preservation and backend ISP bypass,
        free of any 0x10122cba control-flow regression.
  - 04_DARK_ONLY_MODIFIED1/EG162080.BIN: Pure dark current preservation (Modified1)
  - 05_STOCK_C380/EG162080.BIN         : Official factory stock firmware C3.80
  - reports/                           : Complete offline audit evidence (Unicorn probe, updater audit, manifest)
  - verify.py                          : Self-contained independent verification script

Modified12 Key Enhancements:
  1. Complete fix for 0x10122cba NULL-pointer regression:
     Original `cbz r1, #0x10122cce` branch instruction preserved.
     When r1 == NULL: skips gain write and preserves caller control byte [r3, #0x18] (100% stock behavior).
     When r1 != NULL: locks 4-channel digital multipliers to 4096 (1.0x) and writes caller control byte.
  2. Inherits front-end 2D polynomial zeroing and unity DC gains (from Modified9).
  3. Inherits backend ISP 257-entry vignette & dual-17 spatial tables bypass (from Modified10).
  4. Inherits full dark current star-eater disable & zero sub-black clipping (from Modified1/2).

Verification:
  Run `python verify.py` inside this folder to verify all SHA-256 digests, CRC16-HQX checksums,
  and site-by-site binary patch assertions.
"""
    (staging_dir / "README.txt").write_text(readme_text, encoding="utf8")

    # CHECKSUMS.txt
    lines = []
    for k in ("modified12", "modified11", "modified10", "modified1", "stock"):
        lines.append(f"{DIGESTS[k]}  {PATHS[k]}")
    (staging_dir / "CHECKSUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf8")

    # Run verify check on staging
    res = check_kit(staging_dir)
    need(res["status"] == "OK", "Staging kit self-verification failed!")

    # Create ZIP archive from staging
    with zipfile.ZipFile(staging_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in staging_dir.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(staging_dir))

    # --- PHASE 3: ATOMIC SWAP (Only performed after staging completely succeeded) ---
    zip_path = dest.parent / f"{dest.name}.zip"

    if dest.exists():
        backup_dir = dest.parent / f".backup_{dest.name}"
        if backup_dir.exists():
            shutil.rmtree(backup_dir)
        dest.rename(backup_dir)
        try:
            staging_dir.rename(dest)
            shutil.rmtree(backup_dir)
        except Exception:
            if backup_dir.exists() and not dest.exists():
                backup_dir.rename(dest)
            raise
    else:
        staging_dir.rename(dest)

    if staging_zip.exists():
        if zip_path.exists():
            zip_path.unlink()
        staging_zip.rename(zip_path)

    print(f"Packaged Modified12 kit at: {dest}")
    print(f"Created ZIP archive at: {zip_path} ({zip_path.stat().st_size} bytes, sha256={sha(zip_path.read_bytes())})")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, default=ROOT / "outputs/Z6-C380-modified12-reviewed-2026-11-14")
    args = ap.parse_args()
    package(args.output.resolve())


if __name__ == "__main__":
    main()

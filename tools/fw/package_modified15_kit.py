"""Assess offline preflash reviews, package Modified15 (Modified13 + 30-600s v2) kit, and run self-checks."""
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

from verify_modified15_kit import DIGESTS, PATHS, RECIPE_SHA, check_kit, need, sha

ROOT = THIS_DIR.parents[1]
ROUND = ROOT / "analysis/modified15-preflash-2026-11-15"

INPUT_SOURCES = {
    "modified15": ROUND / "lab-build/modified15-candidate.bi",
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

    recipe_path = ROOT / "patches/z6-c380-modified15-production-600s.json"
    need(recipe_path.is_file() and sha(recipe_path.read_bytes()) == RECIPE_SHA, "Recipe JSON missing or hash mismatch")

    probe_report_path = ROUND / "native-probe/native_report.json"
    probe_report = read_json(probe_report_path)
    need(probe_report.get("ok") is True, "Native probe audit failed or incomplete")
    need(probe_report.get("sha256") == DIGESTS["modified15"], "Native probe candidate hash mismatch")
    neg = probe_report.get("m600_v2_extended_shutter_probe", {}).get("negative_control_modified14", {})
    need(neg.get("reproduced_exact_hardware_tmode_lock") is True, "Missing Modified14 T-mode lock negative-control proof")

    updater_report_path = ROUND / "updater-audit/result.json"
    updater_report = read_json(updater_report_path)
    need(updater_report.get("ok") is True, "Updater audit failed or incomplete")

    lab_manifest_path = ROUND / "lab-build/manifest.json"
    manifest = read_json(lab_manifest_path)
    need(manifest.get("ok") is True and manifest.get("sha256") == DIGESTS["modified15"], "Lab build manifest invalid")

    return {
        "recipe": recipe_path,
        "native_probe": probe_report_path,
        "updater_audit": updater_report_path,
        "manifest": lab_manifest_path,
    }


def package(dest: Path) -> None:
    print("Checking Modified15 packaging inputs and release gates...")
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
        "01_TEST_MODIFIED15",
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
    shutil.copy2(THIS_DIR / "verify_modified15_kit.py", staging_dir / "verify.py")

    readme_text = """Nikon Z6 C3.80 Astro Convergence + 30-600s v2 Extended Shutter Firmware (Modified15)
====================================================================================

Model: Nikon Z6 (first generation)
Base Firmware: Official C3.80 (EG162080.BIN)
Supersedes: Modified14 (fixes real-camera T-mode / shutter-dial lockup)
Status: Preflash Candidate (Offline Unicorn ARM/Thumb + Updater Verified; Pending Real-Camera Test)

Package Contents:
  - 01_TEST_MODIFIED15/EG162080.BIN    : Modified15 (Modified13 astro RAW convergence + fixed 60"-600" M-still shutter)
  - 02_BACK_TO_MODIFIED13/EG162080.BIN : [RECOMMENDED RECOVERY FALLBACK 1] Camera-verified Modified13 baseline
  - 03_BACK_TO_MODIFIED12/EG162080.BIN : [RECOMMENDED RECOVERY FALLBACK 2] Camera-verified Modified12 baseline
  - 04_BACK_TO_MODIFIED10/EG162080.BIN : Camera-verified Modified10 baseline
  - 05_STOCK_C380/EG162080.BIN         : Official factory stock firmware C3.80
  - reports/                           : Canonical recipe.json, Unicorn native_probe.json, updater_audit.json, manifest.json
  - verify.py                          : Standalone stdlib-only offline integrity & dual-build verifier

 Note: Modified14 (SHA-256 6d970609...) is intentionally excluded from rollback targets because its
       47-entry 0x204 dependency table shifted context offsets by +4B, setting 0x204 err=1 and locking
       the command dial in the pre-flash shutter state (e.g. Time / T-mode).

What Modified15 Fixes Over Modified14:
  1. Preserves 100% factory Stock internal 0x204 property builder (0x10150602), 46-entry dependency list
     (0x114CBA14), and <=109-entry (0x1B4-byte) global/stack buffer ceiling (0xC18BD7C4[0], 0xC236BEBC).
  2. Enables mtbl[3..10] (600"..60") directly inside 0x1012D464 (ADDR_MTBL_TV_GATE @ 0x1002F7C0) strictly
     in M-still mode when 30" (-120) is allowed in 0x204, unlocking full dial stepping across Time <-> Bulb
     <-> 600"..60" <-> 30"..1/8000s across 1/3 EV, 1/2 EV, and 1 EV grids.
  3. Gates extended 0x204 values (-144..-224) in 0x10209636 (ADDR_PROP_ALLOW @ 0x1002F5F4, with R2 preserved
     for 0x1020963E) and appends them only into the 0x200-byte (128-entry) PTP GetDevicePropDesc buffers
     (ADDR_PTP_ENUM @ 0x1002FE00) for 0x500D and 0xD100 in M-still mode.
  4. Inherits all 14 camera-verified Modified13 astro RAW convergence patches byte-for-byte unchanged.
"""
    (staging_dir / "README.txt").write_text(readme_text, encoding="utf8")

    flash_text = """FLASHING AND RECOVERY INSTRUCTIONS
==================================

CRITICAL SAFETY WARNING:
  - NEVER TURN OFF THE CAMERA OR REMOVE THE BATTERY WHILE AN UPDATE IS IN PROGRESS.
  - Wait at least 15 minutes if the progress bar appears paused.
  - Cutting power during erase/write phases risks permanent hardware bricking.

Direct Upgrade from Modified14 (or Stock / Modified10 / Modified12 / Modified13):
  1. Charge Nikon EN-EL15b/c battery >= 80%.
  2. Format XQD / CFexpress Type B card in-camera (or clear any previous EG162080.BIN from card root).
  3. Copy ONLY 01_TEST_MODIFIED15/EG162080.BIN to the root directory of the memory card.
  4. Insert card into camera -> Menu -> Setup (Wrench) -> Firmware version -> Update.
  5. Wait until 'Update complete. Turn camera off.' appears, then turn the camera off and back on.

Post-Flash Verification Checklist:
  1. In M still photo mode (starting from Time / T-mode), rotate the rear main command dial right (faster):
     verify smooth transitions: Time -> Bulb -> 600" -> 480" -> 300" -> 240" -> 180" -> 120" -> 90" -> 60" -> 30" -> 25"...
     and rotate left (slower) back through 60"..600" -> Bulb -> Time.
  2. Test a 60" M-mode still exposure and verify ~60s wall-clock shutter duration and EXIF ExposureTime = 60s.
  3. Switch mode dial to A / S / P and Movie mode: verify no >30" shutter speed is exposed or executed
     (S/Movie use independent <=30" shutter properties; A/P clamp AE minimum Tv to 30").

Rollback Procedure (if ever needed):
  Copy 02_BACK_TO_MODIFIED13/EG162080.BIN (or 05_STOCK_C380/EG162080.BIN) to card root and run Firmware Update.
"""
    (staging_dir / "FLASH_INSTRUCTIONS.txt").write_text(flash_text, encoding="utf8")

    flash_cn = """尼康 Z6 C3.80 Modified15 刷机与实机验证步骤（修复 Modified14 锁死 T 门问题）
========================================================================

安全警告：
  - 固件升级期间严禁关机、严禁拔电池、严禁取出存储卡！
  - 若进度条短暂不动请耐心等待至少 15 分钟，断电可能导致主板变砖。

从 Modified14（或原厂 C3.80 / Modified13）直接刷入步骤：
  1. 确保 EN-EL15b/c 电池电量 >= 80%。
  2. 删除存储卡根目录旧的 EG162080.BIN，确保根目录同时只有一个固件文件。
  3. 将 01_TEST_MODIFIED15/EG162080.BIN 复制到 XQD / CFexpress 卡根目录。
  4. 插卡开机 -> 菜单 -> 设定菜单（扳手） -> 固件版本 -> 版本升级，按提示等待完成并关机重启。
     （注：Modified14 仍可正常进菜单直接覆盖升级到 Modified15，无需先退回原厂。）

刷入后实机核验清单：
  1. 在 M 档拍照模式下（即使刷机前停留在 Time / T 门），向右拨动主指令拨盘：
     确认依次切换：Time -> Bulb -> 600" -> 480" -> 300" -> 240" -> 180" -> 120" -> 90" -> 60" -> 30" -> 25"...
     再向左拨回，确认可顺畅退回 60"..600" -> Bulb -> Time（肩屏、背屏、EVF 均正常显示秒数）。
  2. 在 60" 档实拍一张，核对快门实际开启约 60 秒，且 NEF 的 EXIF 曝光时间为 60 秒。
  3. 切换到 A / S / P 档及视频模式，确认均不会暴露或执行超过 30" 的快门档位（S 档与视频档使用各自独立的 <=30" 快门参数，A/P 档自动测光慢门下限保持 30"）。

回滚指引（如需回退）：
  将卡根目录替换为 02_BACK_TO_MODIFIED13/EG162080.BIN（已实拍验证的 Modified13）或 05_STOCK_C380/EG162080.BIN 升级即可。
  （本包已刻意剔除存在拨盘锁死缺陷的 Modified14，防止误刷。）
"""
    (staging_dir / "FLASH_STEPS_CN.txt").write_text(flash_cn, encoding="utf8")

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
    print(f"Final Modified15 delivery kit ready: {dest.name} + {dest_zip.name} -> {final_res}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dest", type=Path, default=ROOT / "outputs/Z6-C380-modified15-reviewed-2026-11-15")
    args = ap.parse_args()
    package(args.dest)


if __name__ == "__main__":
    main()

"""Assess offline preflash reviews, package Modified16 (Astro UI-Switchable + 30-600s v2) kit, and run self-checks."""
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

from verify_modified16_kit import DIGESTS, PATHS, RECIPE_SHA, check_kit, need, sha

ROOT = THIS_DIR.parents[1]
ROUND = ROOT / "analysis/modified16-preflash-2026-11-15"

INPUT_SOURCES = {
    "modified16": ROUND / "lab-build/modified16-candidate.bi",
    "modified15": ROOT / "outputs/Z6-C380-modified15-reviewed-2026-11-15/01_TEST_MODIFIED15/EG162080.BIN",
    "modified13": ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN",
    "modified12": ROOT / "outputs/Z6-C380-modified12-reviewed-2026-11-14/01_TEST_MODIFIED12/EG162080.BIN",
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

    recipe_path = ROOT / "patches/z6-c380-modified16-astro-ui-600s.json"
    need(recipe_path.is_file() and sha(recipe_path.read_bytes()) == RECIPE_SHA, "Recipe JSON missing or hash mismatch")

    probe_report_path = ROUND / "native-probe/native_report.json"
    probe_report = read_json(probe_report_path)
    need(probe_report.get("ok") is True, "Native probe audit failed or incomplete")
    need(probe_report.get("sha256") == DIGESTS["modified16"], "Native probe candidate hash mismatch")
    neg = probe_report.get("permanent_m600_v2_extended_shutter", {}).get("negative_control_modified14", {})
    need(neg.get("reproduced_exact_hardware_tmode_lock") is True, "Missing Modified14 T-mode lock negative-control proof")

    updater_report_path = ROUND / "updater-audit/result.json"
    updater_report = read_json(updater_report_path)
    need(updater_report.get("ok") is True, "Updater audit failed or incomplete")

    lab_manifest_path = ROUND / "lab-build/manifest.json"
    manifest = read_json(lab_manifest_path)
    need(manifest.get("ok") is True and manifest.get("sha256") == DIGESTS["modified16"], "Lab build manifest invalid")

    return {
        "recipe": recipe_path,
        "native_probe": probe_report_path,
        "updater_audit": updater_report_path,
        "manifest": lab_manifest_path,
    }


def package(dest: Path) -> None:
    print("Checking Modified16 packaging inputs and release gates...")
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
        "01_TEST_MODIFIED16",
        "02_BACK_TO_MODIFIED15",
        "03_BACK_TO_MODIFIED13",
        "04_BACK_TO_MODIFIED12",
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
    shutil.copy2(THIS_DIR / "verify_modified16_kit.py", staging_dir / "verify.py")

    readme_text = """Nikon Z6 C3.80 UI-Switchable Astro Lossless RAW + Permanent 30-600s Extended Shutter Firmware (Modified16)
========================================================================================================

Model: Nikon Z6 (first generation)
Base Firmware: Official C3.80 (EG162080.BIN)
Supersedes: Modified15 (adds user-controllable in-camera menu toggle for Astro RAW mode)
Status: Preflash Candidate (Offline Unicorn ARM/Thumb + Updater Verified; Pending Real-Camera Test)

Package Contents:
  - 01_TEST_MODIFIED16/EG162080.BIN    : Modified16 (A3 UI-switchable 'Astro Lossless' + permanent 60"-600" M-still shutter)
  - 02_BACK_TO_MODIFIED15/EG162080.BIN : [RECOMMENDED RECOVERY FALLBACK 1] Camera-verified Modified15 baseline (permanent Astro + 600s)
  - 03_BACK_TO_MODIFIED13/EG162080.BIN : [RECOMMENDED RECOVERY FALLBACK 2] Camera-verified Modified13 baseline (permanent Astro)
  - 04_BACK_TO_MODIFIED12/EG162080.BIN : Camera-verified Modified12 baseline
  - 05_STOCK_C380/EG162080.BIN         : Official factory stock firmware C3.80
  - reports/                           : Canonical recipe.json, Unicorn native_probe.json, updater_audit.json, manifest.json
  - verify.py                          : Standalone stdlib-only offline integrity & dual-build verifier

Design A3 Architecture:
  Repurposes Option 2 (value == 2, stock 'Compressed' lossy RAW) in:
    Photo Shooting Menu -> NEF (RAW) recording -> NEF (RAW) compression (property 0x0506)

  1. Option 1 ('Lossless compressed' / '无损压缩', value == 1):
     - 100% Stock C3.80 RAW processing path (dark current clipping, factory CAL33 vignetting & spatial corrections active).
     - Standard Lossless NEF compression.
  2. Option 2 ('Astro Lossless' / '天文无损', value == 2):
     - 100% Modified13 14-site Astro RAW path (dark current clipping bypassed, spatial 33x4 & 17x17 ring modulation zeroed,
       full-size front RAW preserved).
     - Gated dynamically on effective NEF compression (0x1315 == 2 at 0xC24CC77C) AND effective RAW recording (0x131b <= 1 at 0xC24CC798).
     - Forced genuine Lossless NEF compression (lossless buffer allocation, hardware lossless codec [0xC23234C8]=1,
       EXIF MakerNote 0x0093 NEFCompression=3, remaining-shots capacity 0x40000318=1).
  3. Option 3 ('Uncompressed' / '未压缩', value == 0):
     - 100% Stock C3.80 RAW processing path.
     - Standard Uncompressed NEF.

Safety Invariants:
  - Medium/Small RAW natively sets 0x1315 = 1, automatically bypassing Astro mode.
  - JPEG-only recording modes (0x131b >= 2, including HDR/special forced JPEG) automatically bypass Astro mode.
  - In-camera Playback & Retouch of existing Lossy Compressed NEFs on SD/CFx cards remain 100% functional.
  - User Settings banks (U1/U2/U3) and Save/load settings preserve 0x0506 = 2 across power cycles.
  - Extended shutter speeds 60"-600" remain permanently active in M still mode regardless of the menu toggle.
"""
    (staging_dir / "README.txt").write_text(readme_text, encoding="utf8")

    flash_text = """FLASHING AND RECOVERY INSTRUCTIONS
==================================

CRITICAL SAFETY WARNING:
  - NEVER TURN OFF THE CAMERA OR REMOVE THE BATTERY WHILE AN UPDATE IS IN PROGRESS.
  - Wait at least 15 minutes if the progress bar appears paused.
  - Cutting power during erase/write phases risks permanent hardware bricking.

Direct Upgrade from Modified15 (or Stock / Modified12 / Modified13):
  1. Charge Nikon EN-EL15b/c battery >= 80%.
  2. Format XQD / CFexpress Type B card in-camera (or clear any previous EG162080.BIN from card root).
  3. Copy ONLY 01_TEST_MODIFIED16/EG162080.BIN to the root directory of the memory card.
  4. Insert card into camera -> Menu -> Setup (Wrench) -> Firmware version -> Update.
  5. Wait until 'Update complete. Turn camera off.' appears, then turn the camera off and back on.

Post-Flash Verification Checklist:
  1. Menu Toggle & UI Check:
     Go to Photo Shooting Menu -> NEF (RAW) recording -> NEF (RAW) compression.
     Verify the 3 options display as:
       - Lossless compressed (无损压缩)
       - Astro Lossless (天文无损 / 天文無損)
       - Uncompressed (未压缩)
     Press the '?' button on 'Astro Lossless' and verify clean localized help text without glyph truncation.
  2. Astro vs Normal RAW Toggle Test:
     - Select 'Astro Lossless': shoot a dark frame (cap on, 1/8000s, ISO 6400, Large RAW).
       Check in RawDigger: raw black level is centered around ~600 ADU with normal bell curve (zero dark clipping).
     - Select 'Lossless compressed': shoot another dark frame with identical settings.
       Check in RawDigger: raw dark clipping active (stock Nikon behavior with zero values).
  3. Extended Shutter Test:
     In M photo mode, verify rear command dial still rotates smoothly across 60"..600" -> Bulb -> Time.

Rollback Procedure (if ever needed):
  Copy 02_BACK_TO_MODIFIED15/EG162080.BIN (or 05_STOCK_C380/EG162080.BIN) to card root and run Firmware Update.
"""
    (staging_dir / "FLASH_INSTRUCTIONS.txt").write_text(flash_text, encoding="utf8")

    flash_cn = """尼康 Z6 C3.80 Modified16 刷机与实机验证步骤（菜单切换“天文无损” + 常驻 30-600s 扩展快门）
========================================================================================

安全警告：
  - 固件升级期间严禁关机、严禁拔电池、严禁取出存储卡！
  - 若进度条短暂不动请耐心等待至少 15 分钟，断电可能导致主板变砖。

直接刷入步骤（支持从已验证的 Modified15、Modified13 或原厂 C3.80 直接升级）：
  1. 确保 EN-EL15b/c 电池电量 >= 80%。
  2. 格式化存储卡（或删除存储卡根目录下旧的 EG162080.BIN）。
  3. 将 01_TEST_MODIFIED16/EG162080.BIN 复制到存储卡根目录。
  4. 插卡开机 -> 菜单 -> 设定菜单（扳手） -> 固件版本 -> 版本升级，按提示等待完成并关机重启。

刷入后实机核验清单：
  1. 菜单与 UI 检查：
     进入 照片拍摄菜单 -> NEF（RAW）记录 -> NEF（RAW）压缩：
     确认 3 个选项依次显示为：
       - 无损压缩（Lossless compressed）
       - 天文无损（Astro Lossless / 繁体系统显示为“天文無損”）
       - 未压缩（Uncompressed）
     选中“天文无损”按下“？”帮助键，确认帮助说明正常显示（已通过 36 国语言全字体库零乱码核验）。
  2. 天文 / 原厂路径动态切换实拍对比：
     - 设为“天文无损”，盖上镜头盖，M档 1/8000s ISO 6400 实拍一张：
       导入 RawDigger，核验 RAW 底噪直方图完整保留高斯分布（暗电流未被机内裁切），
       EXIF 压缩格式为 Lossless，文件体积与画质均为完整无损。
     - 切换为“无损压缩”，相同参数实拍一张：
       导入 RawDigger，核验已自动恢复原厂暗电流裁切（原厂日常拍摄模式）。
  3. 扩展快门常驻检查：
     在 M 档下向左/向右拨动主拨盘，确认 60"..600" 扩展快门依然常驻可用。

回滚指引（如需退回）：
  将卡根目录替换为 02_BACK_TO_MODIFIED15/EG162080.BIN（已实机验证的 Modified15）
  或 05_STOCK_C380/EG162080.BIN 升级即可。
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
    print(f"Final Modified16 delivery kit ready: {dest.name} + {dest_zip.name} -> {final_res}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dest", type=Path, default=ROOT / "outputs/Z6-C380-modified16-reviewed-2026-11-15")
    args = ap.parse_args()
    package(args.dest)


if __name__ == "__main__":
    main()

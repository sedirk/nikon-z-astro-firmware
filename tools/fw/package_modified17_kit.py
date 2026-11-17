"""Package Modified17 kit and run self-checks."""
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

from verify_modified17_kit import DIGESTS, PATHS, RECIPE_SHA, check_kit, need, sha

ROOT = THIS_DIR.parents[1]
ROUND = ROOT / "analysis/modified17-preflash-2026-11-15"

INPUT_SOURCES = {
    "modified17": ROUND / "lab-build/modified17-candidate.bi",
    "modified16": ROOT / "outputs/Z6-C380-modified16-reviewed-2026-11-15/01_TEST_MODIFIED16/EG162080.BIN",
    "modified15": ROOT / "outputs/Z6-C380-modified15-reviewed-2026-11-15/01_TEST_MODIFIED15/EG162080.BIN",
    "modified13": ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN",
    "stock": ROOT / "firmware/decoded/eg1620_038000.bi",
}


def verify_release_gates() -> dict:
    for name, src_path in INPUT_SOURCES.items():
        need(src_path.is_file(), f"Input binary missing: {src_path}")
        file_sha = sha(src_path.read_bytes())
        need(file_sha == DIGESTS[name], f"Input hash mismatch for {name}: {file_sha} != {DIGESTS[name]}")

    recipe_path = ROOT / "patches/z6-c380-modified17-focus-astro-600s.json"
    need(recipe_path.is_file() and sha(recipe_path.read_bytes()) == RECIPE_SHA, "Recipe JSON missing or hash mismatch")

    probe_report_path = ROUND / "native-probe/native_report.json"
    probe_report = json.loads(probe_report_path.read_text(encoding="utf8"))
    need(probe_report.get("ok") is True, "Native probe audit failed or incomplete")

    updater_report_path = ROUND / "updater-audit/result.json"
    updater_report = json.loads(updater_report_path.read_text(encoding="utf8"))
    need(updater_report.get("ok") is True, "Updater audit failed or incomplete")

    lab_manifest_path = ROUND / "lab-build/manifest.json"
    manifest = json.loads(lab_manifest_path.read_text(encoding="utf8"))
    need(manifest.get("ok") is True, "Lab build manifest invalid")

    return {
        "recipe": recipe_path,
        "native_probe": probe_report_path,
        "updater_audit": updater_report_path,
        "manifest": lab_manifest_path,
    }


def package(dest: Path) -> None:
    print("Checking Modified17 packaging inputs and release gates...")
    gates = verify_release_gates()
    print("Release gates passed: 5 binaries + recipe + Unicorn probe + updater audit verified.")

    staging_dir = dest.parent / f".staging_{dest.name}"
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True)

    # 1. Copy firmware binaries
    for name, rel_path in PATHS.items():
        target_path = staging_dir / rel_path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(INPUT_SOURCES[name], target_path)

    # 2. Copy audit artifacts
    audit_dst = staging_dir / "audit"
    audit_dst.mkdir(parents=True, exist_ok=True)
    shutil.copy2(gates["recipe"], audit_dst / gates["recipe"].name)
    shutil.copy2(gates["native_probe"], audit_dst / "native_report.json")
    shutil.copy2(gates["updater_audit"], audit_dst / "updater_audit.json")
    shutil.copy2(gates["manifest"], audit_dst / "manifest.json")

    # 3. Create README and flash instructions
    readme_text = f"""# Nikon Z6 C3.80 Modified17 固件交付包

## 核心特性更新 (Modified17)
1. **待机休眠唤醒对焦位置自动恢复 (Standby Focus Restoration)**：
   - 彻底修复唯卓仕（Viltrox）AF 16mm F1.8 Z 等 Z 卡口线控镜头在相机待机休眠（半按快门或延时休眠唤醒）后自动重置到假无限远（`∞`，实际星点真无限远在 `5.2m`）的跑焦问题。
   - 在相机唤醒完成镜头握手后，自动通过镜头设置引擎触发对焦位置恢复。
   - 仅在机身“保存对焦位置”开启时生效；若关闭则完全透传原厂行为。
2. **“保存对焦位置”出厂/复位默认开启 (Default-ON)**：
   - 设定菜单（扳手图标）→ `保存对焦位置`（Save focus position）出厂与复位默认值由 `关闭` 改为 `开启`。
3. **完整继承 Modified16 全部特性**：
   - 设定菜单 `a3 空焦跟踪对焦灵敏度` 动态切换“天文无损模式”（1=原厂无损压缩，2=天文极客无损，3=原厂未压缩）。
   - M 档常驻 30s–600s 慢门常驻长曝光支持。
   - 完整保留暗电流微弱星光、彻底消除同心圆彩圈及吃星空间滤波。

## 固件文件哈希清单
- `01_TEST_MODIFIED17/EG162080.BIN`: SHA256 `{DIGESTS['modified17']}`
- `02_BACK_TO_MODIFIED16/EG162080.BIN`: SHA256 `{DIGESTS['modified16']}`
- `03_BACK_TO_MODIFIED15/EG162080.BIN`: SHA256 `{DIGESTS['modified15']}`
- `04_BACK_TO_MODIFIED13/EG162080.BIN`: SHA256 `{DIGESTS['modified13']}`
- `05_STOCK_C380/EG162080.BIN`: SHA256 `{DIGESTS['stock']}`
"""
    (staging_dir / "README.md").write_text(readme_text, encoding="utf8")

    flash_text = """# 刷机操作指南

1. 准备一张在相机中格式化过的 XQD / CFexpress 卡。
2. 将 `01_TEST_MODIFIED17/EG162080.BIN` 复制到存储卡的根目录下（请勿修改文件名）。
3. 相机装入满电原装电池，开机进入菜单：`设定菜单`（扳手图标）→ `固件版本`。
4. 屏幕将显示“更新固件”，选择确定，更新过程中严禁切断电源或取出卡。
5. 更新完成后按提示关机并重启相机。
6. 如需回滚到 Modified16、Modified15 或原厂官方固件，将对应目录下的 `EG162080.BIN` 放入存储卡根目录按相同步骤刷新即可。
"""
    (staging_dir / "FLASH_INSTRUCTIONS.md").write_text(flash_text, encoding="utf8")

    if dest.exists():
        shutil.rmtree(dest)
    staging_dir.rename(dest)

    # 4. Create ZIP
    zip_path = dest.with_suffix(".zip")
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in dest.rglob("*"):
            zf.write(file, file.relative_to(dest.parent))

    print(f"Kit packaged to {dest}")
    print(f"Zip created at {zip_path}")

    # 5. Run verification
    print("Running independent verification on packaged kit...")
    verify_res = check_kit(dest)
    print("Verification result:", verify_res)


def main():
    dest = ROOT / "outputs" / "Z6-C380-modified17-reviewed-2026-11-15"
    package(dest)


if __name__ == "__main__":
    main()

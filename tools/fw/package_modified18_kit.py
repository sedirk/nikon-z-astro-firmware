"""Package Modified18 (Design A1: Color Space Switchable Astro RAW + Permanent 30-600s v2) delivery kit and run self-checks."""
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

from verify_modified18_kit import DIGESTS, PATHS, check_kit, need, sha

ROOT = THIS_DIR.parents[1]
ROUND = ROOT / "analysis/modified18-preflash-2026-11-15"

INPUT_SOURCES = {
    "modified18": ROUND / "lab-build/modified18-candidate.bi",
    "modified15": ROOT / "outputs/Z6-C380-modified15-reviewed-2026-11-15/01_TEST_MODIFIED15/EG162080.BIN",
    "modified13": ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN",
    "modified12": ROOT / "outputs/Z6-C380-modified12-reviewed-2026-11-14/01_TEST_MODIFIED12/EG162080.BIN",
    "stock": ROOT / "firmware/decoded/eg1620_038000.bi",
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "outputs/Z6-C380-modified18-reviewed-2026-11-15",
    )
    args = ap.parse_args()

    kit_dir = args.output_dir.resolve()
    print(f"Creating delivery kit at: {kit_dir}")

    if kit_dir.exists():
        shutil.rmtree(kit_dir)
    kit_dir.mkdir(parents=True, exist_ok=True)

    for name, rel in PATHS.items():
        src = INPUT_SOURCES[name]
        need(src.is_file(), f"Missing input source: {src}")
        dst = kit_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        assert sha(dst.read_bytes()) == DIGESTS[name]
        print(f"  [OK] Copied {name} -> {rel}")

    # Copy audit files into kit
    audit_dst = kit_dir / "audit"
    audit_dst.mkdir(parents=True, exist_ok=True)
    manifest_src = ROUND / "lab-build/modified18-manifest.json"
    if manifest_src.is_file():
        shutil.copy2(manifest_src, audit_dst / "modified18-manifest.json")
    probe_src = ROUND / "lab-build/probe_modified18_native_result.json"
    if probe_src.is_file():
        shutil.copy2(probe_src, audit_dst / "probe_modified18_native_result.json")

    # Write flash instructions
    readme_txt = kit_dir / "FLASH_INSTRUCTIONS.txt"
    readme_txt.write_text(
        """Nikon Z6 C3.80 Modified18 (Design A1: Color Space Switchable Astro RAW + Permanent 30-600s v2)
====================================================================================================

【主要特性】
1. 方案 A1 拍摄菜单「色空间」天文 RAW 开关：
   - 「sRGB」: 原厂标准模式 (Stock)。100% 官方原厂 ISP 流程与画质。
   - 「Adobe RGB」: 天文直通模式 (Astro ON)。
     * 自动旁路机内暗电流热噪点裁切（释放全部真实暗电流与星点弱信号）；
     * 自动清零 2D 多项式空间畸变与色彩台阶；
     * 自动归一化 CAL33 Group 4 空间暗角与数字增益；
     * 自动旁路双 17 点空间滤波表；
     * 全尺寸 RAW 直通，彻底消除同心彩圈。

2. 与 RAW 压缩方式彻底解耦（满足天文未压缩 RAW 诉求）：
   - 本固件完全恢复了「NEF(RAW)压缩」菜单（0x0506）的官方原版定义：
     * 选项 0：未压缩 (Uncompressed)
     * 选项 1：无损压缩 (Lossless compressed)
     * 选项 2：压缩(有损) (Compressed)
   - 当你在色空间选为「Adobe RGB」(天文直通) 时：
     * 若在 NEF 压缩选「未压缩」，机身直接输出 原生未压缩天文 RAW！
       无需 CPU 逐帧进行 Huffman 变长解压，PixInsight / Siril 极速载入、校准与堆栈！
     * 若在 NEF 压缩选「无损压缩」，机身直接输出 标准无损压缩天文 RAW。

3. 底层色彩与文件名安全锁：
   - 固件底层锁死 EXIF 色彩空间标记为 sRGB；
   - 文件名前缀永远保持标准的 DSC_xxxx.NEF，绝不变成 _DSCxxxx；
   - 机内预览 JPEG 永远保持标准 sRGB 色彩，绝不偏色。

4. 永久常驻 30–600s 慢门长曝光：
   - M 档波轮直接连续旋转：30" -> 60" -> 90" -> 120" -> 180" -> 240" -> 300" -> 400" -> 500" -> 600"；
   - 零双倍黑屏等待，零误判，与天文直通完美共存。

5. 快捷操作建议：
   - 可以把「色空间」放进取景界面的「i 快捷菜单」，一键秒切；
   - 可以把色空间设为「Adobe RGB」，并将模式转盘保存到「U3」档位。
     野外拍摄时拧到 U3 自动进入「M 档 + 300s + 天文直通 + 未压缩 RAW」，拧回 M 档自动恢复日常相机！

【刷机指南】
- 刷机测试：将 01_TEST_MODIFIED18/EG162080.BIN 复制到 XQD/CFexpress 卡根目录，进入相机「设定菜单」->「固件版本」进行升级。
- 完整回滚：若需退回，卡根目录放置对应的回滚固件升级即可：
  * 02_BACK_TO_MODIFIED15: Modified15 (常驻 600s + 纯天文直通，无菜单开关)
  * 03_BACK_TO_MODIFIED13: Modified13 (纯天文直通，无 600s)
  * 05_STOCK_C380: 官方原版 C3.80 固件
""",
        encoding="utf-8",
    )

    # Verification
    print("Running verification on generated delivery kit...")
    res = check_kit(kit_dir)
    print(f"  [PASS] {res['verified_slots']} firmware slots verified successfully!")

    # Create ZIP archive
    zip_path = ROOT / f"outputs/{kit_dir.name}.zip"
    print(f"Creating ZIP archive: {zip_path}")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in kit_dir.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(kit_dir.parent))
    print(f"  [OK] ZIP size: {zip_path.stat().st_size:,} bytes")
    print(f"\nMODIFIED18 PACKAGING COMPLETE: {kit_dir}")


if __name__ == "__main__":
    main()

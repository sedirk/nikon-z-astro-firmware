"""Package Nikon Z6 C3.80 Modified19 reviewed delivery kit and ZIP archive."""
from __future__ import annotations
import argparse
from pathlib import Path
import shutil
import sys
import zipfile

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from verify_modified19_kit import DIGESTS, PATHS, check_kit, need, sha

ROOT = THIS_DIR.parents[1]
ROUND = ROOT / "analysis/modified19-preflash-2026-11-16"

INPUT_SOURCES = {
    "modified19": ROUND / "lab-build/modified19-candidate.bi",
    "modified18": ROOT / "outputs/Z6-C380-modified18-reviewed-2026-11-15/01_TEST_MODIFIED18/EG162080.BIN",
    "modified15": ROOT / "outputs/Z6-C380-modified15-reviewed-2026-11-15/01_TEST_MODIFIED15/EG162080.BIN",
    "modified13": ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN",
    "stock": ROOT / "firmware/decoded/eg1620_038000.bi",
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "outputs/Z6-C380-modified19-reviewed-2026-11-16",
    )
    args = ap.parse_args()

    kit_dir = args.output_dir.resolve()
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

    audit_dst = kit_dir / "audit"
    audit_dst.mkdir(parents=True, exist_ok=True)
    for src in (
        ROUND / "lab-build/modified19-manifest.json",
        ROUND / "lab-build/probe_modified19_native_result.json",
        ROUND / "updater-audit/updater_audit.json",
    ):
        if src.is_file():
            shutil.copy2(src, audit_dst / src.name)

    shutil.copy2(THIS_DIR / "verify_modified19_kit.py", kit_dir / "verify.py")

    readme_txt = kit_dir / "FLASH_INSTRUCTIONS.txt"
    readme_txt.write_text(
        """Nikon Z6 C3.80 Modified19 (Astro RAW Mode Full UI v2 + Post-Exposure Interval Timer + Permanent 30-600s v2)
===========================================================================================================

【本次升级核心更新 (相对 Modified18)】
1. 照片拍摄菜单 / i 快捷菜单「色空间」全项直观重命名（全机 36 种语言零缺字）：
   - 菜单标题 (0x03B3)：原厂「色空间」 -> 「天文直通模式」 (英文: Astro RAW mode)
   - 选项 0   (0x03B4)：原厂「sRGB」   -> 「标准 (sRGB)」   (英文: Standard (sRGB)) -> 100% 原厂 ISP 流程
   - 选项 1   (0x03B5)：原厂「Adobe RGB」-> 「天文直通」     (英文: Astro RAW)      -> 13 点全尺寸天文直通 RAW
   - 状态行标签 (0x082B/0x082C)：同步改为单行「标准 (sRGB)：」/「天文直通：」

2. 彻底修复原厂「间隔拍摄 (Interval Timer Shooting)」长曝光吞张数 Bug，并统一改为「曝光结束后间隔」：
   - 原厂 Bug 根因：
     * 尼康原厂显示的「30"」慢门，底层实际快门时间为 2^5 = 32.000 秒（加上读出约 32.25 秒），而我们的扩展快门
       60" / 90" / 120" / 300" / 600" 为精确十进制秒数（如 60.000 秒）。
     * 原厂间隔拍摄 (0x101FF380) 按「上一张预定开始时间 + 间隔」计算刚性时间网格：
       - 当设 30" + 1s 间隔拍 32 张时，单张 32.25s 曝光结束后进入 0x101FF3E4 追赶循环，一次性在后台扣光 31~32 次
         快门计数，导致只拍 1~2 张就提前结束；
       - 当设 30" + 31s 间隔时，因「30"」实为 32.25s，错过了 31.0s 触发点 1.25s，导致扣掉 1 次计数并推迟到 62.0s，
         表现为曝光结束后又干等约 30~31 秒才拍下一张！
   - Modified19 修复方案 (0x101FF392)：
     * 将间隔拍摄下一张目标时间统一改为「当前快门完成时刻 now_ms + 间隔时间 interval_ms」（与尼康自家的焦距变化拍摄
       0x10206A4E 逻辑完全一致）。
     * 现在无论使用 30" 还是 60"~600"，想在快门结束后等 1 秒就拍下一张，直接将间隔设为「00:00:01」（甚至最短 0.5s）即可！
     * 支持多张连拍组（间隔数 x 每次拍摄张数 > 1）；「间隔拍摄短片 (Time-Lapse Movie)」保持原厂不变。
     * 注意：间隔拍摄菜单界面静态预估的「结束时间」不含快门曝光时长（实际结束时间 = 预估时间 + 总张数 x 单张曝光时间），
       拍摄期间肩屏/屏幕的帧间倒计时则完全准确。

3. 完整继承 Modified18 全部特性：
   - 与「NEF(RAW)压缩」完全解耦：天文直通模式下可自由选择「未压缩 RAW」或「无损压缩 RAW」；
   - 底层锁定 sRGB (0x1040AD00)：文件名永远保持 DSC_xxxx.NEF，EXIF 与机内预览色彩 100% 正常；
   - 常驻 M 档 30"~600" (60"/90"/120"/180"/240"/300"/480"/600") 扩展慢门。

【刷机与回滚指南】
- 升级 Modified19：将 01_TEST_MODIFIED19/EG162080.BIN 复制到存储卡根目录，进入「设定菜单 -> 固件版本」升级。
- 随时无损回滚：
  * 02_BACK_TO_MODIFIED18/EG162080.BIN : 回退至 Modified18
  * 03_BACK_TO_MODIFIED15/EG162080.BIN : 回退至 Modified15 (常驻天文 + 600s)
  * 04_BACK_TO_MODIFIED13/EG162080.BIN : 回退至 Modified13 (常驻天文，无 600s)
  * 05_STOCK_C380/EG162080.BIN         : 回退至尼康官方原版 C3.80
""",
        encoding="utf-8",
    )

    res = check_kit(kit_dir)
    zip_path = ROOT / f"outputs/{kit_dir.name}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in kit_dir.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(kit_dir.parent))
    print(f"MODIFIED19 KIT PACKAGED | slots={res['verified_slots']} | zip={zip_path.name} ({zip_path.stat().st_size:,} B)")


if __name__ == "__main__":
    main()

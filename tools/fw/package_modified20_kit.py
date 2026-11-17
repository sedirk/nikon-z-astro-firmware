"""Package Nikon Z6 C3.80 Modified20 release kit + zip archive."""
from __future__ import annotations
import argparse
from pathlib import Path
import shutil
import sys
import zipfile

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from verify_modified20_kit import DIGESTS, PATHS, check_kit, need, sha

ROOT = THIS_DIR.parents[1]
ROUND = ROOT / "analysis/modified20-preflash-2026-11-16"

INPUT_SOURCES = {
    "modified20": ROUND / "lab-build/modified20-candidate.bi",
    "modified19": ROOT / "outputs/Z6-C380-modified19-reviewed-2026-11-16/01_TEST_MODIFIED19/EG162080.BIN",
    "modified18": ROOT / "outputs/Z6-C380-modified18-reviewed-2026-11-15/01_TEST_MODIFIED18/EG162080.BIN",
    "modified15": ROOT / "outputs/Z6-C380-modified15-reviewed-2026-11-15/01_TEST_MODIFIED15/EG162080.BIN",
    "stock": ROOT / "firmware/decoded/eg1620_038000.bi",
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "outputs/Z6-C380-modified20-reviewed-2026-11-16",
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
        ROUND / "lab-build/modified20-manifest.json",
        ROUND / "lab-build/probe_modified20_native_result.json",
        ROUND / "updater-audit/updater_audit.json",
    ):
        if src.is_file():
            shutil.copy2(src, audit_dst / src.name)

    shutil.copy2(THIS_DIR / "verify_modified20_kit.py", kit_dir / "verify.py")

    readme_txt = kit_dir / "FLASH_INSTRUCTIONS.txt"
    readme_txt.write_text(
        """Nikon Z6 C3.80 Modified20 (Astro RAW UI v3 + Dynamic Interval End-Time + Post-Exposure Gap + 600s v2)
=====================================================================================================

【本次升级核心更新 (相对 Modified19)】
1. 「天文直通RAW模式」菜单文案升级（全机 36 种语言 100% 零缺字，排版充裕）：
   - 菜单标题 (0x03B3)：简体「天文直通RAW模式」 / 繁体「天文直通 RAW 模式」 / 英文「Astro RAW mode」
   - 选项 0   (0x03B4)：简体「标准 (sRGB)」     / 繁体「標準 (sRGB)」       / 英文「Standard (sRGB)」 -> 100% 原厂 ISP 流程
   - 选项 1   (0x03B5)：简体「天文直通RAW」     / 繁体「天文直通 RAW」      / 英文「Astro RAW」      -> 13 点全尺寸天文直通 RAW
   - 状态行标签 (0x082B/0x082C)：简体「标准 (sRGB)：」/「天文直通RAW：」，繁体「標準 (sRGB)：」/「天文直通 RAW：」

2. 间隔拍摄菜单底部「结束日期/时间 (End day/time)」动态精准计算 (0x1049C26C -> 0x1002E000)：
   - 原厂缺陷：尼康原厂在 0x1049C19A 中写死了 32s 且仅计入 1 次间隔的曝光开销，完全无视实际设定的快门速度。
   - Modified20 动态公式：
       总耗时 = (间隔次数 - 1) × 曝光后间隔 + 总张数(N × K) × (当前快门实际曝光时长 + 长曝光降噪 + 曝光延迟)
   - 全模式自动适配：
     * M 档定时快门：精准读取原厂全档位（含 30" = 32.0s）及扩展慢门 60"/90"/120"/180"/240"/300"/480"/600"；
     * M 档 x200 闪光同步：自动读取 0x1034 同步快门时长；Bulb / Time 档按 0ms 曝光计；
     * S 档快门优先：读取拨盘快门并自动钳位 <= 30" (32.0s)；
     * P / A / Auto 档：自动读取当前测光快门有理数 (0x1308)，未测光或 Lo/Hi 时安全记为 0ms；
     * 长曝光降噪 (0x0528)：快门慢于 1" (>1000ms) 且开启降噪时自动叠加暗场时长；
     * 曝光延迟模式 (0x1025)：自动叠加 0.2s / 0.5s / 1s / 2s / 3s 延迟；
     * 间隔拍摄暂停界面 (0x9E)：自动按剩余总张数与剩余间隔数实时重算结束时间。

3. 完整继承 Modified19 / Modified18 全部核心特性：
   - 间隔拍摄曝光后计时 (0x101FF392)：间隔时间统一定义为「快门结束后 -> 下一张开始前的纯等待时间」，彻底杜绝长曝光后台吞张数；
   - 与「NEF(RAW)压缩」完全解耦（支持未压缩 RAW 与无损压缩 RAW），底层锁定 sRGB (DSC_xxxx.NEF)；
   - 常驻 M 档 30"~600" 扩展慢门。

【刷机与回滚指南】
- 升级 Modified20：将 01_TEST_MODIFIED20/EG162080.BIN 复制到存储卡根目录，进入「设定菜单 -> 固件版本」升级。
- 随时无损回滚：
  * 02_BACK_TO_MODIFIED19/EG162080.BIN : 回退至 Modified19
  * 03_BACK_TO_MODIFIED18/EG162080.BIN : 回退至 Modified18
  * 04_BACK_TO_MODIFIED15/EG162080.BIN : 回退至 Modified15 (常驻天文 + 600s)
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
    print(f"MODIFIED20 KIT PACKAGED | slots={res['verified_slots']} | zip={zip_path.name} ({zip_path.stat().st_size:,} B)")


if __name__ == "__main__":
    main()

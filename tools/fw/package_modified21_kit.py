"""Package the 5-slot Modified21 reviewed kit + zip archive."""
from __future__ import annotations
import argparse
from pathlib import Path
import shutil
import sys
import zipfile

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from verify_modified21_kit import DIGESTS, PATHS, check_kit, need, sha

ROOT = THIS_DIR.parents[1]
ROUND = ROOT / "analysis/modified21-preflash-2026-11-16"

INPUT_SOURCES = {
    "modified21": ROUND / "lab-build/modified21-candidate.bi",
    "modified20": ROOT / "outputs/Z6-C380-modified20-reviewed-2026-11-16/01_TEST_MODIFIED20/EG162080.BIN",
    "modified19": ROOT / "outputs/Z6-C380-modified19-reviewed-2026-11-16/01_TEST_MODIFIED19/EG162080.BIN",
    "modified15": ROOT / "outputs/Z6-C380-modified15-reviewed-2026-11-15/01_TEST_MODIFIED15/EG162080.BIN",
    "stock": ROOT / "firmware/decoded/eg1620_038000.bi",
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "outputs/Z6-C380-modified21-reviewed-2026-11-16",
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
        ROUND / "lab-build/modified21-manifest.json",
        ROUND / "lab-build/probe_modified21_native_result.json",
        ROUND / "updater-audit/updater_audit.json",
    ):
        need(src.is_file(), f"Missing audit artifact: {src}")
        shutil.copy2(src, audit_dst / src.name)

    shutil.copy2(THIS_DIR / "verify_modified21_kit.py", kit_dir / "verify.py")

    readme_txt = kit_dir / "FLASH_INSTRUCTIONS.txt"
    readme_txt.write_text(
        """Nikon Z6 C3.80 Modified21 (Astro RAW Switch Fix + True sRGB Lock + '标准 (sRGB) / 直通RAW (sRGB)' + Interval End-Time + 600s v2)
=================================================================================================================================

【本次升级核心修复与更新 (相对 Modified20)】
1. 修复色空间菜单切换「天文直通RAW」失效问题 (关键修复)：
   - 根因：Modified18..20 中谓词门控误读了 0xC24CDDC4（实为 PID 0x0440 焦距变化拍摄张数，默认 100 != 1），导致 13 处天文直通 RAW 钩子未触发。
   - 修复：将 `fn_is_astro_r0` 门控修正为读取 PID 0x0508 的真实 RAM 地址 `0xC24CDE28` (`uint32([0xC24CDE28]) == 1 && uint32([0xC24CC798]) <= 1`)，已通过原厂 `GetProperty(0x0508)` 与全部 13 处钩子双分支离线 Unicorn 仿真验证。

2. 锁定照片拍摄态底层有效色空间为 sRGB (0x1014F678 -> 0x1381 = 0)：
   - 根因：此前仅锁定了 UI 灰置条件桩 0x1040AD00，未锁定照片模式有效色空间评估器 0x1014F638 (`0x1381`)，导致选到直通档时文件名变为 `_Z61xxxx.NEF` 且 MakerNote ColorSpace 变为 Adobe RGB。
   - 修复：在 `0x1014F678` 将照片模式有效色空间 `0x1381` (`0xC24CC948`) 统一锁定为 `0 (sRGB)`，同时保留菜单属性 `0x0508` (`0xC24CDE28`) 为 `0/1`：
     * 取景/信息屏外部依然保留 `Adobe` 图标作为「直通RAW已开启」的状态提示；
     * 内嵌预览 JPEG、RAW+JPEG 伴生 JPG、MakerNote 色空间及文件名前缀 (`Z61_xxxx.NEF` / `DSC_xxxx.NEF`) 设计为统一保持标准 sRGB（已通过 `0x1014F638` 离线仿真验证，待实机拍摄复核）。

3. 选项文字更新为「标准 (sRGB)」/「直通RAW (sRGB)」（全机 36 种语言字库扫描零缺字）：
   - 菜单标题 (0x03B3)：简体「天文直通RAW模式」 / 繁体「天文直通 RAW 模式」 / 英文「Astro RAW mode」
   - 选项 0   (0x03B4)：简体「标准 (sRGB)」     / 繁体「標準 (sRGB)」       / 英文「Standard (sRGB)」  -> 原厂 ISP 流程
   - 选项 1   (0x03B5)：简体「直通RAW (sRGB)」  / 繁体「直通RAW (sRGB)」    / 英文「Astro RAW (sRGB)」 -> 13 点全尺寸天文直通 RAW
   - 状态行   (0x082B/0x082C)：简体「标准 (sRGB)：」/「直通RAW (sRGB)：」，繁体「標準 (sRGB)：」/「直通RAW (sRGB)：」

4. 完整保留 Modified20 / Modified19 全部特性：
   - 间隔拍摄曝光后纯等待间隔计时 (`0x101FF392`) + 动态结束日期/时间计算 (`0x1049C26C -> 0x1002E000`)；
   - 与「NEF(RAW)压缩」完全解耦（自由选择未压缩 RAW 或无损压缩 RAW），支持存入 U1/U2/U3 与 `i` 快捷菜单；
   - 常驻 M 档 30"~600" 扩展慢门（60"/90"/120"/180"/240"/300"/480"/600"）。

【验证边界与刷机安全须知（必读）】
- 离线验证说明：本固件包已完成补丁摘要、CRC16-HQX、13 处钩子与评估器离线 Unicorn 仿真，以及升级器预检与块擦写调度的离线 RAM Flash 模型验证（`physical_flash=False`，未做物理闪存擦写或断电注入硬件测试）。
- 刷机前校验：解压后可在包根目录运行 `python verify.py` 复核全部 BIN 文件 SHA-256 与 CRC16。
- 实验固件规范：请使用满电原厂电池与可靠存储卡（格式化后仅放单个目标 `EG162080.BIN` 于根目录），升级全过程严禁断电、拔卡或按键中断。
- 升级步骤：将 `01_TEST_MODIFIED21/EG162080.BIN` 复制到存储卡根目录，进入机身「设定菜单 -> 固件版本」执行升级。
- 正常进系统后的回退槽位（仅在机身可正常开机进入「设定菜单 -> 固件版本」时适用）：
  * 02_BACK_TO_MODIFIED20/EG162080.BIN : 回退至 Modified20
  * 03_BACK_TO_MODIFIED19/EG162080.BIN : 回退至 Modified19
  * 04_BACK_TO_MODIFIED15/EG162080.BIN : 回退至 Modified15 (常驻天文 + 600s)
  * 05_STOCK_C380/EG162080.BIN         : 回退至尼康官方原版 C3.80

【刷机后实机验收清单】
1. 拍摄菜单与 `i` 菜单显示「标准 (sRGB)」/「直通RAW (sRGB)」，切至直通档时屏幕外侧显示 `Adobe` 提示图标；
2. 分别在两档下各拍一张全尺寸 RAW（推荐带平场或星野/暗场），确认直通档文件名前缀保持 `Z61_`/`DSC_`（非 `_Z61`）、MakerNote ColorSpace 为 sRGB，且 RAW 通道直方图梳状纹消失；
3. 验证 U1/U2/U3 档位保存切换、机内回放缩放、USB/PTP 连接及视频录制模式均工作正常。
""",
        encoding="utf-8",
    )

    res = check_kit(kit_dir)
    zip_path = ROOT / f"outputs/{kit_dir.name}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in kit_dir.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(kit_dir.parent))
    print(f"MODIFIED21 KIT PACKAGED | slots={res['verified_slots']} | zip={zip_path.name} ({zip_path.stat().st_size:,} B)")


if __name__ == "__main__":
    main()

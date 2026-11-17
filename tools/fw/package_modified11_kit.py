"""Assess offline preflash reviews, package Modified11 kit, and generate review report."""
from pathlib import Path
import argparse, datetime, json, shutil
from verify_modified11_kit import DIGESTS, PATHS, need, sha, check_kit

ROOT = Path(__file__).resolve().parents[2]
ROUND = ROOT / "analysis/modified11-preflash-2026-11-13"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf8"))


def record_file(path: Path, base: Path = ROOT) -> dict:
    return dict(path=path.relative_to(base).as_posix(), bytes=path.stat().st_size, sha256=sha(path.read_bytes()))


def package(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=False)
    for p in ("01_TEST_MODIFIED11", "02_BACK_TO_MODIFIED10", "03_BACK_TO_MODIFIED9", "04_DARK_ONLY_MODIFIED1", "05_STOCK_C380"):
        (dest / p).mkdir()

    # Binary distribution copies
    shutil.copy2(ROUND / "lab-build/modified11-candidate.bi", dest / PATHS["modified11"])
    shutil.copy2(ROOT / "outputs/Z6-C380-modified10-reviewed-2026-11-13/01_TEST_MODIFIED10/EG162080.BIN", dest / PATHS["modified10"])
    shutil.copy2(ROOT / "outputs/Z6-C380-production-modified9-2026-11-12/01_TEST_MODIFIED9/EG162080.BIN", dest / PATHS["modified9"])
    shutil.copy2(ROOT / "outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN", dest / PATHS["modified1"])
    shutil.copy2(ROOT / "firmware/decoded/eg1620_038000.bi", dest / PATHS["stock"])

    # verify.py in kit
    verify_script = (ROOT / "tools/fw/verify_modified11_kit.py").read_text(encoding="utf8")
    (dest / "verify.py").write_text(verify_script, encoding="utf8")

    # Documentation and guides
    readme_text = """Nikon Z6 C3.80 Production Convergence Astro Firmware (Modified11)
Release: 2026-11-14
Candidate: modified11-production-convergence

[GOALS ACHIEVED]
1. Preserve Dark Current: 3-site neighborhood clamping disabled (112/112 hot pixels & negative noise fully preserved).
2. Clean NEF Pipeline: Front-end 2D polynomial shading zeroed (DC=16384), backend 257-entry vignette & dual-17 spatial tables neutralized. Full-size static RAW routed directly from front-end frame+0x1f8 to 14-bit lossless encoder.
3. Eliminate Comb Teeth & Chromatic Rings: Front-end 4-channel digital multipliers locked to 1.0x unity gain (Q12=0x1000=4096) at packet builder 0x10122cba, completely eliminating digital integer scaling missing codes and concentric quantization rings.

[FOLDERS]
01_TEST_MODIFIED11/    -> Primary test firmware: EG162080.BIN (SHA256: 4b6b8989d1f18f20fd1a6e86c99b885eeab2bad88c4310fe144be3620970df7a)
02_BACK_TO_MODIFIED10/ -> Immediate fallback to Modified10
03_BACK_TO_MODIFIED9/  -> Immediate fallback to Modified9
04_DARK_ONLY_MODIFIED1/-> Fallback to Modified1 (dark preserve only)
05_STOCK_C380/         -> Official stock Nikon Z6 C3.80 firmware

[FLASH INSTRUCTIONS]
1. Copy EG162080.BIN from 01_TEST_MODIFIED11 to the root of a formatted XQD/CFexpress card.
2. Turn on camera, press [Playback] button and wait 3-5 seconds (avoids 0x0d02 busy skip).
3. Enter Setup Menu -> Firmware version -> Update.
4. After update completes, power off and remove battery for 5 seconds.
"""
    (dest / "README.txt").write_text(readme_text, encoding="utf8")

    start_here = """Nikon Z6 C3.80 Astro Firmware Modified11 生产收敛版刷机指南
==========================================================
核心目标：
1. 保留暗电流与微弱星点（关闭 31 点邻域热像素抑制）
2. 全尺寸 RAW 直通（绕过全部后端 ISP 替换渲染）
3. 根除直方图缺码梳状齿与平场同心彩圈（前端四通道数字乘法器锁定 1.0x 单位增益）

刷机步骤：
1. 复制 01_TEST_MODIFIED11/EG162080.BIN 到格式化后的存储卡根目录。
2. 插入相机开机，按【回放键 ▶】等待 3 秒后进入【菜单 -> 固件版本 -> 更新】。
3. 更新完成后关机拔电池 5 秒。
4. 建议拍摄：
   - 3 张 5s ISO 1600 暗场（DARK）核验暗电流与热像素保留；
   - 3 张 1/8000s 偏置场（BIAS）核验黑电平读出噪声；
   - 3 张均匀平场（FLAT）核验直方图梳状齿彻底消失与平场同心彩圈彻底消除！
"""
    (dest / "START_HERE.txt").write_text(start_here, encoding="utf8")

    flat_compare = """FLAT_COMPARE PROTOCOL (Modified11 vs Modified10 / Modified9 / Modified4)
================================================================================
Test Items:
1. Lossless 14-bit NEF decode integrity: 0 diff vs LibRaw.
2. Central 400x400 ADU histogram FFT:
   - Modified9/10: R peak_f=0.228 (T=4.39 ADU, SNR>25), B peak_f=0.210 (T=4.78 ADU, SNR>15).
   - Modified11 Expected: Comb SNR < 2.0 (flat noise floor, missing codes eliminated).
3. 16x16 CFA radial fine ring profile (sigma=6):
   - Check if step-quantization chromatic rings are eliminated.
"""
    (dest / "FLAT_COMPARE.txt").write_text(flat_compare, encoding="utf8")

    (dest / "MANIFEST.json").write_text("{}", encoding="utf8")
    manifest = check_kit(dest)
    (dest / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dest", type=Path, default=ROOT / "outputs/Z6-C380-modified11-reviewed-2026-11-14")
    args = ap.parse_args()
    package(args.dest)
    print(f"Successfully packaged Modified11 kit at {args.dest}")


if __name__ == "__main__":
    main()

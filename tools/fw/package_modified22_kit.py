"""Non-destructively package the Modified22 reviewed or clean-clone flash kit.

Safety guarantees:
  - Validates output directory path and ALL inputs in memory BEFORE touching disk.
  - Refuses to overwrite a non-empty existing directory unless `--force` is passed.
  - Stages into a sibling temporary directory and runs `check_kit` before atomic rename.
  - Automatically builds a 2-slot kit (`01_TEST_MODIFIED22` + `05_STOCK_C380`) on a clean
    clone with only official `Z_6_0380.bin`, or a 5-slot researcher kit when local
    Modified16/15/13 binaries are present.
"""
from __future__ import annotations
import argparse
import binascii
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from verify_modified22_kit import BASE, DIGESTS, OPTIONAL_SLOTS, PATHS, SIZE, check_kit, need, sha
from z6_c380_container import load_stock_eg_module

ROOT = THIS_DIR.parents[1]
ROUND = ROOT / "analysis/modified22-preflash-2026-11-17"
TRACKED_RECIPE = ROOT / "patches/z6-c380-modified22-color-space-pid0526-srgb-600s.json"

OPTIONAL_SOURCES = {
    "modified16": ROOT / "outputs/Z6-C380-modified16-reviewed-2026-11-15/01_TEST_MODIFIED16/EG162080.BIN",
    "modified15": ROOT / "outputs/Z6-C380-modified15-reviewed-2026-11-15/01_TEST_MODIFIED15/EG162080.BIN",
    "modified13": ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN",
}


def _validate_safe_output_dir(kit_dir: Path, stock_arg: Path | None, force: bool) -> None:
    resolved = kit_dir.resolve()
    forbidden = {ROOT.resolve(), THIS_DIR.resolve(), (ROOT / "tools").resolve(), (ROOT / "patches").resolve()}
    if stock_arg is not None:
        forbidden.add(stock_arg.resolve())
        forbidden.add(stock_arg.resolve().parent)

    for protected in forbidden:
        if resolved == protected or resolved in protected.parents:
            raise ValueError(f"Refusing unsafe output directory: {resolved}")

    if resolved.exists():
        if resolved.is_file():
            raise ValueError(f"Output path is an existing file: {resolved}")
        if any(resolved.iterdir()) and not force:
            raise FileExistsError(
                f"Output directory '{resolved}' already exists and is non-empty. "
                "Specify a new --output-dir or pass --force to replace after staged verification."
            )


def _build_m22_from_recipe(stock: bytes, recipe_path: Path) -> bytes:
    import json

    manifest = json.loads(recipe_path.read_text(encoding="utf-8"))
    buf = bytearray(stock)
    for ed in manifest["edits"]:
        off = int(ed["address"], 16) - BASE
        before = bytes.fromhex(ed["before"])
        after = bytes.fromhex(ed["after"])
        need(buf[off : off + len(before)] == before, f"Stock mismatch at {ed['address']}")
        buf[off : off + len(after)] = after
    crc = binascii.crc_hqx(bytes(buf[:-2]), 0)
    buf[-2:] = crc.to_bytes(2, "big")
    out = bytes(buf)
    need(sha(out) == DIGESTS["modified22"], "Rebuilt Modified22 digest mismatch")
    return out


def _render_instructions(has_historical_slots: bool) -> str:
    slots_block = (
        "  * 01_TEST_MODIFIED22/EG162080.BIN    : Modified22（色空间菜单直通RAW修复版）\n"
        "  * 02_BACK_TO_MODIFIED16/EG162080.BIN : 回退至 Modified16（历史 NEF压缩菜单切换版 + 600s）\n"
        "  * 03_BACK_TO_MODIFIED15/EG162080.BIN : 回退至 Modified15（常驻天文直通 + 600s）\n"
        "  * 04_BACK_TO_MODIFIED13/EG162080.BIN : 回退至 Modified13（常驻天文直通基准版）\n"
        "  * 05_STOCK_C380/EG162080.BIN         : 回退至尼康官方原版 C3.80\n"
        if has_historical_slots
        else "  * 01_TEST_MODIFIED22/EG162080.BIN : Modified22（色空间菜单直通RAW修复版）\n"
        "  * 05_STOCK_C380/EG162080.BIN      : 回退至尼康官方原版 C3.80\n"
    )
    return f"""Nikon Z6 C3.80 Modified22 (Genuine Color Space PID 0x0526 Astro RAW Fix + PID 0x130A sRGB Lock + Auto ISO Restored + Interval End-Time + 600s v2)
=================================================================================================================================================

【Modified22 三项核心修复】
1. 修正天文直通 RAW 动态门控 (`fn_is_astro_r0` @ `0x1002D900`)：
   - 读取真正的色空间菜单属性 `PID 0x0526` (`uint32([0xC24CDEA0]) == 1`) 且 `PID 0x131B <= 1` (`[0xC24CC798]` 为 RAW 或 RAW+JPEG)：
     * 选「标准 (sRGB)」(`0x0526 = 0`) -> 100% 原厂 C3.80 ISP 流程；
     * 选「直通RAW (sRGB)」(`0x0526 = 1`) -> 激活全部 13 处 Modified13 全尺寸天文直通 RAW 路径。
2. 锁定底层有效色空间为标准 sRGB (`0x1014BB28`: `bne` -> `nop` => `PID 0x130A = 0`)：
   - 无论选「标准 (sRGB)」还是「直通RAW (sRGB)」，底层有效色空间 `PID 0x130A` (`0xC24CC74C`) 恒为 `0 (sRGB)`：
     * 文件名前缀恒保持标准 sRGB 命名 (`Z61_xxxx.NEF` / `DSC_xxxx.NEF`，不再出现 `_Z61xxxx.NEF`)；
     * MakerNote `ColorSpace (0x001E)`、NEF 内嵌预览图、RAW+JPEG 直出 JPG 与实时取景色彩均保持标准 `sRGB`；
     * 拍摄菜单、`i` 快捷菜单/信息屏单元格、关机 NVRAM 记忆及 `U1/U2/U3` 用户档位完整保留档位切换状态。
3. 100% 恢复原厂「自动 ISO 感光度控制」(`0x1040AD00` 与 `0x1014F678` 恢复原版字节)。

【深空拍摄必读设置（重要）】
- 开启「直通RAW (sRGB)」进行天文拍摄（尤其是 >= 1 秒曝光）时，请务必将「NEF (RAW) 记录 -> NEF (RAW) 压缩」设为：
  **14位 + 无损压缩 (Lossless Compressed)**！
- 注意：请勿在 >= 1 秒曝光下同时开启「直通RAW (sRGB)」与「未压缩 (Uncompressed)」（详见 `docs/MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md`）。

【验证边界与刷机安全须知（必读）】
- 本包生成的 `EG162080.BIN` 为尼康 Z6 主固件单模块升级文件（卡根目录直接识别，非外层四模块 `Z_6_0380.bin` 容器）。
- 刷机前可在包目录运行 `python verify.py` 独立复核 SHA-256、CRC16 与全部 104 处补丁不变量。
- 请使用满电原厂电池与机内格式化后的存储卡，卡根目录每次只放一个 `EG162080.BIN`，升级全程严禁断电、拔卡或按键中断。
- 槽位说明（回退槽位仅在机身可正常开机进入「设定菜单 -> 固件版本」时使用）：
{slots_block}"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--stock",
        type=Path,
        default=None,
        help="Path to official Z_6_0380.bin or decoded eg1620_038000.bi",
    )
    ap.add_argument(
        "--candidate",
        type=Path,
        default=None,
        help="Optional path to Modified22 .bi/.BIN (otherwise built from --stock + tracked recipe)",
    )
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "outputs/Z6-C380-modified22-reviewed-2026-11-17",
    )
    ap.add_argument(
        "--stock-only",
        action="store_true",
        help="Package 2-slot kit (Modified22 + Stock C3.80) even if historical M13/M15/M16 files exist",
    )
    ap.add_argument(
        "--no-zip",
        action="store_true",
        help="Skip creating sibling .zip archive",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing non-empty output directory after staged verification succeeds",
    )
    args = ap.parse_args()

    kit_dir = args.output_dir.resolve()
    _validate_safe_output_dir(kit_dir, args.stock, args.force)

    # Load and validate all binary inputs BEFORE creating or modifying any output directory
    stock_bytes = load_stock_eg_module(args.stock, ROOT)
    need(len(stock_bytes) == SIZE and sha(stock_bytes) == DIGESTS["stock"], "Stock EG module hash/size mismatch")

    manifest_src = ROUND / "lab-build/modified22-manifest.json"
    if not manifest_src.is_file():
        manifest_src = TRACKED_RECIPE
    need(manifest_src.is_file(), f"Missing Modified22 manifest/recipe: {manifest_src}")

    default_cand = ROUND / "lab-build/modified22-candidate.bi"
    if args.candidate is not None:
        cand_p = args.candidate.resolve()
        need(cand_p.is_file(), f"Missing --candidate file: {cand_p}")
        m22_bytes = cand_p.read_bytes()
    elif default_cand.is_file():
        m22_bytes = default_cand.read_bytes()
    else:
        m22_bytes = _build_m22_from_recipe(stock_bytes, manifest_src)
    need(len(m22_bytes) == SIZE and sha(m22_bytes) == DIGESTS["modified22"], "Modified22 binary hash/size mismatch")

    slot_payloads: dict[str, bytes] = {
        "modified22": m22_bytes,
        "stock": stock_bytes,
    }
    has_all_hist = (not args.stock_only) and all(OPTIONAL_SOURCES[s].is_file() for s in OPTIONAL_SLOTS)
    if has_all_hist:
        for s in OPTIONAL_SLOTS:
            b = OPTIONAL_SOURCES[s].read_bytes()
            need(len(b) == SIZE and sha(b) == DIGESTS[s], f"Historical {s} binary hash/size mismatch")
            slot_payloads[s] = b

    optional_audit_files = [
        p
        for p in (
            ROUND / "lab-build/probe_modified22_native_result.json",
            ROUND / "updater-audit/updater_audit.json",
        )
        if p.is_file()
    ]

    kit_dir.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(tempfile.mkdtemp(prefix=f".{kit_dir.name}.staging-", dir=str(kit_dir.parent)))
    try:
        for name, data in slot_payloads.items():
            dst = staging_dir / PATHS[name]
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)

        audit_dst = staging_dir / "audit"
        audit_dst.mkdir(parents=True, exist_ok=True)
        shutil.copy2(manifest_src, audit_dst / "modified22-manifest.json")
        for extra_audit in optional_audit_files:
            shutil.copy2(extra_audit, audit_dst / extra_audit.name)

        shutil.copy2(THIS_DIR / "verify_modified22_kit.py", staging_dir / "verify.py")
        (staging_dir / "FLASH_INSTRUCTIONS.txt").write_text(
            _render_instructions(has_all_hist), encoding="utf-8"
        )

        res = check_kit(staging_dir)

        if kit_dir.exists():
            shutil.rmtree(kit_dir)
        staging_dir.rename(kit_dir)
    except Exception:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        raise

    if args.no_zip:
        print(f"MODIFIED22 KIT PACKAGED | slots={res['verified_slots']} | dir={kit_dir}")
        return

    zip_path = kit_dir.parent / f"{kit_dir.name}.zip"
    tmp_zip = kit_dir.parent / f".{kit_dir.name}.staging.zip"
    try:
        with zipfile.ZipFile(tmp_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(kit_dir.rglob("*")):
                if f.is_file():
                    zf.write(f, f.relative_to(kit_dir.parent))
        if zip_path.exists():
            zip_path.unlink()
        tmp_zip.rename(zip_path)
    finally:
        if tmp_zip.exists():
            tmp_zip.unlink()

    print(
        f"MODIFIED22 KIT PACKAGED | slots={res['verified_slots']} ({res['kit_mode']}) | "
        f"zip={zip_path.name} ({zip_path.stat().st_size:,} B)"
    )


if __name__ == "__main__":
    main()

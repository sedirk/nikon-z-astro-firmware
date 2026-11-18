"""Non-destructively package the Nikon Z6 C3.80 Modified23 flash kit.

SPDX-License-Identifier: GPL-3.0-or-later

Safety guarantees:
  - Validates output directory path and ALL inputs in memory BEFORE touching disk.
  - Refuses to overwrite a non-empty existing directory unless `--force` is passed.
  - Stages into a sibling temporary directory and runs `check_kit` before atomic rename.
  - Supports:
      * 6-slot researcher kit (`01_TEST_MODIFIED23` + `02_BACK_TO_MODIFIED22` + M16/15/13 + `06_STOCK_C380`)
        when local historical binaries are present;
      * 3-slot baseline kit (`01_TEST_MODIFIED23` + `02_BACK_TO_MODIFIED22` + `03_STOCK_C380`) on a clean
        clone using the tracked Modified22 recipe;
      * 2-slot stock-only kit (`01_TEST_MODIFIED23` + `02_STOCK_C380_ROLLBACK`) with `--stock-only`.
"""
from __future__ import annotations

if not __debug__:
    raise RuntimeError("package_modified23_kit.py must not be executed with Python -O/-OO.")

import argparse
import binascii
import json
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from verify_modified23_kit import (  # noqa: E402
    BASE,
    DIGESTS,
    HISTORICAL_SLOTS,
    PATHS,
    SIZE,
    check_kit,
    need,
    sha,
)
from z6_c380_container import load_stock_eg_module  # noqa: E402

ROOT = THIS_DIR.parents[1]
ROUND = ROOT / "analysis/modified23-preflash-2026-11-18"
TRACKED_M23_RECIPE = ROOT / "patches/z6-c380-modified23-uncompressed-astro-raw-srgb-600s.json"
TRACKED_M22_RECIPE = ROOT / "patches/z6-c380-modified22-color-space-pid0526-srgb-600s.json"

OPTIONAL_SOURCES = {
    "modified22": ROOT / "outputs/Z6-C380-modified22-reviewed-2026-11-17/01_TEST_MODIFIED22/EG162080.BIN",
    "modified16": ROOT / "outputs/Z6-C380-modified16-reviewed-2026-11-15/01_TEST_MODIFIED16/EG162080.BIN",
    "modified15": ROOT / "outputs/Z6-C380-modified15-reviewed-2026-11-15/01_TEST_MODIFIED15/EG162080.BIN",
    "modified13": ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN",
}


KNOWN_M23_KIT_ENTRIES = {
    "01_MODIFIED23",
    "01_TEST_MODIFIED23",
    "02_STOCK_C380_ROLLBACK",
    "02_BACK_TO_MODIFIED22",
    "03_STOCK_C380",
    "03_BACK_TO_MODIFIED16",
    "04_BACK_TO_MODIFIED15",
    "05_BACK_TO_MODIFIED13",
    "06_STOCK_C380",
    "audit",
    "verify.py",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "FLASH_INSTRUCTIONS.txt",
    "SHA256SUMS.txt",
    "build_receipt.json",
}


def _is_replaceable_m23_kit_dir(resolved: Path) -> bool:
    has_marker = (resolved / "audit/modified23-manifest.json").is_file() or (
        resolved / "build_receipt.json"
    ).is_file()
    if not has_marker:
        return False
    entries = {p.name for p in resolved.iterdir()}
    return bool(entries) and entries.issubset(KNOWN_M23_KIT_ENTRIES)


def _validate_safe_output_dir(kit_dir: Path, stock_arg: Path | None, force: bool) -> None:
    resolved = kit_dir.resolve()
    if resolved.parent == resolved:
        raise ValueError(f"Refusing filesystem root as output directory: {resolved}")
    forbidden = {
        Path.home().resolve(),
        ROOT.resolve(),
        THIS_DIR.resolve(),
        (ROOT / ".git").resolve(),
        (ROOT / "tools").resolve(),
        (ROOT / "patches").resolve(),
        (ROOT / "docs").resolve(),
        (ROOT / "firmware").resolve(),
        (ROOT / "samples").resolve(),
        (ROOT / "work").resolve(),
        (ROOT / "references").resolve(),
    }
    if stock_arg is not None:
        forbidden.add(stock_arg.resolve())
        forbidden.add(stock_arg.resolve().parent)

    for protected in forbidden:
        if resolved == protected or resolved in protected.parents:
            raise ValueError(f"Refusing unsafe output directory: {resolved}")

    if resolved.exists():
        if resolved.is_file():
            raise ValueError(f"Output path is an existing file: {resolved}")
        if any(resolved.iterdir()):
            if not force:
                raise FileExistsError(
                    f"Output directory '{resolved}' already exists and is non-empty. "
                    "Specify a new --output-dir or pass --force to replace a previous Modified23 kit."
                )
            if not _is_replaceable_m23_kit_dir(resolved):
                raise ValueError(
                    f"Refusing '--force' overwrite of '{resolved}': directory does not match a "
                    "recognized Modified23 kit layout."
                )

def _build_from_recipe(stock: bytes, recipe_path: Path, expected_digest: str, label: str) -> bytes:
    manifest = json.loads(recipe_path.read_text(encoding="utf-8"))
    buf = bytearray(stock)
    for ed in manifest["edits"]:
        off = int(ed["address"], 16) - BASE
        before = bytes.fromhex(ed["before"])
        after = bytes.fromhex(ed["after"])
        need(buf[off : off + len(before)] == before, f"{label} stock mismatch at {ed['address']}")
        buf[off : off + len(after)] = after
    crc = binascii.crc_hqx(bytes(buf[:-2]), 0)
    buf[-2:] = crc.to_bytes(2, "big")
    out = bytes(buf)
    need(sha(out) == expected_digest, f"Rebuilt {label} digest mismatch")
    return out


def _render_instructions(kit_mode: str) -> str:
    if kit_mode == "6-slot-researcher":
        slots_block = (
            "  * 01_TEST_MODIFIED23/EG162080.BIN    : Modified23 天文增强正式固件主模块\n"
            "  * 02_BACK_TO_MODIFIED22/EG162080.BIN : 回退至 Modified22 历史基线\n"
            "  * 03_BACK_TO_MODIFIED16/EG162080.BIN : 回退至 Modified16 历史归档\n"
            "  * 04_BACK_TO_MODIFIED15/EG162080.BIN : 回退至 Modified15 历史归档\n"
            "  * 05_BACK_TO_MODIFIED13/EG162080.BIN : 回退至 Modified13 历史归档\n"
            "  * 06_STOCK_C380/EG162080.BIN         : 回退至尼康官方原版 C3.80\n"
        )
    elif kit_mode == "3-slot-with-modified22":
        slots_block = (
            "  * 01_TEST_MODIFIED23/EG162080.BIN    : Modified23 天文增强正式固件主模块\n"
            "  * 02_BACK_TO_MODIFIED22/EG162080.BIN : 回退至 Modified22 历史基线\n"
            "  * 03_STOCK_C380/EG162080.BIN         : 回退至尼康官方原版 C3.80\n"
        )
    else:
        slots_block = (
            "  * 01_TEST_MODIFIED23/EG162080.BIN      : Modified23 天文增强正式固件主模块\n"
            "  * 02_STOCK_C380_ROLLBACK/EG162080.BIN  : 回退至尼康官方原版 C3.80\n"
        )

    return f"""Nikon Z6 C3.80 Astro Firmware (Modified23) — Researcher & Multi-Slot Kit Guide
================================================================================

【核心功能说明】
- 照片拍摄菜单 -> 天文直通RAW模式（覆盖原“色空间”项，支持 36 种机身语言）：
    * 标准 (sRGB)    : 100% 原厂 C3.80 图像流水线
    * 直通RAW (sRGB) : 启用 14 处动态门控天文直通 RAW 流水线（消除同心彩圈与空间滤波吃星，锁定前端四通道 Q12 单位增益 1.0000x，保持标准 Z61_ / DSC_ 命名与 sRGB EXIF）
- NEF(RAW)记录：支持 14位 / 12位 位深度，完整兼容无损压缩、未压缩与有损压缩全模式及全快门档位。
- M 档扩展慢门与间隔拍摄：M 档越过 30" 后直选 60"~600" 共 8 档长曝光；间隔拍摄按前帧曝光结束后起算帧间隔，并动态刷新预计结束时间。

【刷机安全须知（必读）】
- 本包生成的 `EG162080.BIN` 为尼康 Z6 主固件单模块升级文件（卡根目录直接识别，非外层 `Z_6_0380.bin` 容器）。
- 刷机前可在包目录运行 `python verify.py` 离线复核 SHA-256、CRC16 与全部 105 处补丁字节。
- 请使用满电原厂电池与机内格式化后的存储卡，卡根目录每次只放一个 `EG162080.BIN`，升级全程严禁断电、拔卡或按键中断。
- 槽位说明（回退槽位仅在机身可正常开机进入「设定菜单 -> 固件版本」时使用）：
{slots_block}"""


def main() -> None:
    if not __debug__:
        raise RuntimeError("package_modified23_kit.py must not be executed with Python -O/-OO.")
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
        help="Optional path to Modified23 .bi/.BIN (otherwise built from --stock + tracked recipe)",
    )
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "outputs/Z6-C380-modified23-reviewed-2026-11-18",
    )
    ap.add_argument(
        "--stock-only",
        action="store_true",
        help="Package 2-slot kit (Modified23 + Stock C3.80) without Modified22/historical rollback slots",
    )
    ap.add_argument(
        "--m22-only",
        action="store_true",
        help="Package 3-slot kit (Modified23 + Modified22 + Stock C3.80) even if M13/M15/M16 files exist",
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

    stock_bytes = load_stock_eg_module(args.stock, ROOT)
    need(len(stock_bytes) == SIZE and sha(stock_bytes) == DIGESTS["stock"], "Stock EG module hash/size mismatch")

    manifest_src = ROUND / "lab-build/modified23-manifest.json"
    if not manifest_src.is_file():
        manifest_src = TRACKED_M23_RECIPE
    need(manifest_src.is_file(), f"Missing Modified23 manifest/recipe: {manifest_src}")

    default_cand = ROUND / "lab-build/modified23-candidate.bi"
    if args.candidate is not None:
        cand_p = args.candidate.resolve()
        need(cand_p.is_file(), f"Missing --candidate file: {cand_p}")
        m23_bytes = cand_p.read_bytes()
    elif default_cand.is_file():
        m23_bytes = default_cand.read_bytes()
    else:
        m23_bytes = _build_from_recipe(stock_bytes, manifest_src, DIGESTS["modified23"], "Modified23")
    need(len(m23_bytes) == SIZE and sha(m23_bytes) == DIGESTS["modified23"], "Modified23 binary hash/size mismatch")

    slot_rel_paths: dict[str, str] = {}
    slot_payloads: dict[str, bytes] = {}

    has_all_hist = (
        (not args.stock_only)
        and (not args.m22_only)
        and all(OPTIONAL_SOURCES[s].is_file() for s in HISTORICAL_SLOTS)
    )

    if args.stock_only:
        kit_mode = "2-slot-stock-only"
        slot_rel_paths["modified23"] = "01_TEST_MODIFIED23/EG162080.BIN"
        slot_rel_paths["stock"] = "02_STOCK_C380_ROLLBACK/EG162080.BIN"
        slot_payloads["modified23"] = m23_bytes
        slot_payloads["stock"] = stock_bytes
    else:
        if OPTIONAL_SOURCES["modified22"].is_file():
            m22_bytes = OPTIONAL_SOURCES["modified22"].read_bytes()
        else:
            need(TRACKED_M22_RECIPE.is_file(), f"Missing Modified22 recipe: {TRACKED_M22_RECIPE}")
            m22_bytes = _build_from_recipe(stock_bytes, TRACKED_M22_RECIPE, DIGESTS["modified22"], "Modified22")
        need(len(m22_bytes) == SIZE and sha(m22_bytes) == DIGESTS["modified22"], "Modified22 binary hash/size mismatch")

        if has_all_hist:
            kit_mode = "6-slot-researcher"
            slot_rel_paths = dict(PATHS)
            slot_payloads["modified23"] = m23_bytes
            slot_payloads["modified22"] = m22_bytes
            slot_payloads["stock"] = stock_bytes
            for s in HISTORICAL_SLOTS:
                b = OPTIONAL_SOURCES[s].read_bytes()
                need(len(b) == SIZE and sha(b) == DIGESTS[s], f"Historical {s} binary hash/size mismatch")
                slot_payloads[s] = b
        else:
            kit_mode = "3-slot-with-modified22"
            slot_rel_paths["modified23"] = "01_TEST_MODIFIED23/EG162080.BIN"
            slot_rel_paths["modified22"] = "02_BACK_TO_MODIFIED22/EG162080.BIN"
            slot_rel_paths["stock"] = "03_STOCK_C380/EG162080.BIN"
            slot_payloads["modified23"] = m23_bytes
            slot_payloads["modified22"] = m22_bytes
            slot_payloads["stock"] = stock_bytes

    optional_audit_files: list[Path] = []
    prb_cand = ROUND / "lab-build/probe_modified23_native_result.json"
    if prb_cand.is_file():
        prb_obj = json.loads(prb_cand.read_text(encoding="utf-8"))
        need(
            prb_obj.get("status") == "PASS" and "exception" not in prb_obj,
            "Refusing to bundle non-PASS probe_modified23_native_result.json",
        )
        optional_audit_files.append(prb_cand)
    upd_cand = ROUND / "updater-audit/updater_audit.json"
    if upd_cand.is_file():
        upd_obj = json.loads(upd_cand.read_text(encoding="utf-8"))
        need(
            upd_obj.get("ok") is True and "exception" not in upd_obj and "error" not in upd_obj,
            "Refusing to bundle non-PASS updater_audit.json",
        )
        optional_audit_files.append(upd_cand)

    def _write_lf_text(dst: Path, text: str) -> None:
        dst.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))

    kit_dir.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(tempfile.mkdtemp(prefix=f".{kit_dir.name}.staging-", dir=str(kit_dir.parent)))
    try:
        for name, data in slot_payloads.items():
            dst = staging_dir / slot_rel_paths[name]
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)

        audit_dst = staging_dir / "audit"
        audit_dst.mkdir(parents=True, exist_ok=True)
        _write_lf_text(audit_dst / "modified23-manifest.json", manifest_src.read_text(encoding="utf-8"))
        for extra_audit in optional_audit_files:
            _write_lf_text(audit_dst / extra_audit.name, extra_audit.read_text(encoding="utf-8"))

        _write_lf_text(staging_dir / "verify.py", (THIS_DIR / "verify_modified23_kit.py").read_text(encoding="utf-8"))
        _write_lf_text(staging_dir / "FLASH_INSTRUCTIONS.txt", _render_instructions(kit_mode))

        res = check_kit(staging_dir)
        need(res["kit_mode"] == kit_mode, f"Kit mode mismatch: {res['kit_mode']} != {kit_mode}")

        if kit_dir.exists():
            shutil.rmtree(kit_dir)
        staging_dir.rename(kit_dir)
    except Exception:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        raise

    if args.no_zip:
        print(f"MODIFIED23 KIT PACKAGED | slots={res['verified_slots']} ({res['kit_mode']}) | dir={kit_dir}")
        return

    zip_path = kit_dir.parent / f"{kit_dir.name}.zip"
    tmp_zip = kit_dir.parent / f".{kit_dir.name}.staging.zip"
    files_to_zip = sorted(
        (f for f in kit_dir.rglob("*") if f.is_file()),
        key=lambda p: p.relative_to(kit_dir).as_posix(),
    )
    try:
        with zipfile.ZipFile(tmp_zip, "w") as zf:
            for f in files_to_zip:
                arcname = f"{kit_dir.name}/{f.relative_to(kit_dir).as_posix()}"
                zi = zipfile.ZipInfo(filename=arcname, date_time=(2026, 11, 18, 0, 0, 0))
                zi.create_system = 0
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = 0o644 << 16
                zf.writestr(zi, f.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
        if zip_path.exists():
            zip_path.unlink()
        tmp_zip.rename(zip_path)
    finally:
        if tmp_zip.exists():
            tmp_zip.unlink()

    print(
        f"MODIFIED23 KIT PACKAGED | slots={res['verified_slots']} ({res['kit_mode']}) | "
        f"zip={zip_path.name} ({zip_path.stat().st_size:,} B)"
    )


if __name__ == "__main__":
    main()

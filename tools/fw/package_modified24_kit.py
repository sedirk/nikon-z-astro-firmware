"""Package and verify multi-slot Nikon Z6 C3.80 Astro Firmware (Modified24) Flash Kits.

SPDX-License-Identifier: GPL-3.0-or-later

Safety guarantees:
  - Validates output directory path and ALL inputs in memory BEFORE touching disk.
  - Refuses to overwrite a non-empty existing directory unless `--force` is passed.
  - Stages into a sibling temporary directory and runs `check_kit` before atomic swap.
  - Supports:
      * 7-slot researcher kit (`01_TEST_MODIFIED24` + M23 + M22 + M16/15/13 + `07_STOCK_C380`)
        when local historical binaries are present;
      * 4-slot baseline kit (`01_TEST_MODIFIED24` + M23 + M22 + `04_STOCK_C380`) on a clean
        clone using tracked Modified23 & Modified22 recipes;
      * 3-slot kit (`01_TEST_MODIFIED24` + `02_BACK_TO_MODIFIED23` + `03_STOCK_C380`) with `--m23-only`;
      * 2-slot stock-only kit (`01_TEST_MODIFIED24` + `02_STOCK_C380_ROLLBACK`) with `--stock-only`.
"""
from __future__ import annotations

if not __debug__:
    raise RuntimeError("package_modified24_kit.py must not be executed with Python -O/-OO.")

import argparse
import binascii
import json
from pathlib import Path
import os
import re
import shutil
import sys
import tempfile
import uuid
import zipfile
THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from verify_modified24_kit import (  # noqa: E402
    BASE,
    DIGESTS,
    EXACT_LAYOUTS,
    SIZE,
    check_kit,
    need,
    sha,
)
from z6_c380_container import load_stock_eg_module  # noqa: E402

ROOT = THIS_DIR.parents[1]
ROUND = ROOT / "analysis/modified24-release-2026-11-21"
TRACKED_M24_RECIPE = ROOT / "patches/z6-c380-modified24-astro-raw-red-srgb-600s.json"
TRACKED_M23_RECIPE = ROOT / "patches/z6-c380-modified23-uncompressed-astro-raw-srgb-600s.json"
TRACKED_M22_RECIPE = ROOT / "patches/z6-c380-modified22-color-space-pid0526-srgb-600s.json"

HISTORICAL_SLOTS = ("modified16", "modified15", "modified13")
OPTIONAL_SOURCES = {
    "modified23": ROOT / "outputs/Nikon-Z6-C380-Modified23-Astro-Firmware/01_MODIFIED23/EG162080.BIN",
    "modified22": ROOT / "outputs/Z6-C380-modified22-reviewed-2026-11-17/01_TEST_MODIFIED22/EG162080.BIN",
    "modified16": ROOT / "outputs/Z6-C380-modified16-reviewed-2026-11-15/01_TEST_MODIFIED16/EG162080.BIN",
    "modified15": ROOT / "outputs/Z6-C380-modified15-reviewed-2026-11-15/01_TEST_MODIFIED15/EG162080.BIN",
    "modified13": ROOT / "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN",
}

KNOWN_M24_KIT_ENTRIES = {
    "01_MODIFIED24",
    "01_TEST_MODIFIED24",
    "02_STOCK_C380_ROLLBACK",
    "02_BACK_TO_MODIFIED23",
    "03_STOCK_C380",
    "03_BACK_TO_MODIFIED22",
    "04_STOCK_C380",
    "04_BACK_TO_MODIFIED16",
    "05_BACK_TO_MODIFIED15",
    "06_BACK_TO_MODIFIED13",
    "07_STOCK_C380",
    "audit",
    "verify.py",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "FLASH_INSTRUCTIONS.txt",
    "SHA256SUMS.txt",
    "build_receipt.json",
}


def _is_replaceable_m24_kit_dir(resolved: Path) -> bool:
    has_marker = (resolved / "audit/modified24-manifest.json").is_file() or (
        resolved / "build_receipt.json"
    ).is_file()
    if not has_marker:
        return False
    entries = {p.name for p in resolved.iterdir()}
    return bool(entries) and entries.issubset(KNOWN_M24_KIT_ENTRIES)


def _is_replaceable_m24_zip(zip_path: Path, expected_prefix: str) -> bool:
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return False
    if not names or not all(n.startswith(f"{expected_prefix}/") for n in names):
        return False
    return (
        f"{expected_prefix}/audit/modified24-manifest.json" in names
        or f"{expected_prefix}/build_receipt.json" in names
    )


def _validate_safe_output_dir(
    kit_dir: Path,
    input_paths: list[Path | None],
    force: bool,
    make_zip: bool = True,
) -> None:
    resolved = kit_dir.resolve()
    if resolved.parent == resolved:
        raise ValueError(f"Refusing filesystem root as output directory: {resolved}")
    protected_trees = {
        (ROOT / ".git").resolve(),
        (ROOT / "tools").resolve(),
        (ROOT / "patches").resolve(),
        (ROOT / "docs").resolve(),
        (ROOT / "firmware").resolve(),
        (ROOT / "samples").resolve(),
        (ROOT / "work").resolve(),
        (ROOT / "references").resolve(),
    }
    for anc in (Path.home().resolve(), ROOT.resolve()):
        if resolved == anc or resolved in anc.parents:
            raise ValueError(f"Refusing unsafe output directory: {resolved}")
    for tree in protected_trees:
        if resolved == tree or resolved in tree.parents or tree in resolved.parents:
            raise ValueError(f"Refusing protected repository directory: {resolved}")

    zip_path = resolved.parent / f"{resolved.name}.zip"
    for in_p in input_paths:
        if in_p is None:
            continue
        in_res = in_p.resolve()
        if resolved == in_res or resolved in in_res.parents or in_res in resolved.parents:
            raise ValueError(f"Refusing output directory overlapping input path: {resolved}")
        if make_zip and zip_path == in_res:
            raise ValueError(f"Refusing output ZIP path overlapping input file: {zip_path}")

    if kit_dir.is_symlink() or (resolved.exists() and resolved.is_file()):
        raise ValueError(f"Output path is an existing file or symlink: {kit_dir}")
    if resolved.exists() and any(resolved.iterdir()):
        if not force:
            raise FileExistsError(
                f"Output directory '{resolved}' already exists and is non-empty. "
                "Specify a new --output-dir or pass --force to replace a previous Modified24 kit."
            )
        if not _is_replaceable_m24_kit_dir(resolved):
            raise ValueError(
                f"Refusing '--force' overwrite of '{resolved}': directory does not match a "
                "recognized Modified24 kit layout."
            )

    if make_zip and (zip_path.exists() or zip_path.is_symlink()):
        if zip_path.is_symlink() or zip_path.is_dir():
            raise ValueError(f"Output ZIP path is an existing directory or symlink: {zip_path}")
        if not force:
            raise FileExistsError(
                f"Output ZIP archive '{zip_path}' already exists. "
                "Specify a new --output-dir, pass --no-zip, or add --force to replace a previous Modified24 ZIP."
            )
        if not _is_replaceable_m24_zip(zip_path, resolved.name):
            raise ValueError(
                f"Refusing '--force' overwrite of '{zip_path}': archive does not match a "
                "recognized Modified24 ZIP layout."
            )


def _atomic_replace_dir(staging_dir: Path, out_dir: Path) -> None:
    if not out_dir.exists():
        staging_dir.rename(out_dir)
        return
    while True:
        backup_dir = out_dir.parent / f".{out_dir.name}.old-{uuid.uuid4().hex[:10]}"
        if not backup_dir.exists() and not backup_dir.is_symlink():
            break
    out_dir.rename(backup_dir)
    try:
        staging_dir.rename(out_dir)
    except Exception:
        if not out_dir.exists() and backup_dir.exists():
            backup_dir.rename(out_dir)
        raise
    shutil.rmtree(backup_dir, ignore_errors=True)

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
    slot_map = EXACT_LAYOUTS[kit_mode]
    labels = {
        "modified24": "Modified24 天文增强正式固件主模块 (SHA-256: 168dcf2c..., CRC-16: 0x8799)",
        "modified23": "回退至 Modified23 历史基线",
        "modified22": "回退至 Modified22 历史基线",
        "modified16": "回退至 Modified16 历史归档",
        "modified15": "回退至 Modified15 历史归档",
        "modified13": "回退至 Modified13 历史归档",
        "stock": "回退至尼康官方原版 C3.80",
    }
    slots_block = "".join(
        f"  * {rel_p:<38} : {labels[key]}\n" for key, rel_p in slot_map.items()
    )
    return f"""Nikon Z6 C3.80 Astro Firmware (Modified24) — Researcher & Multi-Slot Kit Guide
================================================================================

【两项核心开关借用的原厂菜单说明（支持 36 种机身语言）】
1. 天文直通RAW模式 —— 借用原厂「照片拍摄菜单 -> 色空间」(PID 0x0526)：
   - 底层有效色空间 (PID 0x130A) 已永久锁定为 `0 (sRGB)`，原厂色空间菜单改造为：
     * `标准 (sRGB)` (`0`)    : 100% 原厂 C3.80 图像流水线
     * `直通RAW (sRGB)` (`1`) : 启用 14 处动态门控天文直通 RAW 流水线（消除同心彩圈与空间滤波吃星，锁定前端四通道 Q12 单位增益 1.0000x，完整支持 14/12 位无损压缩、未压缩与有损压缩）
2. 天文红光显示 —— 借用原厂「设定菜单 -> 信息显示」(PID 0x1111，出厂重置默认值 = `0`)：
   - `DISP` 参数信息屏已永久锁定为「黑底亮字」，原厂信息显示菜单改造为：
     * `关闭 (标准色彩)` (`0`) : 背面显示屏与 OLED 取景器保持标准全彩显示
     * `开启 (天文红光)` (`1`) : 背面显示屏与 OLED 取景器（含硬件构图网格）切换为纯红夜视模式 (`G = 0, B = 0`)；实拍 NEF RAW、JPEG 与外接 HDMI 输出完全不受影响。
   - 首次开机提示：若刷机前原厂「信息显示」曾设为「黑暗时用亮字体 (`1`)」，机身 NVRAM 保留该值会使首次开机直接进入红光模式，进菜单切回一次 `关闭 (标准色彩)` (`0`) 即可。
3. M 档扩展慢门与间隔拍摄：M 档越过 30" 后直选 60"~600" 共 8 档长曝光；间隔拍摄按前帧曝光结束后起算帧间隔并动态刷新预计结束时间。

【刷机安全须知（必读）】
- 本包生成的 `EG162080.BIN` 为尼康 Z6 主固件单模块升级文件（卡根目录直接识别，非外层 `Z_6_0380.bin` 容器）。
- 刷机前可在包目录运行 `python verify.py` 离线复核 SHA-256、CRC16 与全部 112 处补丁字节。
- 请使用满电原厂电池与机内格式化后的存储卡，卡根目录每次只放一个 `EG162080.BIN`，升级全程严禁断电、拔卡或按键中断。
- 槽位说明（回退槽位仅在机身可正常开机进入「设定菜单 -> 固件版本」时使用）：
{slots_block}"""


def main() -> None:
    if not __debug__:
        raise RuntimeError("package_modified24_kit.py must not be executed with Python -O/-OO.")
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
        help="Optional path to Modified24 .bi/.BIN (otherwise built from --stock + tracked recipe)",
    )
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "outputs/Z6-C380-modified24-reviewed-2026-11-21",
    )
    ap.add_argument(
        "--stock-only",
        action="store_true",
        help="Package 2-slot kit (Modified24 + Stock C3.80)",
    )
    ap.add_argument(
        "--m23-only",
        action="store_true",
        help="Package 3-slot kit (Modified24 + Modified23 + Stock C3.80)",
    )
    ap.add_argument(
        "--m23-m22-only",
        action="store_true",
        help="Package 4-slot kit (Modified24 + Modified23 + Modified22 + Stock C3.80)",
    )
    ap.add_argument(
        "--no-zip",
        action="store_true",
        help="Skip creating sibling .zip archive",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing non-empty Modified24 kit directory after staged verification succeeds",
    )
    args = ap.parse_args()

    kit_dir = args.output_dir.resolve()
    _validate_safe_output_dir(
        kit_dir, [args.stock, args.candidate], args.force, make_zip=not args.no_zip
    )
    stock_bytes = load_stock_eg_module(args.stock, ROOT)
    need(len(stock_bytes) == SIZE and sha(stock_bytes) == DIGESTS["stock"], "Stock EG module hash/size mismatch")

    manifest_src = ROUND / "lab-build/modified24-manifest.json"
    if not manifest_src.is_file():
        manifest_src = TRACKED_M24_RECIPE
    need(manifest_src.is_file(), f"Missing Modified24 manifest/recipe: {manifest_src}")

    default_cand = ROUND / "lab-build/modified24-candidate.bi"
    if args.candidate is not None:
        cand_p = args.candidate.resolve()
        need(cand_p.is_file(), f"Missing --candidate file: {cand_p}")
        m24_bytes = cand_p.read_bytes()
    elif default_cand.is_file():
        m24_bytes = default_cand.read_bytes()
    else:
        m24_bytes = _build_from_recipe(stock_bytes, manifest_src, DIGESTS["modified24"], "Modified24")
    need(len(m24_bytes) == SIZE and sha(m24_bytes) == DIGESTS["modified24"], "Modified24 binary hash/size mismatch")

    has_all_hist = (
        (not args.stock_only)
        and (not args.m23_only)
        and (not args.m23_m22_only)
        and all(OPTIONAL_SOURCES[s].is_file() for s in HISTORICAL_SLOTS)
    )

    slot_payloads: dict[str, bytes] = {"modified24": m24_bytes, "stock": stock_bytes}
    if args.stock_only:
        kit_mode = "2-slot-stock-only"
    else:
        if OPTIONAL_SOURCES["modified23"].is_file():
            m23_bytes = OPTIONAL_SOURCES["modified23"].read_bytes()
        else:
            need(TRACKED_M23_RECIPE.is_file(), f"Missing Modified23 recipe: {TRACKED_M23_RECIPE}")
            m23_bytes = _build_from_recipe(stock_bytes, TRACKED_M23_RECIPE, DIGESTS["modified23"], "Modified23")
        need(len(m23_bytes) == SIZE and sha(m23_bytes) == DIGESTS["modified23"], "Modified23 binary hash/size mismatch")
        slot_payloads["modified23"] = m23_bytes

        if args.m23_only:
            kit_mode = "3-slot-with-modified23"
        else:
            if OPTIONAL_SOURCES["modified22"].is_file():
                m22_bytes = OPTIONAL_SOURCES["modified22"].read_bytes()
            else:
                need(TRACKED_M22_RECIPE.is_file(), f"Missing Modified22 recipe: {TRACKED_M22_RECIPE}")
                m22_bytes = _build_from_recipe(stock_bytes, TRACKED_M22_RECIPE, DIGESTS["modified22"], "Modified22")
            need(len(m22_bytes) == SIZE and sha(m22_bytes) == DIGESTS["modified22"], "Modified22 binary hash/size mismatch")
            slot_payloads["modified22"] = m22_bytes

            if has_all_hist:
                kit_mode = "7-slot-researcher"
                for s in HISTORICAL_SLOTS:
                    b = OPTIONAL_SOURCES[s].read_bytes()
                    need(len(b) == SIZE and sha(b) == DIGESTS[s], f"Historical {s} binary hash/size mismatch")
                    slot_payloads[s] = b
            else:
                kit_mode = "4-slot-with-m23-m22"

    slot_rel_paths = EXACT_LAYOUTS[kit_mode]

    optional_audit_files: list[tuple[str, Path]] = []
    prb_cand = ROOT / "docs/evidence/probe_modified24_native_result.json"
    if prb_cand.is_file():
        prb_obj = json.loads(prb_cand.read_text(encoding="utf-8"))
        need(
            prb_obj.get("status") == "PASS"
            and prb_obj.get("measured_candidate_sha256") == DIGESTS["modified24"]
            and "exception" not in prb_obj
            and "error" not in prb_obj,
            "Refusing to bundle non-PASS probe_modified24_native_result.json",
        )
        optional_audit_files.append(("probe_modified24_native_result.json", prb_cand))

    upd_cand = ROOT / "docs/evidence/modified24_updater_audit.json"
    if upd_cand.is_file():
        upd_obj = json.loads(upd_cand.read_text(encoding="utf-8"))
        need(
            upd_obj.get("ok") is True
            and upd_obj.get("measured_modified24_sha256") == DIGESTS["modified24"]
            and "exception" not in upd_obj
            and "error" not in upd_obj,
            "Refusing to bundle non-PASS modified24_updater_audit.json",
        )
        optional_audit_files.append(("modified24_updater_audit.json", upd_cand))

    qemu_cand = ROOT / "docs/evidence/qemu_modified24_result.json"
    if qemu_cand.is_file():
        q_obj = json.loads(qemu_cand.read_text(encoding="utf-8"))
        need(
            q_obj.get("ok") is True
            and q_obj.get("firmware_sha256") == DIGESTS["modified24"]
            and "error" not in q_obj,
            "Refusing to bundle non-PASS qemu_modified24_result.json",
        )
        optional_audit_files.append(("qemu_modified24_result.json", qemu_cand))

    def _write_lf_text(dst: Path, text: str) -> None:
        dst.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))

    kit_dir.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(tempfile.mkdtemp(prefix=f".{kit_dir.name}.staging-", dir=str(kit_dir.parent)))
    try:
        sums_lines: list[str] = []
        for slot_key, rel_p in slot_rel_paths.items():
            data = slot_payloads[slot_key]
            dst = staging_dir / rel_p
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
            sums_lines.append(f"{sha(data)}  {rel_p}")

        audit_dst = staging_dir / "audit"
        audit_dst.mkdir(parents=True, exist_ok=True)
        _write_lf_text(audit_dst / "modified24-manifest.json", manifest_src.read_text(encoding="utf-8"))
        for dst_name, src_p in optional_audit_files:
            _write_lf_text(audit_dst / dst_name, src_p.read_text(encoding="utf-8"))

        _write_lf_text(staging_dir / "verify.py", (THIS_DIR / "verify_modified24_kit.py").read_text(encoding="utf-8"))
        for legal_name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            legal_src = ROOT / legal_name
            if legal_src.is_file():
                _write_lf_text(staging_dir / legal_name, legal_src.read_text(encoding="utf-8"))
        _write_lf_text(staging_dir / "FLASH_INSTRUCTIONS.txt", _render_instructions(kit_mode))
        _write_lf_text(staging_dir / "SHA256SUMS.txt", "\n".join(sums_lines) + "\n")

        verify_res = check_kit(staging_dir)
        _atomic_replace_dir(staging_dir, kit_dir)
    except Exception:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        raise

    out_summary = dict(verify_res)
    out_summary["output_dir"] = str(kit_dir)

    if not args.no_zip:
        zip_path = kit_dir.parent / f"{kit_dir.name}.zip"
        with tempfile.NamedTemporaryFile(
            prefix=f".{kit_dir.name}.staging-",
            suffix=".zip",
            dir=str(kit_dir.parent),
            delete=False,
        ) as tf:
            tmp_zip = Path(tf.name)
        files_to_zip = sorted(
            (f for f in kit_dir.rglob("*") if f.is_file()),
            key=lambda p: p.relative_to(kit_dir).as_posix(),
        )
        host_path_re = re.compile(r"(?:(?<![A-Za-z0-9])[C-Zc-z]:[\\/]|/(?:Users|home)/)")
        try:
            with zipfile.ZipFile(tmp_zip, "w") as zf:
                for f in files_to_zip:
                    arcname = f"{kit_dir.name}/{f.relative_to(kit_dir).as_posix()}"
                    zi = zipfile.ZipInfo(filename=arcname, date_time=(2026, 11, 21, 0, 0, 0))
                    zi.create_system = 0
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    zi.external_attr = 0o644 << 16
                    zf.writestr(zi, f.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
            with zipfile.ZipFile(tmp_zip, "r") as zf:
                for info in zf.infolist():
                    need(not host_path_re.search(info.filename), f"Host path leak in ZIP member: {info.filename}")
                    low = info.filename.lower()
                    if low.endswith((".bin", ".bi", ".png")) or low.endswith("/verify.py"):
                        continue
                    need(
                        not host_path_re.search(zf.read(info.filename).decode("utf-8")),
                        f"Host path leak inside ZIP content: {info.filename}",
                    )
            os.replace(tmp_zip, zip_path)
        finally:
            if tmp_zip.exists():
                tmp_zip.unlink()
        out_summary["zip_path"] = str(zip_path)
        out_summary["zip_size_bytes"] = zip_path.stat().st_size
        out_summary["zip_sha256"] = sha(zip_path.read_bytes())

    print(json.dumps(out_summary, indent=2))


if __name__ == "__main__":
    main()

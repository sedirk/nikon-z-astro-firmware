"""Standalone clean-room builder for Nikon Z6 C3.80 Astro Firmware (Modified24).

SPDX-License-Identifier: GPL-3.0-or-later

Requires ONLY Python 3.10+ standard library and the user's legally obtained official
Nikon Z6 C3.80 firmware container (`Z_6_0380.bin`, SHA-256 `ff978ffd...`) or its
decoded main EG module (`eg1620_038000.bi`, SHA-256 `1e6348d5...`).

Note on output format:
  Nikon Z6 firmware update reads a single decoded/CRC-valid main module named
  `EG162080.BIN` from the memory card root. This tool outputs `EG162080.BIN`
  (Modified24, SHA-256 `168dcf2c...`, CRC-16 `0x8799`, 112 patch spans) plus an
  unmodified `EG162080.BIN` (Stock C3.80 rollback) directly; it does NOT re-wrap
  the outer 4-module `Z_6_0380.bin` container.
"""
from __future__ import annotations

if not __debug__:
    raise RuntimeError("build_modified24.py must not be executed with Python -O/-OO.")

import argparse
import binascii
import hashlib
import json
from pathlib import Path
import os
import re
import shutil
import struct
import sys
import tempfile
import uuid
import zipfile
THIS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = THIS_DIR.parent
FW_DIR = THIS_DIR / "fw"
if str(FW_DIR) not in sys.path:
    sys.path.insert(0, str(FW_DIR))

from verify_modified24_kit import check_kit  # noqa: E402
from z6_c380_container import (  # noqa: E402
    CONTAINER_SHA256,
    STOCK_EG_SHA256,
    STOCK_EG_SIZE,
    load_stock_eg_module,
)

BASE_ADDR = 0x10020000
MODIFIED24_SHA256 = "168dcf2ceffb2622915e06f6cf8c9f3d90a5824ea2fbb6451b28657897a89653"
MODIFIED24_CRC16_HEX = "8799"
TRAMP_A34D0_HEX = (
    "07b5eff30082fff7cdfe012807d082f3008cbde80740a270e27075f098bc"
    "0020a0706978022900d00121e17082f3008cbde8074075f08bbc"
)
DEFAULT_RECIPE = PROJECT_ROOT / "patches/z6-c380-modified24-astro-raw-red-srgb-600s.json"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def recompute_module_crc(buf: bytearray) -> str:
    crc = binascii.crc_hqx(bytes(buf[:-2]), 0)
    buf[-2:] = crc.to_bytes(2, "big")
    if binascii.crc_hqx(bytes(buf), 0) != 0:
        raise ValueError("CRC-16/XMODEM remainder check failed after trailer update")
    return f"{crc:04x}"


def verify_rom_property_slots(stock: bytes) -> dict[str, str]:
    t1, t2 = struct.unpack_from("<2I", stock, 0x10070474 - BASE_ADDR)
    expected = {
        0x0526: (0xC24CDEA0, 7, 4),
        0x1111: (0xC24DD0EC, 7, 4),
        0x130A: (0xC24CC74C, 7, 4),
        0x131B: (0xC24CC798, 7, 4),
        0x0508: (0xC24CDE28, 7, 4),
        0x1381: (0xC24CC948, 7, 4),
    }
    out: dict[str, str] = {}
    for pid, (exp_ram, exp_type, exp_sz) in expected.items():
        grp, sub = pid >> 8, pid & 0xFF
        bidx, cnt = struct.unpack_from("<HH", stock, t1 + grp * 28 - BASE_ADDR + 0xC)
        if sub >= cnt:
            raise ValueError(f"PID {pid:#06x} index out of range")
        w0, w1, w2, w3 = struct.unpack_from("<4I", stock, t2 + (bidx + sub) * 16 - BASE_ADDR)
        if w2 != exp_ram or (w0 & 0xFF) != exp_type or w1 != exp_sz:
            raise ValueError(f"ROM property table mismatch for PID {pid:#06x}")
        if pid == 0x1111:
            rom_def = struct.unpack_from("<I", stock, w3 - BASE_ADDR)[0]
            if w3 != 0x114E3DF0 or rom_def != 0:
                raise ValueError(f"PID 0x1111 default mismatch: def_va={w3:#x}, val={rom_def}")
        out[f"0x{pid:04x}"] = f"0x{w2:08x}"
    return out


def verify_m24_binary_invariants(m24: bytes, stock: bytes | None = None) -> dict:
    if len(m24) != STOCK_EG_SIZE:
        raise ValueError(f"Expected {STOCK_EG_SIZE} bytes, got {len(m24)}")
    digest = sha256_hex(m24)
    if digest != MODIFIED24_SHA256:
        raise ValueError(f"Modified24 SHA-256 mismatch: expected {MODIFIED24_SHA256}, got {digest}")
    if binascii.crc_hqx(m24, 0) != 0:
        raise ValueError("Modified24 CRC-16/XMODEM remainder is non-zero")
    crc_hex = m24[-2:].hex()
    if crc_hex != MODIFIED24_CRC16_HEX:
        raise ValueError(f"Unexpected trailing CRC-16: {crc_hex} != {MODIFIED24_CRC16_HEX}")

    if m24[0x1002D900 - BASE_ADDR : 0x1002D908 - BASE_ADDR] != bytes.fromhex("4df6a061ccf24c21"):
        raise ValueError("fn_is_astro_r0 @ 0x1002D900 does not load PID 0x0526 (0xC24CDEA0)")
    if m24[0x1014BB28 - BASE_ADDR : 0x1014BB2A - BASE_ADDR] != bytes.fromhex("00bf"):
        raise ValueError("Effective Color Space PID 0x130A sRGB NOP-lock missing at 0x1014BB28")
    if m24[0x100A34D0 - BASE_ADDR : 0x100A34D6 - BASE_ADDR] != bytes.fromhex("8af744bbe9e7"):
        raise ValueError("0x100A34D0 Uncompressed Astro RAW pack hook missing or corrupted 0x100A34D4")
    if m24[0x1002DB5C - BASE_ADDR : 0x1002DB94 - BASE_ADDR] != bytes.fromhex(TRAMP_A34D0_HEX):
        raise ValueError("tramp_a34d0 @ 0x1002DB5C bytes mismatch")
    if m24[0x1002E1B0 - BASE_ADDR : 0x1002E1B4 - BASE_ADDR] != bytes.fromhex("0e461d46"):
        raise ValueError("Astro Red cave header missing at 0x1002E1B0")
    if (
        m24[0x1040E7D8 - BASE_ADDR : 0x1040E7DA - BASE_ADDR] != bytes.fromhex("0024")
        or m24[0x1043A1E0 - BASE_ADDR : 0x1043A1E2 - BASE_ADDR] != bytes.fromhex("18e0")
    ):
        raise ValueError("Astro Red DISP Light-on-dark lock missing at 0x1040E7D8 / 0x1043A1E0")

    for h_addr, exp_hook_hex in (
        (0x10243422, "eaf5c5be"),
        (0x102435AE, "eaf52dbe00bf"),
        (0x10244154, "eaf546b8"),
        (0x104C013C, "6ef7b4b0"),
    ):
        span_len = len(exp_hook_hex) // 2
        if m24[h_addr - BASE_ADDR : h_addr - BASE_ADDR + span_len] != bytes.fromhex(exp_hook_hex):
            raise ValueError(f"Astro Red hook bytes mismatch at {h_addr:#x}")

    if stock is not None:
        for addr, length in ((0x1040AD00, 4), (0x1014F678, 2)):
            off = addr - BASE_ADDR
            if m24[off : off + length] != stock[off : off + length]:
                raise ValueError(f"Auto ISO factory byte parity failed at {addr:#x}")

    return {
        "status": "PASS",
        "size_bytes": len(m24),
        "sha256": digest,
        "crc16_hqx": f"0x{crc_hex}",
        "crc_remainder": 0,
    }


def apply_and_verify_m24_recipe(
    stock: bytes, recipe_path: Path, rebuild_from_source: bool = False
) -> tuple[bytes, dict]:
    if len(stock) != STOCK_EG_SIZE or sha256_hex(stock) != STOCK_EG_SHA256:
        raise ValueError("Stock EG module hash/size mismatch")

    recipe = json.loads(recipe_path.read_text(encoding="utf-8"))
    edits = recipe.get("edits", [])
    if len(edits) != 112:
        raise ValueError(f"Expected 112 patch spans in recipe, got {len(edits)}")

    if rebuild_from_source:
        try:
            from prepare_modified24_lab import collect_m24_edits
        except ImportError as exc:
            raise RuntimeError(
                f"Optional flag --rebuild-from-source requires development dependencies ({exc}). "
                "Install capstone (pip install capstone) or omit --rebuild-from-source to build using standard library."
            ) from exc

        _, _, rebuilt_edits, _, _ = collect_m24_edits(stock)
        if rebuilt_edits != edits:
            raise ValueError("Source Thumb emitters diverged from pinned JSON recipe")

    prop_slots = verify_rom_property_slots(stock)

    buf = bytearray(stock)
    prev_end = 0
    counts = {"astro_ui": 0, "astro_red": 0, "interval": 0, "m600": 0}
    delta_bytes = 0

    for ed in edits:
        addr = int(ed["address"], 16)
        before = bytes.fromhex(ed["before"])
        after = bytes.fromhex(ed["after"])
        off = addr - BASE_ADDR
        end = off + len(before)
        if len(before) == 0 or len(before) != len(after):
            raise ValueError(f"Invalid span length at {addr:#x}")
        if off < prev_end or end > STOCK_EG_SIZE - 2:
            raise ValueError(f"Overlapping or out-of-bounds span at {addr:#x}")
        prev_end = end
        if stock[off:end] != before:
            raise ValueError(f"Stock before-bytes mismatch at {addr:#x}")
        buf[off:end] = after
        delta_bytes += sum(1 for a, b in zip(before, after) if a != b)

        grp = ed["group"]
        if grp.startswith("astro_red_"):
            counts["astro_red"] += 1
        elif grp.startswith("m600_"):
            counts["m600"] += 1
        elif "interval" in grp:
            counts["interval"] += 1
        else:
            counts["astro_ui"] += 1

    if (counts["astro_ui"], counts["astro_red"], counts["interval"], counts["m600"]) != (18, 7, 3, 84):
        raise ValueError(f"Unexpected edit group distribution: {counts}")

    crc_hex = recompute_module_crc(buf)
    m24 = bytes(buf)

    rev = bytearray(m24)
    for ed in edits:
        off = int(ed["address"], 16) - BASE_ADDR
        before = bytes.fromhex(ed["before"])
        rev[off : off + len(before)] = before
    recompute_module_crc(rev)
    if bytes(rev) != stock:
        raise ValueError("Byte-for-byte reversal to Stock C3.80 failed")

    inv = verify_m24_binary_invariants(m24, stock)
    receipt = {
        "status": "PASS",
        "validation_tier": "camera-verified-release",
        "stock_eg_sha256": STOCK_EG_SHA256,
        "modified24_sha256": inv["sha256"],
        "crc16_hqx": f"0x{crc_hex}",
        "size_bytes": len(m24),
        "total_edits": len(edits),
        "edit_groups": counts,
        "byte_deltas_vs_stock": delta_bytes,
        "verified_rom_property_slots": prop_slots,
    }
    return m24, receipt


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
    has_marker = (resolved / "build_receipt.json").is_file() or (
        resolved / "audit/modified24-manifest.json"
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
        f"{expected_prefix}/build_receipt.json" in names
        or f"{expected_prefix}/audit/modified24-manifest.json" in names
    )


def _validate_safe_output_dir(
    out_dir: Path,
    input_paths: list[Path | None],
    force: bool,
    make_zip: bool = False,
) -> None:
    resolved = out_dir.resolve()
    if resolved.parent == resolved:
        raise ValueError(f"Refusing filesystem root as output directory: {resolved}")

    protected_trees = {
        (PROJECT_ROOT / ".git").resolve(),
        (PROJECT_ROOT / "tools").resolve(),
        (PROJECT_ROOT / "patches").resolve(),
        (PROJECT_ROOT / "docs").resolve(),
        (PROJECT_ROOT / "firmware").resolve(),
        (PROJECT_ROOT / "samples").resolve(),
        (PROJECT_ROOT / "work").resolve(),
        (PROJECT_ROOT / "references").resolve(),
    }
    forbidden_ancestors = {
        Path.home().resolve(),
        PROJECT_ROOT.resolve(),
    }
    for anc in forbidden_ancestors:
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

    if out_dir.is_symlink() or (resolved.exists() and resolved.is_file()):
        raise ValueError(f"Output path is an existing file or symlink: {out_dir}")
    if resolved.exists() and any(resolved.iterdir()):
        if not force:
            raise FileExistsError(
                f"Output directory '{resolved}' already exists and is non-empty. "
                "Pass a new '--output-dir' or add '--force' to replace a previous Modified24 build."
            )
        if not _is_replaceable_m24_kit_dir(resolved):
            raise ValueError(
                f"Refusing '--force' overwrite of '{resolved}': directory does not match a "
                "recognized Modified24 build/kit layout."
            )

    if make_zip and (zip_path.exists() or zip_path.is_symlink()):
        if zip_path.is_symlink() or zip_path.is_dir():
            raise ValueError(f"Output ZIP path is an existing directory or symlink: {zip_path}")
        if not force:
            raise FileExistsError(
                f"Output ZIP archive '{zip_path}' already exists. "
                "Pass a new '--output-dir' or add '--force' to replace a previous Modified24 ZIP."
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

FLASH_GUIDE = """Nikon Z6 C3.80 Astro Firmware (Modified24) — Flash & Usage Guide (中英双语刷机指南)
================================================================================

[简体中文说明]
--------------------------------------------------------------------------------
1. 目录结构与刷机前校验 (Pre-Flash Verification)：
   - 01_MODIFIED24/EG162080.BIN          : Modified24 天文增强正式固件主模块
       * 文件大小 : 33,502,842 字节
       * SHA-256  : 168dcf2ceffb2622915e06f6cf8c9f3d90a5824ea2fbb6451b28657897a89653
       * CRC-16   : 0x8799 (全模块 XMODEM 余数为 0x0000)
   - 02_STOCK_C380_ROLLBACK/EG162080.BIN : 尼康官方原厂 C3.80 回退模块
       * 文件大小 : 33,502,842 字节
       * SHA-256  : 1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c
   - 刷机前可在解压目录运行 `python verify.py` 离线核验全部哈希、CRC16 与 112 处补丁字节。
   - 说明：`EG162080.BIN` 为尼康 Z6 机身升级程序直接识别的主固件模块文件（非外层 Z_6_0380.bin 容器）。

2. 两项核心开关分别借用的原厂菜单与用法说明（支持 36 种机身语言）：
   (1) 天文直通RAW模式 —— 借用原厂「照片拍摄菜单 -> 色空间」(PID 0x0526)：
       * 原厂选项为 `0 = sRGB`、`1 = Adobe RGB`；本固件将底层有效色空间 (PID 0x130A) 永久锁定为 sRGB (`0`)，并将该菜单项改造为天文直通 RAW 开关：
       * `标准 (sRGB)` (`0`)    : 100% 保持官方原厂 C3.80 图像流水线
       * `直通RAW (sRGB)` (`1`) : 启用天文直通 RAW 旁路（消除同心彩圈与空间滤波吃星，锁定前端通道增益 1.0000x，保持标准 Z61_ / DSC_ 文件名与 sRGB EXIF）
   (2) 天文红光显示 —— 借用原厂「设定菜单 -> 信息显示」(PID 0x1111，出厂重置默认值 = `0`)：
       * 原厂选项为 `0 = 光亮时用暗字体`、`1 = 黑暗时用亮字体`；本固件将 `DISP` 参数信息屏永久锁定为护眼的「黑底亮字」，并将该菜单项改造为纯红夜视显示开关：
       * `关闭 (标准色彩)` (`0`) : 背面显示屏与 OLED 取景器保持标准全彩显示（重设所有设定后的默认状态）
       * `开启 (天文红光)` (`1`) : 背面显示屏与 OLED 取景器（含硬件构图网格）切换为纯红夜视模式 (`G = 0, B = 0`)，保护暗适应；实拍 NEF RAW、JPEG、测光直方图与外接 HDMI 输出完全不受影响。
       * 首次开机提示：尼康固件升级会保留机身 NVRAM 个人设定。若您刷机前在原厂固件下将「设定菜单 -> 信息显示」设为了「黑暗时用亮字体 (`1`)」，刷入后首次开机会直接处于红光显示状态；只需进入「设定菜单 -> 天文红光显示」切回一次 `关闭 (标准色彩)` (`0`) 即可持久化保存标准全彩显示。
   (3) NEF(RAW)记录与 M 档扩展慢门 / 间隔拍摄：
       * NEF(RAW) 支持 14位 / 12位 位深度，完整兼容无损压缩、未压缩及有损压缩全模式与全快门档位（日常深空推荐使用「14位 + 无损压缩」）。
       * M 档主指令拨盘越过 30" 后可直接选择 60"、90"、120"、180"、240"、300"、480"、600" 共 8 档长曝光；间隔拍摄按前帧曝光结束后起算帧间隔并动态刷新预计结束时间。

3. 刷入与回退步骤：
   - 使用相机内格式化过的 XQD / CFexpress 存储卡，并装入满电原厂电池；
   - 将 `01_MODIFIED24/EG162080.BIN` 复制到存储卡根目录（卡根目录只保留这一个 .BIN 文件）；
   - 开机进入「设定菜单 -> 固件版本 -> 版本升级」，按屏幕提示完成升级（全程严禁断电或拔卡）；
   - 随时回退原厂：将 `02_STOCK_C380_ROLLBACK/EG162080.BIN` 放入存储卡根目录执行「版本升级」即可。


[English Guide]
--------------------------------------------------------------------------------
1. Package Layout & Pre-Flash Checksum Verification:
   - 01_MODIFIED24/EG162080.BIN          : Modified24 Astro Firmware main module
       * Expected Size   : 33,502,842 bytes
       * Expected SHA256 : 168dcf2ceffb2622915e06f6cf8c9f3d90a5824ea2fbb6451b28657897a89653
       * Expected CRC16  : 0x8799 (full-module XMODEM remainder 0x0000)
   - 02_STOCK_C380_ROLLBACK/EG162080.BIN : Official Nikon Stock C3.80 rollback module
       * Expected Size   : 33,502,842 bytes
       * Expected SHA256 : 1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c
   - Run `python verify.py` inside this folder before flashing to verify SHA-256, CRC16, and all 112 patch sites.
   - Note: `EG162080.BIN` is the decoded main firmware module read directly by Setup Menu -> Firmware version -> Update.

2. Repurposed Factory Menus & Astro Feature Guide (36 Camera Languages):
   (1) Astro Direct RAW — Repurposes `Photo Shooting Menu -> Color space` (PID 0x0526):
       * Stock options were `0 = sRGB`, `1 = Adobe RGB`. Effective Color Space (PID 0x130A) is permanently locked to `0 (sRGB)` while PID 0x0526 switches the RAW pipeline:
       * `Standard (sRGB)` (`0`)   : 100% factory Stock C3.80 ISP pipeline
       * `Direct RAW (sRGB)` (`1`) : Full-size Astro RAW bypass (eliminates concentric rings & spatial star-eating, locks 1.0000x unity frontend channel gain, preserves Z61_ / DSC_ naming & sRGB EXIF)
   (2) Astro Red Night-Vision Display — Repurposes `Setup Menu -> Information display` (PID 0x1111, factory reset default = `0`):
       * Stock options were `0 = Dark on light`, `1 = Light on dark`. The `DISP` shooting info screen is permanently locked to dark-adapted `Light on dark`, while PID 0x1111 switches rear LCD & OLED EVF night vision:
       * `Off (Standard)` (`0`) : Standard full-color display on rear LCD & EVF (factory reset default)
       * `On (Astro Red)` (`1`) : Pure-red night-vision display (`G = 0, B = 0`) on rear LCD & OLED EVF (including hardware framing grid) while keeping captured NEF RAW, JPEG, AE/AF, histograms, and external HDMI output 100% normal.
       * First-Boot NVRAM Note: Nikon firmware updates preserve user settings in camera NVRAM. If `Setup Menu -> Information display` was previously set to `Light on dark (1)` under stock firmware, the camera will boot directly in `On (Astro Red)` mode after flashing; simply select `Setup Menu -> Astro red display -> Off (Standard)` once to save standard full-color persistently.
   (3) NEF (RAW) Recording, Extended Shutter & Interval Timer:
       * Supports `14-bit` and `12-bit` NEF across `Lossless compressed`, `Uncompressed`, and lossy compressed modes at all shutter speeds (`14-bit + Lossless compressed` recommended).
       * In M mode, rotate the main command dial past 30" to select 60", 90", 120", 180", 240", 300", 480", or 600". Interval timer counts from exposure completion and dynamically updates End Day/Time.

3. Flashing & Rollback Steps:
   - Format an XQD / CFexpress card in-camera and insert a fully charged Nikon battery.
   - Copy ONLY ONE `EG162080.BIN` (`01_MODIFIED24/EG162080.BIN`) to the root directory of the memory card.
   - Navigate to Setup Menu -> Firmware version -> Update and follow on-screen prompts.
   - NEVER power off or remove battery/card during flashing.
   - To revert to official factory C3.80 at any time while the menu is accessible, place
     `02_STOCK_C380_ROLLBACK/EG162080.BIN` at the card root and run Firmware Update.

Source Code & GPL-3.0 License: https://github.com/sedirk/nikon-z-astro-firmware
"""


def run_verify_only(target: Path) -> int:
    p = target.resolve()
    if p.is_dir():
        res = check_kit(p)
        res["verified_kit_dir"] = str(p)
        print(json.dumps(res, indent=2))
        return 0

    if not p.is_file():
        raise FileNotFoundError(f"Verify target does not exist: {p}")
    res = verify_m24_binary_invariants(p.read_bytes())
    res["verified_path"] = str(p)
    print(json.dumps(res, indent=2))
    return 0


def _verify_zip_privacy(zip_path: Path) -> None:
    host_path_re = re.compile(r"(?:(?<![A-Za-z0-9])[C-Zc-z]:[\\/]|/(?:Users|home)/)")
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if host_path_re.search(info.filename):
                raise ValueError(f"Host path leak in ZIP member name: {info.filename}")
            low = info.filename.lower()
            if low.endswith((".bin", ".bi", ".png")) or low.endswith("/verify.py"):
                continue
            txt = zf.read(info.filename).decode("utf-8")
            if host_path_re.search(txt):
                raise ValueError(f"Host path leak inside ZIP member content: {info.filename}")


def main() -> None:
    if not __debug__:
        raise RuntimeError("build_modified24.py must not be executed with Python -O/-OO.")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--stock",
        "--input",
        dest="stock",
        type=Path,
        default=None,
        help=f"Path to official Z_6_0380.bin ({CONTAINER_SHA256[:12]}...) or decoded eg1620_038000.bi",
    )
    ap.add_argument(
        "--recipe",
        type=Path,
        default=DEFAULT_RECIPE,
        help="Path to Modified24 JSON patch recipe",
    )
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "outputs/Nikon-Z6-C380-Modified24-Astro-Firmware",
        help="Destination directory for built EG162080.BIN package",
    )
    ap.add_argument(
        "--rebuild-from-source",
        action="store_true",
        help="Cross-check JSON recipe against Thumb assembly emitters in tools/fw/",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="Allow replacing an existing Modified24 output directory after staged build succeeds",
    )
    ap.add_argument(
        "--zip",
        action="store_true",
        help="Also package a deterministic sibling <output-dir>.zip archive ready for distribution",
    )
    ap.add_argument(
        "--verify",
        type=Path,
        default=None,
        help="Verify an existing built kit directory or EG162080.BIN file without building",
    )
    args = ap.parse_args()

    if args.verify is not None:
        raise SystemExit(run_verify_only(args.verify))

    out_dir = args.output_dir.resolve()
    _validate_safe_output_dir(
        out_dir, [args.stock, args.recipe], args.force, make_zip=args.zip
    )
    stock_bytes = load_stock_eg_module(args.stock, PROJECT_ROOT)
    m24_bytes, receipt = apply_and_verify_m24_recipe(
        stock_bytes, args.recipe.resolve(), rebuild_from_source=args.rebuild_from_source
    )

    out_dir.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(tempfile.mkdtemp(prefix=f".{out_dir.name}.staging-", dir=str(out_dir.parent)))
    try:
        slot_m24 = staging_dir / "01_MODIFIED24/EG162080.BIN"
        slot_stk = staging_dir / "02_STOCK_C380_ROLLBACK/EG162080.BIN"
        slot_m24.parent.mkdir(parents=True, exist_ok=True)
        slot_stk.parent.mkdir(parents=True, exist_ok=True)
        slot_m24.write_bytes(m24_bytes)
        slot_stk.write_bytes(stock_bytes)

        def _write_lf_text(dst: Path, text: str) -> None:
            dst.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))

        audit_dir = staging_dir / "audit"
        audit_dir.mkdir(parents=True, exist_ok=True)
        _write_lf_text(
            audit_dir / "modified24-manifest.json",
            args.recipe.resolve().read_text(encoding="utf-8"),
        )
        verifier_src = FW_DIR / "verify_modified24_kit.py"
        if not verifier_src.is_file():
            raise FileNotFoundError(f"Missing verifier script: {verifier_src}")
        _write_lf_text(staging_dir / "verify.py", verifier_src.read_text(encoding="utf-8"))
        for legal_name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            legal_src = PROJECT_ROOT / legal_name
            if legal_src.is_file():
                _write_lf_text(staging_dir / legal_name, legal_src.read_text(encoding="utf-8"))

        _write_lf_text(staging_dir / "FLASH_INSTRUCTIONS.txt", FLASH_GUIDE)
        _write_lf_text(
            staging_dir / "SHA256SUMS.txt",
            f"{MODIFIED24_SHA256}  01_MODIFIED24/EG162080.BIN\n"
            f"{STOCK_EG_SHA256}  02_STOCK_C380_ROLLBACK/EG162080.BIN\n",
        )
        _write_lf_text(
            staging_dir / "build_receipt.json",
            json.dumps(receipt, indent=2, ensure_ascii=False) + "\n",
        )
        receipt["rebuilt_from_thumb_emitters"] = args.rebuild_from_source

        check_kit(staging_dir)
        _atomic_replace_dir(staging_dir, out_dir)
    except Exception:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        raise

    if args.zip:
        zip_path = out_dir.parent / f"{out_dir.name}.zip"
        with tempfile.NamedTemporaryFile(
            prefix=f".{out_dir.name}.staging-",
            suffix=".zip",
            dir=str(out_dir.parent),
            delete=False,
        ) as tf:
            tmp_zip = Path(tf.name)
        files_to_zip = sorted(
            (f for f in out_dir.rglob("*") if f.is_file()),
            key=lambda p: p.relative_to(out_dir).as_posix(),
        )
        try:
            with zipfile.ZipFile(tmp_zip, "w") as zf:
                for f in files_to_zip:
                    arcname = f"{out_dir.name}/{f.relative_to(out_dir).as_posix()}"
                    zi = zipfile.ZipInfo(filename=arcname, date_time=(2026, 11, 21, 0, 0, 0))
                    zi.create_system = 0
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    zi.external_attr = 0o644 << 16
                    zf.writestr(zi, f.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
            _verify_zip_privacy(tmp_zip)
            os.replace(tmp_zip, zip_path)
        finally:
            if tmp_zip.exists():
                tmp_zip.unlink()
        receipt["zip_path"] = str(zip_path)
        receipt["zip_size_bytes"] = zip_path.stat().st_size
        receipt["zip_sha256"] = sha256_hex(zip_path.read_bytes())
    receipt["output_dir"] = str(out_dir)
    print(json.dumps(receipt, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

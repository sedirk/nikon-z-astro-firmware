"""Public stock-only builder & offline verifier for Nikon Z6 C3.80 Astro Firmware (Modified22).

Requires ONLY Python 3.10+ standard library and the user's legally obtained official
Nikon Z6 C3.80 firmware container (`Z_6_0380.bin`, SHA-256 `ff978ffd...`) or its
decoded main EG module (`eg1620_038000.bi`, SHA-256 `1e6348d5...`).

Note on output format:
  Nikon Z6 firmware update reads a single decoded/CRC-valid main module named
  `EG162080.BIN` from the memory card root. This tool outputs `EG162080.BIN`
  (Modified22) plus an unmodified `EG162080.BIN` (Stock C3.80 rollback) directly;
  it does NOT re-wrap the outer 4-module `Z_6_0380.bin` container.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile

THIS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = THIS_DIR.parent
FW_DIR = THIS_DIR / "fw"
if str(FW_DIR) not in sys.path:
    sys.path.insert(0, str(FW_DIR))

from z6_c380_container import (  # noqa: E402
    CONTAINER_SHA256,
    STOCK_EG_SHA256,
    STOCK_EG_SIZE,
    load_stock_eg_module,
)

BASE_ADDR = 0x10020000
MODIFIED22_SHA256 = "c6a23ea40f03d83c6c721e96e8b5af8a8422a7b4ed81d39222392b7635681771"
MODIFIED22_CRC16_HEX = "48f3"
DEFAULT_RECIPE = PROJECT_ROOT / "patches/z6-c380-modified22-color-space-pid0526-srgb-600s.json"


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
        w0, w1, w2, _ = struct.unpack_from("<4I", stock, t2 + (bidx + sub) * 16 - BASE_ADDR)
        if w2 != exp_ram or (w0 & 0xFF) != exp_type or w1 != exp_sz:
            raise ValueError(f"ROM property table mismatch for PID {pid:#06x}")
        out[f"0x{pid:04x}"] = f"0x{w2:08x}"
    return out


def verify_m22_binary_invariants(m22: bytes, stock: bytes | None = None) -> dict:
    if len(m22) != STOCK_EG_SIZE:
        raise ValueError(f"Expected {STOCK_EG_SIZE} bytes, got {len(m22)}")
    digest = sha256_hex(m22)
    if digest != MODIFIED22_SHA256:
        raise ValueError(f"Modified22 SHA-256 mismatch: expected {MODIFIED22_SHA256}, got {digest}")
    if binascii.crc_hqx(m22, 0) != 0:
        raise ValueError("Modified22 CRC-16/XMODEM remainder is non-zero")
    crc_hex = m22[-2:].hex()
    if crc_hex != MODIFIED22_CRC16_HEX:
        raise ValueError(f"Unexpected trailing CRC-16: {crc_hex} != {MODIFIED22_CRC16_HEX}")

    if m22[0x1002D900 - BASE_ADDR : 0x1002D908 - BASE_ADDR] != bytes.fromhex("4df6a061ccf24c21"):
        raise ValueError("fn_is_astro_r0 @ 0x1002D900 does not load PID 0x0526 (0xC24CDEA0)")
    if m22[0x1014BB28 - BASE_ADDR : 0x1014BB2A - BASE_ADDR] != bytes.fromhex("00bf"):
        raise ValueError("Effective Color Space PID 0x130A sRGB NOP-lock missing at 0x1014BB28")

    if stock is not None:
        for addr, length in ((0x1040AD00, 4), (0x1014F678, 2)):
            off = addr - BASE_ADDR
            if m22[off : off + length] != stock[off : off + length]:
                raise ValueError(f"Auto ISO factory byte parity failed at {addr:#x}")

    return {
        "status": "PASS",
        "size_bytes": len(m22),
        "sha256": digest,
        "crc16_hqx": f"0x{crc_hex}",
        "crc_remainder": 0,
    }


def apply_and_verify_m22_recipe(
    stock: bytes, recipe_path: Path, rebuild_from_source: bool = False
) -> tuple[bytes, dict]:
    if len(stock) != STOCK_EG_SIZE or sha256_hex(stock) != STOCK_EG_SHA256:
        raise ValueError("Stock EG module hash/size mismatch")

    recipe = json.loads(recipe_path.read_text(encoding="utf-8"))
    edits = recipe.get("edits", [])
    if len(edits) != 104:
        raise ValueError(f"Expected 104 patch spans in recipe, got {len(edits)}")

    if rebuild_from_source:
        try:
            from prepare_modified22_lab import collect_m22_edits
        except ImportError as e:
            raise RuntimeError(
                f"Optional flag --rebuild-from-source requires development dependencies ({e}). "
                "Install capstone (pip install capstone) or omit --rebuild-from-source to build using standard library."
            ) from e

        rebuilt_edits, _ = collect_m22_edits(stock)
        if rebuilt_edits != edits:
            raise ValueError("Source Thumb emitters diverged from pinned JSON recipe")
    prop_slots = verify_rom_property_slots(stock)

    buf = bytearray(stock)
    prev_end = 0
    counts = {"astro_ui": 0, "interval": 0, "m600": 0}
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
        if grp.startswith("m600_"):
            counts["m600"] += 1
        elif "interval" in grp:
            counts["interval"] += 1
        else:
            counts["astro_ui"] += 1

    if (counts["astro_ui"], counts["interval"], counts["m600"]) != (17, 3, 84):
        raise ValueError(f"Unexpected edit group distribution: {counts}")

    crc_hex = recompute_module_crc(buf)
    m22 = bytes(buf)

    # Exact byte-reversal proof back to Stock C3.80
    rev = bytearray(m22)
    for ed in edits:
        off = int(ed["address"], 16) - BASE_ADDR
        before = bytes.fromhex(ed["before"])
        rev[off : off + len(before)] = before
    recompute_module_crc(rev)
    if bytes(rev) != stock:
        raise ValueError("Byte-for-byte reversal to Stock C3.80 failed")

    inv = verify_m22_binary_invariants(m22, stock)
    receipt = {
        "status": "PASS",
        "stock_eg_sha256": STOCK_EG_SHA256,
        "modified22_sha256": inv["sha256"],
        "crc16_hqx": f"0x{crc_hex}",
        "size_bytes": len(m22),
        "total_edits": len(edits),
        "edit_groups": counts,
        "byte_deltas_vs_stock": delta_bytes,
        "verified_rom_property_slots": prop_slots,
        "rebuilt_from_thumb_emitters": rebuild_from_source,
    }
    return m22, receipt


def _validate_safe_output_dir(
    out_dir: Path, input_path: Path | None, force: bool
) -> None:
    resolved = out_dir.resolve()
    forbidden = {PROJECT_ROOT.resolve(), THIS_DIR.resolve()}
    if input_path is not None:
        forbidden.add(input_path.resolve())
        forbidden.add(input_path.resolve().parent)

    for protected in forbidden:
        if resolved == protected or resolved in protected.parents:
            raise ValueError(f"Refusing unsafe output directory: {resolved}")

    if resolved.exists():
        if resolved.is_file():
            raise ValueError(f"Output path is an existing file: {resolved}")
        if any(resolved.iterdir()) and not force:
            raise FileExistsError(
                f"Output directory '{resolved}' already exists and is non-empty. "
                "Pass a new '--output-dir' or add '--force' to replace a previous build."
            )


FLASH_GUIDE = """Nikon Z6 C3.80 Astro Firmware (Modified22) — Local Build Package
================================================================

1. Pre-Flash Checksum Verification:
   Verify SHA-256 of `01_MODIFIED22/EG162080.BIN` before copying to card:
     Expected Size   : 33,502,842 bytes
     Expected SHA256 : c6a23ea40f03d83c6c721e96e8b5af8a8422a7b4ed81d39222392b7635681771
     Expected CRC16  : 0x48f3 (full-module XMODEM remainder 0x0000)

   Note: `EG162080.BIN` is the camera's decoded main firmware module read directly
   by Setup Menu -> Firmware version -> Update (not an outer 4-module Z_6_0380.bin).

2. Recommended Astro RAW Camera Settings (Important):
   - Photo Shooting Menu -> Astro RAW mode (天文直通RAW模式):
       * Standard (sRGB)  [标准 (sRGB)]    : 100% factory Stock C3.80 ISP pipeline
       * Astro RAW (sRGB) [直通RAW (sRGB)] : 13-site Astro RAW bypass + sRGB naming/EXIF
   - NEF (RAW) recording:
       * NEF (RAW) bit depth   : 14-bit
       * NEF (RAW) compression : Lossless compressed (无损压缩) [REQUIRED for >=1s long exposures]
         (Caution: Do NOT combine 'Astro RAW' + 'Uncompressed / 未压缩' on >=1s exposures;
          see docs/MODIFIED22_REAL_NEF_AUDIT_2026-11-17.md for raw format-3 buffer details.)

3. Flashing Steps:
   - Format an XQD / CFexpress card in-camera and insert a fully charged Nikon battery.
   - Copy ONLY ONE `EG162080.BIN` (`01_MODIFIED22/EG162080.BIN`) to the root directory of the card.
   - Navigate to Setup Menu -> Firmware version -> Update and follow on-screen prompts.
   - NEVER power off or remove battery/card during flashing.
   - To revert to factory firmware at any time when the menu is accessible, place
     `02_STOCK_C380_ROLLBACK/EG162080.BIN` at the card root and run Firmware Update.
"""


def run_verify_only(target: Path) -> int:
    p = target.resolve()
    if p.is_dir():
        cand = p / "01_MODIFIED22/EG162080.BIN"
        if not cand.is_file():
            cand = p / "01_TEST_MODIFIED22/EG162080.BIN"
        stock_p = p / "02_STOCK_C380_ROLLBACK/EG162080.BIN"
        if not stock_p.is_file():
            stock_p = p / "05_STOCK_C380/EG162080.BIN"
        if not cand.is_file():
            raise FileNotFoundError(f"No Modified22 EG162080.BIN found inside {p}")
        stock_b = stock_p.read_bytes() if stock_p.is_file() else None
        if stock_b is not None and sha256_hex(stock_b) != STOCK_EG_SHA256:
            raise ValueError(f"Rollback Stock EG162080.BIN SHA-256 mismatch in {stock_p}")
        res = verify_m22_binary_invariants(cand.read_bytes(), stock_b)
        res["verified_path"] = str(cand)
        if stock_b is not None:
            res["rollback_stock_verified"] = True
        print(json.dumps(res, indent=2))
        return 0

    if not p.is_file():
        raise FileNotFoundError(f"Verify target does not exist: {p}")
    res = verify_m22_binary_invariants(p.read_bytes())
    res["verified_path"] = str(p)
    print(json.dumps(res, indent=2))
    return 0


def main() -> None:
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
        help="Path to Modified22 JSON patch recipe",
    )
    ap.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "outputs/Z6-C380-modified22-local-build",
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
        help="Allow replacing an existing output directory after staged build succeeds",
    )
    ap.add_argument(
        "--verify",
        type=Path,
        default=None,
        help="Verify an existing built directory or EG162080.BIN file without building",
    )
    args = ap.parse_args()

    if args.verify is not None:
        raise SystemExit(run_verify_only(args.verify))

    out_dir = args.output_dir.resolve()
    _validate_safe_output_dir(out_dir, args.stock, args.force)

    # Validate inputs and build in memory BEFORE touching filesystem output
    stock_bytes = load_stock_eg_module(args.stock, PROJECT_ROOT)
    m22_bytes, receipt = apply_and_verify_m22_recipe(
        stock_bytes, args.recipe.resolve(), rebuild_from_source=args.rebuild_from_source
    )

    out_dir.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(tempfile.mkdtemp(prefix=f".{out_dir.name}.staging-", dir=str(out_dir.parent)))
    try:
        slot_m22 = staging_dir / "01_MODIFIED22/EG162080.BIN"
        slot_stk = staging_dir / "02_STOCK_C380_ROLLBACK/EG162080.BIN"
        slot_m22.parent.mkdir(parents=True, exist_ok=True)
        slot_stk.parent.mkdir(parents=True, exist_ok=True)
        slot_m22.write_bytes(m22_bytes)
        slot_stk.write_bytes(stock_bytes)

        # Read-back verification on staged files
        verify_m22_binary_invariants(slot_m22.read_bytes(), slot_stk.read_bytes())
        if sha256_hex(slot_stk.read_bytes()) != STOCK_EG_SHA256:
            raise ValueError("Staged Stock rollback readback mismatch")

        (staging_dir / "FLASH_INSTRUCTIONS.txt").write_text(FLASH_GUIDE, encoding="utf-8")
        (staging_dir / "SHA256SUMS.txt").write_text(
            f"{MODIFIED22_SHA256}  01_MODIFIED22/EG162080.BIN\n"
            f"{STOCK_EG_SHA256}  02_STOCK_C380_ROLLBACK/EG162080.BIN\n",
            encoding="utf-8",
        )
        (staging_dir / "build_receipt.json").write_text(
            json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        if out_dir.exists():
            shutil.rmtree(out_dir)
        staging_dir.rename(out_dir)
    except Exception:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        raise

    receipt["output_dir"] = str(out_dir)
    print(json.dumps(receipt, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

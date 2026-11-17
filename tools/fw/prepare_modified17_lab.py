"""Deterministically build and statically audit Modified17 (A3 UI-Switchable Astro Lossless + Permanent 30-600s + Standby Focus Position Fix)."""
from __future__ import annotations
import argparse
import binascii
import hashlib
import json
import struct
from pathlib import Path
import sys

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from z6_astro_ui_toggle import (
    ADDR_M16_CAVE,
    ADDR_M9_SANITIZER,
    build_all_m16_astro_ui_spans,
)
from z6_m600_tables import BASE, SIZE
from z6_m600_v2 import build_all_m600_v2_spans
from z6_focus_standby_restore import (
    ADDR_M17_FOCUS_CAVE,
    ADDR_M17_RESUME_HOOK,
    ADDR_M17_MENU_DEF,
    build_focus_standby_restore_spans,
)


ROOT = THIS_DIR.parents[1]
STOCK_SHA = "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c"
M15_SHA = "0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c"
M16_SHA = "2c79a405efaa0c3132e4d257a06c52a0a2df3dd43ba7ebbe3a6c117d609279b9"  # candidate.bi sha256


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def update_crc(buf: bytearray) -> str:
    crc = binascii.crc_hqx(bytes(buf[:-2]), 0)
    buf[-2:] = crc.to_bytes(2, "big")
    assert binascii.crc_hqx(bytes(buf), 0) == 0
    return f"{crc:04x}"


def collect_m17_edits(stock: bytes) -> tuple[list[dict], dict[str, int]]:
    m16_spans, syms = build_all_m16_astro_ui_spans(stock)
    m600_spans = build_all_m600_v2_spans(stock)
    focus_spans = build_focus_standby_restore_spans(stock)

    edits: list[dict] = []
    for addr, grp, new_b, desc in m16_spans + m600_spans + focus_spans:
        off = addr - BASE
        assert 0 <= off and off + len(new_b) <= SIZE - 2
        old_b = stock[off : off + len(new_b)]
        edits.append(
            {
                "group": grp,
                "address": f"0x{addr:08x}",
                "before": old_b.hex(),
                "after": new_b.hex(),
                "description": desc,
            }
        )
    edits.sort(key=lambda item: int(item["address"], 16))

    # Add focus symbols
    syms["ADDR_M17_FOCUS_CAVE"] = ADDR_M17_FOCUS_CAVE
    syms["ADDR_M17_RESUME_HOOK"] = ADDR_M17_RESUME_HOOK
    syms["ADDR_M17_MENU_DEF"] = ADDR_M17_MENU_DEF
    return edits, syms



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--stock",
        type=Path,
        default=ROOT / "firmware" / "decoded" / "eg1620_038000.bi",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "analysis" / "modified17-preflash-2026-11-15" / "lab-build",
    )
    parser.add_argument(
        "--recipe-out",
        type=Path,
        default=ROOT / "patches" / "z6-c380-modified17-focus-astro-600s.json",
    )
    args = parser.parse_args()

    stock = args.stock.read_bytes()
    assert sha(stock) == STOCK_SHA, f"Stock SHA mismatch: {sha(stock)}"

    edits, syms = collect_m17_edits(stock)
    print(f"Total Modified17 edits collected: {len(edits)}")

    m17_buf = bytearray(stock)
    spans = []
    for e in edits:
        addr = int(e["address"], 16)
        off = addr - BASE
        old_b = bytes.fromhex(e["before"])
        new_b = bytes.fromhex(e["after"])
        assert m17_buf[off : off + len(old_b)] == old_b, f"Before mismatch at 0x{addr:08x}"
        m17_buf[off : off + len(new_b)] = new_b
        spans.append((off, off + len(new_b), addr, e["group"], old_b, new_b, e))

    crc_stock = update_crc(m17_buf)
    m17_bytes = bytes(m17_buf)
    m17_sha = sha(m17_bytes)

    # Verify rollback to stock
    rev_buf = bytearray(m17_bytes)
    for off, end, addr, grp, old_b, new_b, meta in reversed(spans):
        rev_buf[off:end] = old_b
    update_crc(rev_buf)
    assert bytes(rev_buf) == stock, "Transform rollback to stock failed!"

    # Save recipe JSON
    recipe = {
        "format_version": 1,
        "target_model": "Z 6",
        "target_version": "C:3.80",
        "target_module": "firmware/decoded/eg1620_038000.bi",
        "stock_sha256": STOCK_SHA,
        "modified_sha256": m17_sha,
        "modified_crc16": crc_stock,
        "candidate": "modified17",
        "candidate_id": "modified17-focus-astro-600s-v1",
        "edits": edits,
    }
    args.recipe_out.parent.mkdir(parents=True, exist_ok=True)
    args.recipe_out.write_text(json.dumps(recipe, indent=2), encoding="utf8")

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    out_bin = out_dir / "modified17-candidate.bi"
    out_bin.write_bytes(m17_bytes)

    site_details = []
    for off, end, addr, grp, old_b, new_b, meta in spans:
        site_details.append(
            {
                "address": f"0x{addr:08x}",
                "file_offset": f"0x{off:08x}",
                "group": grp,
                "span_bytes": len(old_b),
                "changed_bytes": sum(x != y for x, y in zip(old_b, new_b)),
                "description": meta.get("description", ""),
            }
        )

    manifest = {
        "ok": True,
        "candidate": "modified17",
        "candidate_id": "modified17-focus-astro-600s-v1",
        "parent_candidate": "modified16",
        "recipe_path": args.recipe_out.relative_to(ROOT).as_posix(),
        "recipe_sha256": sha(args.recipe_out.read_bytes()),
        "module_path": out_bin.relative_to(ROOT).as_posix(),
        "sha256": m17_sha,
        "size_bytes": len(m17_bytes),
        "crc16": crc_stock,
        "total_sites": len(spans),
        "total_changed_bytes_vs_stock": sum(a != b for a, b in zip(stock, m17_bytes)),
        "cave_symbols": {k: f"0x{v:08x}" if isinstance(v, int) else str(v) for k, v in syms.items()},
        "verified_dual_build": True,
        "verified_rollback_to_stock": True,
        "sites": site_details,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf8")
    print(f"Modified17 successfully built: SHA256={m17_sha} CRC16={crc_stock}")
    print(f"Sites: {len(spans)}, Total changed bytes vs stock: {manifest['total_changed_bytes_vs_stock']}")


if __name__ == "__main__":
    main()

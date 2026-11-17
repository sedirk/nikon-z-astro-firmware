"""Independent offline verification of the final Modified14 (Modified13 + 30-600s) delivery kit."""
from __future__ import annotations
import argparse
import binascii
import hashlib
import json
from pathlib import Path

DIGESTS = {
    "modified14": "6d970609c18ac64302e82a7e4f4bfba9d8d4b14a606b55bf2cbc56dc37ea754b",
    "modified13": "3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749",
    "modified12": "9734012be0e063fa8f2ccbf77c2dd5a63a76be2f45887aa6b806b97b441cb67c",
    "modified10": "85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4",
    "stock": "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c",
}
PATHS = {
    "modified14": "01_TEST_MODIFIED14/EG162080.BIN",
    "modified13": "02_BACK_TO_MODIFIED13/EG162080.BIN",
    "modified12": "03_BACK_TO_MODIFIED12/EG162080.BIN",
    "modified10": "04_BACK_TO_MODIFIED10/EG162080.BIN",
    "stock": "05_STOCK_C380/EG162080.BIN",
}
RECIPE_SHA = "86d97d4819cc61e16a5a0cb7dae26cebcfb6bf0766cd8df7d21e3c1c8c8b4887"
BASE = 0x10020000
SIZE = 33502842


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def need(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _apply_crc(buf: bytearray) -> None:
    crc = binascii.crc_hqx(bytes(buf[:-2]), 0)
    buf[-2:] = crc.to_bytes(2, "big")
    need(binascii.crc_hqx(bytes(buf), 0) == 0, "CRC recomputation check failed")


def check_kit(kit_dir: Path) -> dict:
    blobs = {}
    for name, rel in PATHS.items():
        p = kit_dir / rel
        need(p.is_file(), f"Missing file: {rel}")
        b = p.read_bytes()
        need(len(b) == SIZE, f"Wrong size for {rel}: {len(b)} != {SIZE}")
        need(sha(b) == DIGESTS[name], f"Hash mismatch for {rel}")
        need(binascii.crc_hqx(b, 0) == 0, f"CRC failure for {rel}")
        blobs[name] = b

    recipe_file = kit_dir / "reports/recipe.json"
    need(recipe_file.is_file(), "Missing reports/recipe.json")
    recipe_bytes = recipe_file.read_bytes()
    need(sha(recipe_bytes) == RECIPE_SHA, "Tampered or mismatched reports/recipe.json")
    edits = json.loads(recipe_bytes.decode("utf8"))["candidates"][0]["edits"]
    need(len(edits) == 98, f"Expected 98 patch sites, got {len(edits)}")

    stock = blobs["stock"]
    m13 = blobs["modified13"]
    m14 = blobs["modified14"]

    rebuilt_from_stock = bytearray(stock)
    rebuilt_from_m13 = bytearray(m13)
    prev_end = 0
    m600_count = 0

    for e in edits:
        addr = int(e["address"], 16)
        old_b = bytes.fromhex(e["before"])
        new_b = bytes.fromhex(e["after"])
        off = addr - BASE
        end = off + len(old_b)
        need(len(old_b) == len(new_b) > 0, f"Invalid edit span at {addr:#x}")
        need(prev_end <= off and end <= SIZE - 2, f"Unsorted or overlapping span at {addr:#x}")
        prev_end = end

        need(stock[off:end] == old_b, f"Stock anchor mismatch at {addr:#x}")
        need(m14[off:end] == new_b, f"Modified14 patch mismatch at {addr:#x}")
        rebuilt_from_stock[off:end] = new_b

        if e["group"].startswith("m600_"):
            need(m13[off:end] == old_b, f"Modified13 anchor mismatch at {addr:#x}")
            rebuilt_from_m13[off:end] = new_b
            m600_count += 1
        else:
            need(m13[off:end] == new_b, f"Modified13 inherited site mismatch at {addr:#x}")

    need(m600_count == 84, f"Expected 84 m600 sites, got {m600_count}")
    _apply_crc(rebuilt_from_stock)
    _apply_crc(rebuilt_from_m13)
    need(bytes(rebuilt_from_stock) == m14, "Rebuilt from Stock diverged from Modified14")
    need(bytes(rebuilt_from_m13) == m14, "Rebuilt from Modified13 diverged from Modified14")

    return {"status": "OK", "total_files": len(PATHS), "sites": len(edits), "m600_sites": m600_count}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("kit_dir", type=Path, nargs="?", default=Path(__file__).resolve().parent)
    args = ap.parse_args()
    res = check_kit(args.kit_dir)
    print(f"PASS: {res}")


if __name__ == "__main__":
    main()

"""Independent offline verification of the final Modified16 (Astro UI-Switchable + 30-600s v2) delivery kit."""
from __future__ import annotations
import argparse
import binascii
import hashlib
import json
from pathlib import Path

DIGESTS = {
    "modified16": "4cca328ccbac4a025111bcf5fd6d88ca8667eb2da0b543ce3db42cf0d8da91cf",
    "modified15": "0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c",
    "modified13": "3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749",
    "modified12": "9734012be0e063fa8f2ccbf77c2dd5a63a76be2f45887aa6b806b97b441cb67c",
    "stock": "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c",
}
PATHS = {
    "modified16": "01_TEST_MODIFIED16/EG162080.BIN",
    "modified15": "02_BACK_TO_MODIFIED15/EG162080.BIN",
    "modified13": "03_BACK_TO_MODIFIED13/EG162080.BIN",
    "modified12": "04_BACK_TO_MODIFIED12/EG162080.BIN",
    "stock": "05_STOCK_C380/EG162080.BIN",
}
FORBIDDEN_DIGESTS = {
    "modified14_broken_tmode": "6d970609c18ac64302e82a7e4f4bfba9d8d4b14a606b55bf2cbc56dc37ea754b",
}
RECIPE_SHA = "813af1df75fd8749a6c21d0a007339fc76e308d904480bdf4fed8ecf3f57a0d7"
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
        digest = sha(b)
        need(digest not in FORBIDDEN_DIGESTS.values(), f"Superseded Modified14 binary found in kit: {rel}")
        need(digest == DIGESTS[name], f"Hash mismatch for {rel}")
        need(binascii.crc_hqx(b, 0) == 0, f"CRC failure for {rel}")
        blobs[name] = b

    for bin_file in kit_dir.rglob("*.BIN"):
        need(sha(bin_file.read_bytes()) not in FORBIDDEN_DIGESTS.values(), f"Superseded Modified14 found: {bin_file}")

    recipe_file = kit_dir / "reports/recipe.json"
    need(recipe_file.is_file(), "Missing reports/recipe.json")
    recipe_bytes = recipe_file.read_bytes()
    need(sha(recipe_bytes) == RECIPE_SHA, "Tampered or mismatched reports/recipe.json")
    edits = json.loads(recipe_bytes.decode("utf8"))["candidates"][0]["edits"]
    need(len(edits) == 105, f"Expected 105 patch sites, got {len(edits)}")

    stock = blobs["stock"]
    m15 = blobs["modified15"]
    m16 = blobs["modified16"]

    rebuilt_from_stock = bytearray(stock)
    prev_end = 0
    m600_count = 0
    astro_ui_count = 0

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
        need(m16[off:end] == new_b, f"Modified16 patch mismatch at {addr:#x}")
        rebuilt_from_stock[off:end] = new_b

        if e["group"].startswith("m600_"):
            m600_count += 1
        else:
            astro_ui_count += 1

    need(m600_count == 84, f"Expected 84 m600 sites, got {m600_count}")
    need(astro_ui_count == 21, f"Expected 21 astro UI sites, got {astro_ui_count}")

    # Ensure internal 0x204 property builder & dependency table remain 100% factory Stock
    for stock_preserved_addr, span_len in ((0x101508FD, 1), (0x1015093E, 4), (0x114D3518, 8)):
        off = stock_preserved_addr - BASE
        need(
            m16[off : off + span_len] == stock[off : off + span_len],
            f"0x204 stock ceiling invariant violated at {stock_preserved_addr:#x}",
        )

    # Ensure SD Lossy Playback & Retouch are 100% factory Stock
    for pb_addr, span_len in ((0x102DD088, 0xFC), (0x103C68CE, 0x10)):
        off = pb_addr - BASE
        need(
            m16[off : off + span_len] == stock[off : off + span_len],
            f"SD lossy playback / settings invariant violated at {pb_addr:#x}",
        )

    _apply_crc(rebuilt_from_stock)
    need(bytes(rebuilt_from_stock) == m16, "Rebuilt from Stock diverged from Modified16")

    return {
        "status": "OK",
        "total_files": len(PATHS),
        "total_sites": len(edits),
        "astro_ui_sites": astro_ui_count,
        "m600_sites": m600_count,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("kit_dir", type=Path, nargs="?", default=Path(__file__).resolve().parent)
    args = ap.parse_args()
    res = check_kit(args.kit_dir)
    print(f"PASS: {res}")


if __name__ == "__main__":
    main()

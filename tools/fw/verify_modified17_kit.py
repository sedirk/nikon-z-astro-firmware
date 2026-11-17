"""Independent offline verification of the final Modified17 delivery kit."""
from __future__ import annotations
import argparse
import binascii
import hashlib
import json
from pathlib import Path

DIGESTS = {
    "modified17": "d72daf2d0f0e367d1c4da23ec506cfd3a73f8009713ed8c046298d7b846d3281",
    "modified16": "4cca328ccbac4a025111bcf5fd6d88ca8667eb2da0b543ce3db42cf0d8da91cf",
    "modified15": "0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c",
    "modified13": "3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749",
    "stock": "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c",
}

PATHS = {
    "modified17": "01_TEST_MODIFIED17/EG162080.BIN",
    "modified16": "02_BACK_TO_MODIFIED16/EG162080.BIN",
    "modified15": "03_BACK_TO_MODIFIED15/EG162080.BIN",
    "modified13": "04_BACK_TO_MODIFIED13/EG162080.BIN",
    "stock": "05_STOCK_C380/EG162080.BIN",
}

RECIPE_SHA = "1aab36471145d4d5fdc4c738828166950ef19a9ca6dd93fedae5b1f03504b898"

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
        need(digest == DIGESTS[name], f"Hash mismatch for {rel}: {digest} != {DIGESTS[name]}")
        need(binascii.crc_hqx(b, 0) == 0, f"CRC failure for {rel}")
        blobs[name] = b

    # Verify recipe and audits in audit/
    audit_dir = kit_dir / "audit"
    need(audit_dir.is_dir(), "Missing audit directory")

    recipe_path = audit_dir / "z6-c380-modified17-focus-astro-600s.json"
    need(recipe_path.is_file(), "Missing recipe JSON in kit")
    need(sha(recipe_path.read_bytes()) == RECIPE_SHA, "Recipe JSON hash mismatch")

    native_rep_path = audit_dir / "native_report.json"
    need(native_rep_path.is_file(), "Missing native_report.json")
    nrep = json.loads(native_rep_path.read_text(encoding="utf8"))
    need(nrep.get("ok") is True, "Native report status not ok")

    updater_rep_path = audit_dir / "updater_audit.json"
    need(updater_rep_path.is_file(), "Missing updater_audit.json")
    urep = json.loads(updater_rep_path.read_text(encoding="utf8"))
    need(urep.get("ok") is True, "Updater audit report status not ok")

    # Verify exact bit transformation: Reverting recipe on m17 produces Stock
    recipe = json.loads(recipe_path.read_text(encoding="utf8"))
    rebuilt_stock = bytearray(blobs["modified17"])
    for e in reversed(recipe["edits"]):
        off = int(e["address"], 16) - BASE
        old_b = bytes.fromhex(e["before"])
        rebuilt_stock[off : off + len(old_b)] = old_b
    _apply_crc(rebuilt_stock)
    need(bytes(rebuilt_stock) == blobs["stock"], "Rollback to stock byte check failed!")

    return {
        "status": "PASS",
        "verified_binaries": len(blobs),
        "recipe_sha": RECIPE_SHA,
        "m17_sha": DIGESTS["modified17"],
        "stock_sha": DIGESTS["stock"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kit_dir", type=Path)
    args = parser.parse_args()

    res = check_kit(args.kit_dir)
    print(f"PASS: Modified17 kit verified completely -> {res}")


if __name__ == "__main__":
    main()

"""Verify Nikon Z6 C3.80 Modified20 release kit integrity (sizes, SHA-256, CRC16-HQX)."""
from __future__ import annotations
import argparse
import binascii
import hashlib
import json
from pathlib import Path

DIGESTS = {
    "modified20": "8003fac8111e059d8b64d7800e471524247eab451dc1f84da2b163ed2e255ac1",
    "modified19": "c4629a3700c947846b6c535567beb57055613db1b4120d024b7473cd1e27667a",
    "modified18": "5d404ea3707796c895782ebe75288763a67a238b7cac6cfce6dec71ba04dd157",
    "modified15": "0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c",
    "stock": "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c",
}
PATHS = {
    "modified20": "01_TEST_MODIFIED20/EG162080.BIN",
    "modified19": "02_BACK_TO_MODIFIED19/EG162080.BIN",
    "modified18": "03_BACK_TO_MODIFIED18/EG162080.BIN",
    "modified15": "04_BACK_TO_MODIFIED15/EG162080.BIN",
    "stock": "05_STOCK_C380/EG162080.BIN",
}
SIZE = 33502842


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def need(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


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

    return {
        "status": "PASS",
        "verified_slots": len(blobs),
        "digests": {k: sha(v) for k, v in blobs.items()},
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("kit_dir", type=Path, nargs="?")
    args = ap.parse_args()

    root = Path(__file__).resolve().parents[2]
    kit_dir = (args.kit_dir or (root / "outputs/Z6-C380-modified20-reviewed-2026-11-16")).resolve()
    res = check_kit(kit_dir)
    print(json.dumps(res))


if __name__ == "__main__":
    main()

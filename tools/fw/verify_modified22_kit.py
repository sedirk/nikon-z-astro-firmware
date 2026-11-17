"""Independent offline verification of Modified22 reviewed or stock-only flash kits.

Supports both:
  - 5-slot researcher kit (Modified22 + Modified16/15/13 rollbacks + Stock C3.80)
  - 2-slot clean-clone kit (Modified22 + Stock C3.80 rollback)
"""
from __future__ import annotations
import argparse
import binascii
import hashlib
import json
from pathlib import Path

DIGESTS = {
    "modified22": "c6a23ea40f03d83c6c721e96e8b5af8a8422a7b4ed81d39222392b7635681771",
    "modified16": "4cca328ccbac4a025111bcf5fd6d88ca8667eb2da0b543ce3db42cf0d8da91cf",
    "modified15": "0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c",
    "modified13": "3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749",
    "stock": "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c",
}
PATHS = {
    "modified22": "01_TEST_MODIFIED22/EG162080.BIN",
    "modified16": "02_BACK_TO_MODIFIED16/EG162080.BIN",
    "modified15": "03_BACK_TO_MODIFIED15/EG162080.BIN",
    "modified13": "04_BACK_TO_MODIFIED13/EG162080.BIN",
    "stock": "05_STOCK_C380/EG162080.BIN",
}
ALT_PATHS = {
    "modified22": ("01_TEST_MODIFIED22/EG162080.BIN", "01_MODIFIED22/EG162080.BIN"),
    "stock": ("05_STOCK_C380/EG162080.BIN", "02_STOCK_C380_ROLLBACK/EG162080.BIN"),
}
OPTIONAL_SLOTS = ("modified16", "modified15", "modified13")
SUPERSEDED_DIGESTS = {
    "modified21_wrong_pid0508_autoiso": "e632a9113b4a32944d6f9582dd9e44ad43eeeef1846778143e46626023908609",
    "modified20_wrong_pid0440": "8003fac8111e059d8b64d7800e471524247eab451dc1f84da2b163ed2e255ac1",
    "modified19_wrong_pid0440": "c4629a3700c947846b6c535567beb57055613db1b4120d024b7473cd1e27667a",
    "modified14_broken_tmode": "6d970609c18ac64302e82a7e4f4bfba9d8d4b14a606b55bf2cbc56dc37ea754b",
}
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


def _resolve_required_slot(kit_dir: Path, slot: str) -> Path:
    for rel in ALT_PATHS[slot]:
        p = kit_dir / rel
        if p.is_file():
            return p
    raise AssertionError(f"Missing required {slot} slot (checked {ALT_PATHS[slot]})")


def check_kit(kit_dir: Path) -> dict:
    blobs: dict[str, bytes] = {}
    allowed_digests = set(DIGESTS.values())

    for req_slot in ("modified22", "stock"):
        p = _resolve_required_slot(kit_dir, req_slot)
        b = p.read_bytes()
        need(len(b) == SIZE, f"Wrong size for {p.name}: {len(b)} != {SIZE}")
        digest = sha(b)
        need(digest not in SUPERSEDED_DIGESTS.values(), f"Superseded binary found in kit: {p}")
        need(digest == DIGESTS[req_slot], f"Hash mismatch for {p}: {digest} != {DIGESTS[req_slot]}")
        need(binascii.crc_hqx(b, 0) == 0, f"CRC failure for {p}")
        blobs[req_slot] = b

    present_opt = [s for s in OPTIONAL_SLOTS if (kit_dir / PATHS[s]).is_file()]
    need(
        len(present_opt) in (0, len(OPTIONAL_SLOTS)),
        f"Incomplete optional rollback set: found {present_opt}, expected either none (2-slot) or all 3 (5-slot)",
    )
    for opt_slot in present_opt:
        rel = PATHS[opt_slot]
        p = kit_dir / rel
        b = p.read_bytes()
        need(len(b) == SIZE, f"Wrong size for {rel}: {len(b)} != {SIZE}")
        digest = sha(b)
        need(digest not in SUPERSEDED_DIGESTS.values(), f"Superseded binary found in kit: {rel}")
        need(digest == DIGESTS[opt_slot], f"Hash mismatch for {rel}: {digest} != {DIGESTS[opt_slot]}")
        need(binascii.crc_hqx(b, 0) == 0, f"CRC failure for {rel}")
        blobs[opt_slot] = b

    all_bins = sorted(kit_dir.rglob("*.BIN"))
    need(len(all_bins) == len(blobs), f"Expected {len(blobs)} .BIN files, found {len(all_bins)}")
    for bin_file in all_bins:
        d = sha(bin_file.read_bytes())
        need(d not in SUPERSEDED_DIGESTS.values(), f"Superseded .BIN digest in kit: {bin_file}")
        need(d in allowed_digests, f"Unexpected .BIN digest in kit: {bin_file}")

    manifest_candidates = [
        kit_dir / "audit/modified22-manifest.json",
        Path(__file__).resolve().parents[2] / "patches/z6-c380-modified22-color-space-pid0526-srgb-600s.json",
    ]
    manifest_file = next((m for m in manifest_candidates if m.is_file()), None)
    need(manifest_file is not None, "Missing audit/modified22-manifest.json (and tracked patch recipe)")
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    edits = manifest["edits"]
    need(len(edits) == 104, f"Expected 104 patch sites, got {len(edits)}")

    stock = blobs["stock"]
    m22 = blobs["modified22"]
    rebuilt = bytearray(stock)
    prev_end = 0
    m600_count = 0
    iv_count = 0
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
        need(m22[off:end] == new_b, f"Modified22 patch mismatch at {addr:#x}")
        rebuilt[off:end] = new_b

        grp = e["group"]
        if grp.startswith("m600_"):
            m600_count += 1
        elif "interval" in grp:
            iv_count += 1
        else:
            astro_ui_count += 1

    need(astro_ui_count == 17, f"Expected 17 astro/UI/sRGB sites, got {astro_ui_count}")
    need(iv_count == 3, f"Expected 3 interval timer sites, got {iv_count}")
    need(m600_count == 84, f"Expected 84 m600_v2 sites, got {m600_count}")

    # Verify critical Modified22 root-cause invariants:
    need(
        m22[0x1002D900 - BASE : 0x1002D908 - BASE] == bytes.fromhex("4df6a061ccf24c21"),
        "fn_is_astro_r0 does not read 0xC24CDEA0 (PID 0x0526)",
    )
    need(
        stock[0x1014BB28 - BASE : 0x1014BB2A - BASE] == bytes.fromhex("01d1")
        and m22[0x1014BB28 - BASE : 0x1014BB2A - BASE] == bytes.fromhex("00bf"),
        "0x1014BB28 PID 0x130A sRGB lock missing",
    )
    for auto_iso_addr, span_len in ((0x1040AD00, 4), (0x1014F678, 2)):
        off = auto_iso_addr - BASE
        need(
            m22[off : off + span_len] == stock[off : off + span_len],
            f"Auto ISO Stock invariant violated at {auto_iso_addr:#x}",
        )

    _apply_crc(rebuilt)
    need(bytes(rebuilt) == m22, "Rebuilt from Stock diverged from Modified22")

    return {
        "status": "PASS",
        "verified_slots": len(blobs),
        "kit_mode": "5-slot-researcher" if len(blobs) == 5 else "2-slot-stock-only",
        "total_edits": len(edits),
        "astro_ui_edits": astro_ui_count,
        "interval_edits": iv_count,
        "m600_edits": m600_count,
        "digests": {k: sha(v) for k, v in blobs.items()},
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("kit_dir", type=Path, nargs="?")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    default_dir = (
        here
        if any((here / rel).is_file() for rel in ALT_PATHS["modified22"])
        else (Path(__file__).resolve().parents[2] / "outputs/Z6-C380-modified22-reviewed-2026-11-17")
    )
    kit_dir = (args.kit_dir or default_dir).resolve()
    res = check_kit(kit_dir)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

"""Independent offline verification of Nikon Z6 C3.80 Modified23 flash kits.

SPDX-License-Identifier: GPL-3.0-or-later

Supports:
  - 6-slot researcher kit (Modified23 + Modified22 + Modified16/15/13 rollbacks + Stock C3.80)
  - 3-slot baseline kit (Modified23 + Modified22 rollback + Stock C3.80 rollback)
  - 2-slot clean-clone kit (Modified23 + Stock C3.80 rollback)
"""
from __future__ import annotations
if not __debug__:
    raise RuntimeError("verify_modified23_kit.py must not be executed with Python -O/-OO.")

import argparse
import binascii
import hashlib
import json
from pathlib import Path
import re
DIGESTS = {
    "modified23": "47a5caa9521c4d81e57958626baf9660fefdc489da120840b931525968a11029",
    "modified22": "c6a23ea40f03d83c6c721e96e8b5af8a8422a7b4ed81d39222392b7635681771",
    "modified16": "4cca328ccbac4a025111bcf5fd6d88ca8667eb2da0b543ce3db42cf0d8da91cf",
    "modified15": "0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c",
    "modified13": "3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749",
    "stock": "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c",
}
PATHS = {
    "modified23": "01_TEST_MODIFIED23/EG162080.BIN",
    "modified22": "02_BACK_TO_MODIFIED22/EG162080.BIN",
    "modified16": "03_BACK_TO_MODIFIED16/EG162080.BIN",
    "modified15": "04_BACK_TO_MODIFIED15/EG162080.BIN",
    "modified13": "05_BACK_TO_MODIFIED13/EG162080.BIN",
    "stock": "06_STOCK_C380/EG162080.BIN",
}
ALT_PATHS = {
    "modified23": ("01_TEST_MODIFIED23/EG162080.BIN", "01_MODIFIED23/EG162080.BIN"),
    "stock": (
        "06_STOCK_C380/EG162080.BIN",
        "03_STOCK_C380/EG162080.BIN",
        "02_STOCK_C380_ROLLBACK/EG162080.BIN",
    ),
}
HISTORICAL_SLOTS = ("modified16", "modified15", "modified13")
SUPERSEDED_DIGESTS = {
    "modified21_wrong_pid0508_autoiso": "e632a9113b4a32944d6f9582dd9e44ad43eeeef1846778143e46626023908609",
    "modified20_wrong_pid0440": "8003fac8111e059d8b64d7800e471524247eab451dc1f84da2b163ed2e255ac1",
    "modified19_wrong_pid0440": "c4629a3700c947846b6c535567beb57055613db1b4120d024b7473cd1e27667a",
    "modified14_broken_tmode": "6d970609c18ac64302e82a7e4f4bfba9d8d4b14a606b55bf2cbc56dc37ea754b",
}
TRAMP_A34D0_HEX = (
    "07b5eff30082fff7cdfe012807d082f3008cbde80740a270e27075f098bc"
    "0020a0706978022900d00121e17082f3008cbde8074075f08bbc"
)
BASE = 0x10020000
SIZE = 33502842


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def need(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)

def _apply_crc(buf: bytearray) -> None:
    crc = binascii.crc_hqx(bytes(buf[:-2]), 0)
    buf[-2:] = crc.to_bytes(2, "big")
    need(binascii.crc_hqx(bytes(buf), 0) == 0, "CRC recomputation check failed")


def _resolve_required_slot(kit_dir: Path, slot: str) -> Path:
    for rel in ALT_PATHS[slot]:
        p = kit_dir / rel
        if p.is_file():
            return p
    raise ValueError(f"Missing required {slot} slot (checked {ALT_PATHS[slot]})")


def check_kit(kit_dir: Path) -> dict:
    if not __debug__:
        raise RuntimeError("verify_modified23_kit.py must not be executed with Python -O/-OO.")
    blobs: dict[str, bytes] = {}
    allowed_digests = set(DIGESTS.values())

    for req_slot in ("modified23", "stock"):
        p = _resolve_required_slot(kit_dir, req_slot)
        rel_p = p.relative_to(kit_dir).as_posix()
        b = p.read_bytes()
        need(len(b) == SIZE, f"Wrong size for {rel_p}: {len(b)} != {SIZE}")
        digest = sha(b)
        need(digest not in SUPERSEDED_DIGESTS.values(), f"Superseded binary found in kit: {rel_p}")
        need(digest == DIGESTS[req_slot], f"Hash mismatch for {rel_p}: {digest} != {DIGESTS[req_slot]}")
        need(binascii.crc_hqx(b, 0) == 0, f"CRC failure for {rel_p}")
        blobs[req_slot] = b
    m22_p = kit_dir / PATHS["modified22"]
    if m22_p.is_file():
        b = m22_p.read_bytes()
        need(len(b) == SIZE, f"Wrong size for {PATHS['modified22']}: {len(b)} != {SIZE}")
        digest = sha(b)
        need(digest == DIGESTS["modified22"], f"Hash mismatch for {PATHS['modified22']}: {digest}")
        need(binascii.crc_hqx(b, 0) == 0, f"CRC failure for {PATHS['modified22']}")
        blobs["modified22"] = b

    present_hist = [s for s in HISTORICAL_SLOTS if (kit_dir / PATHS[s]).is_file()]
    need(
        len(present_hist) in (0, len(HISTORICAL_SLOTS)),
        f"Incomplete historical rollback set: found {present_hist}, expected none or all 3",
    )
    if present_hist:
        need("modified22" in blobs, "6-slot researcher kit requires 02_BACK_TO_MODIFIED22/EG162080.BIN")
    for hist_slot in present_hist:
        rel = PATHS[hist_slot]
        p = kit_dir / rel
        b = p.read_bytes()
        need(len(b) == SIZE, f"Wrong size for {rel}: {len(b)} != {SIZE}")
        digest = sha(b)
        need(digest not in SUPERSEDED_DIGESTS.values(), f"Superseded binary found in kit: {rel}")
        need(digest == DIGESTS[hist_slot], f"Hash mismatch for {rel}: {digest} != {DIGESTS[hist_slot]}")
        need(binascii.crc_hqx(b, 0) == 0, f"CRC failure for {rel}")
        blobs[hist_slot] = b

    all_bins = sorted(kit_dir.rglob("*.BIN"))
    need(len(all_bins) == len(blobs), f"Expected {len(blobs)} .BIN files, found {len(all_bins)}")
    for bin_file in all_bins:
        rel_bin = bin_file.relative_to(kit_dir).as_posix()
        d = sha(bin_file.read_bytes())
        need(d not in SUPERSEDED_DIGESTS.values(), f"Superseded .BIN digest in kit: {rel_bin}")
        need(d in allowed_digests, f"Unexpected .BIN digest in kit: {rel_bin}")

    # Verify optional audit JSON files and ensure zero host-path leaks in packaged text files:
    opt_probe = kit_dir / "audit/probe_modified23_native_result.json"
    if opt_probe.is_file():
        prb = json.loads(opt_probe.read_text(encoding="utf-8"))
        need(
            prb.get("status") == "PASS"
            and prb.get("modified23_sha256") == DIGESTS["modified23"]
            and "exception" not in prb,
            "Bundled probe_modified23_native_result.json is not a clean PASS report",
        )
    opt_upd = kit_dir / "audit/updater_audit.json"
    if opt_upd.is_file():
        upd = json.loads(opt_upd.read_text(encoding="utf-8"))
        need(
            upd.get("ok") is True and "exception" not in upd and "error" not in upd,
            "Bundled updater_audit.json is not a clean PASS report",
        )
    host_path_re = re.compile(r"(?:(?<![A-Za-z0-9])[C-Zc-z]:[\\/]|/(?:Users|home)/)")
    for tf in sorted(kit_dir.rglob("*")):
        if tf.is_file() and tf.suffix.lower() not in (".bin", ".bi"):
            rel_tf = tf.relative_to(kit_dir).as_posix()
            if rel_tf == "verify.py":
                continue
            txt = tf.read_text(encoding="utf-8")
            need(not host_path_re.search(txt), f"Host filesystem path leak detected in kit file: {rel_tf}")
    manifest_candidates = [
        kit_dir / "audit/modified23-manifest.json",
        Path(__file__).resolve().parents[2] / "patches/z6-c380-modified23-uncompressed-astro-raw-srgb-600s.json",
    ]
    manifest_file = next((m for m in manifest_candidates if m.is_file()), None)
    need(manifest_file is not None, "Missing audit/modified23-manifest.json (and tracked patch recipe)")
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    edits = manifest["edits"]
    need(len(edits) == 105, f"Expected 105 patch sites, got {len(edits)}")

    stock = blobs["stock"]
    m23 = blobs["modified23"]
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
        need(m23[off:end] == new_b, f"Modified23 patch mismatch at {addr:#x}")
        rebuilt[off:end] = new_b

        grp = e["group"]
        if grp.startswith("m600_"):
            m600_count += 1
        elif "interval" in grp:
            iv_count += 1
        else:
            astro_ui_count += 1

    need(astro_ui_count == 18, f"Expected 18 astro/UI/sRGB/uncomp-pack sites, got {astro_ui_count}")
    need(iv_count == 3, f"Expected 3 interval timer sites, got {iv_count}")
    need(m600_count == 84, f"Expected 84 m600_v2 sites, got {m600_count}")

    # Verify critical Modified22 + Modified23 root-cause invariants:
    need(
        m23[0x1002D900 - BASE : 0x1002D908 - BASE] == bytes.fromhex("4df6a061ccf24c21"),
        "fn_is_astro_r0 does not read 0xC24CDEA0 (PID 0x0526)",
    )
    need(
        stock[0x1014BB28 - BASE : 0x1014BB2A - BASE] == bytes.fromhex("01d1")
        and m23[0x1014BB28 - BASE : 0x1014BB2A - BASE] == bytes.fromhex("00bf"),
        "0x1014BB28 PID 0x130A sRGB lock missing",
    )
    need(
        stock[0x100A34D0 - BASE : 0x100A34D6 - BASE] == bytes.fromhex("a270e270e9e7")
        and m23[0x100A34D0 - BASE : 0x100A34D6 - BASE] == bytes.fromhex("8af744bbe9e7"),
        "0x100A34D0 uncompressed format-3 hardware bit-packer hook missing or corrupted 0x100A34D4",
    )
    need(
        m23[0x1002DB5C - BASE : 0x1002DB94 - BASE] == bytes.fromhex(TRAMP_A34D0_HEX),
        "tramp_a34d0 @ 0x1002DB5C bytes mismatch",
    )
    for auto_iso_addr, span_len in ((0x1040AD00, 4), (0x1014F678, 2)):
        off = auto_iso_addr - BASE
        need(
            m23[off : off + span_len] == stock[off : off + span_len],
            f"Auto ISO Stock invariant violated at {auto_iso_addr:#x}",
        )

    _apply_crc(rebuilt)
    need(bytes(rebuilt) == m23, "Rebuilt from Stock diverged from Modified23")

    if len(blobs) == 6:
        kit_mode = "6-slot-researcher"
    elif len(blobs) == 3:
        kit_mode = "3-slot-with-modified22"
    else:
        kit_mode = "2-slot-stock-only"

    return {
        "status": "PASS",
        "verified_slots": len(blobs),
        "kit_mode": kit_mode,
        "total_edits": len(edits),
        "astro_ui_edits": astro_ui_count,
        "interval_edits": iv_count,
        "m600_edits": m600_count,
        "digests": {k: sha(v) for k, v in blobs.items()},
    }


def main() -> None:
    if not __debug__:
        raise RuntimeError("verify_modified23_kit.py must not be executed with Python -O/-OO.")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("kit_dir", type=Path, nargs="?")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    default_dir = (
        here
        if any((here / rel).is_file() for rel in ALT_PATHS["modified23"])
        else (Path(__file__).resolve().parents[2] / "outputs/Z6-C380-modified23-reviewed-2026-11-18")
    )
    kit_dir = (args.kit_dir or default_dir).resolve()
    res = check_kit(kit_dir)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

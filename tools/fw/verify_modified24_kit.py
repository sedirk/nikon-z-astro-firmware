"""Standalone offline verifier for Nikon Z6 C3.80 Astro Firmware (Modified24) Flash Kits.

SPDX-License-Identifier: GPL-3.0-or-later

Uses Python 3.10+ standard library only so it runs both inside `tools/fw/` and as
the standalone `verify.py` bundled at the root of the release flash kit archive.

Supports:
  - 2-slot standard release kit (`01_MODIFIED24` / `01_TEST_MODIFIED24` + `02_STOCK_C380_ROLLBACK`)
  - 3-slot kit (`01_TEST_MODIFIED24` + `02_BACK_TO_MODIFIED23` + `03_STOCK_C380`)
  - 4-slot kit (`01_TEST_MODIFIED24` + `02_BACK_TO_MODIFIED23` + `03_BACK_TO_MODIFIED22` + `04_STOCK_C380`)
  - 7-slot researcher kit (`01_TEST_MODIFIED24` + M23 + M22 + M16 + M15 + M13 + `07_STOCK_C380`)
"""
from __future__ import annotations

if not __debug__:
    raise RuntimeError("verify_modified24_kit.py must not be executed with Python -O/-OO.")

import argparse
import binascii
import hashlib
import json
from pathlib import Path
import re

DIGESTS = {
    "modified24": "168dcf2ceffb2622915e06f6cf8c9f3d90a5824ea2fbb6451b28657897a89653",
    "modified23": "47a5caa9521c4d81e57958626baf9660fefdc489da120840b931525968a11029",
    "modified22": "c6a23ea40f03d83c6c721e96e8b5af8a8422a7b4ed81d39222392b7635681771",
    "modified16": "4cca328ccbac4a025111bcf5fd6d88ca8667eb2da0b543ce3db42cf0d8da91cf",
    "modified15": "0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c",
    "modified13": "3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749",
    "stock": "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c",
}

EXACT_LAYOUTS: dict[str, dict[str, str]] = {
    "2-slot-release": {
        "modified24": "01_MODIFIED24/EG162080.BIN",
        "stock": "02_STOCK_C380_ROLLBACK/EG162080.BIN",
    },
    "2-slot-stock-only": {
        "modified24": "01_TEST_MODIFIED24/EG162080.BIN",
        "stock": "02_STOCK_C380_ROLLBACK/EG162080.BIN",
    },
    "3-slot-with-modified23": {
        "modified24": "01_TEST_MODIFIED24/EG162080.BIN",
        "modified23": "02_BACK_TO_MODIFIED23/EG162080.BIN",
        "stock": "03_STOCK_C380/EG162080.BIN",
    },
    "4-slot-with-m23-m22": {
        "modified24": "01_TEST_MODIFIED24/EG162080.BIN",
        "modified23": "02_BACK_TO_MODIFIED23/EG162080.BIN",
        "modified22": "03_BACK_TO_MODIFIED22/EG162080.BIN",
        "stock": "04_STOCK_C380/EG162080.BIN",
    },
    "7-slot-researcher": {
        "modified24": "01_TEST_MODIFIED24/EG162080.BIN",
        "modified23": "02_BACK_TO_MODIFIED23/EG162080.BIN",
        "modified22": "03_BACK_TO_MODIFIED22/EG162080.BIN",
        "modified16": "04_BACK_TO_MODIFIED16/EG162080.BIN",
        "modified15": "05_BACK_TO_MODIFIED15/EG162080.BIN",
        "modified13": "06_BACK_TO_MODIFIED13/EG162080.BIN",
        "stock": "07_STOCK_C380/EG162080.BIN",
    },
}

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


def _detect_exact_layout(kit_dir: Path, declared_sums: dict[str, str]) -> tuple[str, dict[str, str]]:
    declared_bins = {p for p in declared_sums if p.upper().endswith(".BIN")}
    for mode_name, slot_map in EXACT_LAYOUTS.items():
        if set(slot_map.values()) == declared_bins:
            return mode_name, slot_map
    raise ValueError(
        f"Unrecognized or incomplete kit slot layout in SHA256SUMS.txt: {sorted(declared_bins)}"
    )


def _repo_recipe_fallback() -> Path | None:
    resolved = Path(__file__).resolve()
    if len(resolved.parents) > 2:
        cand = resolved.parents[2] / "patches/z6-c380-modified24-astro-raw-red-srgb-600s.json"
        if cand.is_file():
            return cand
    return None


def check_kit(kit_dir: Path) -> dict:
    if not __debug__:
        raise RuntimeError("verify_modified24_kit.py must not be executed with Python -O/-OO.")

    sums_path = kit_dir / "SHA256SUMS.txt"
    need(sums_path.is_file(), "Missing SHA256SUMS.txt in kit root")
    sums_entries: dict[str, str] = {}
    for raw_line in sums_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("  ", 1)
        need(len(parts) == 2 and len(parts[0]) == 64, f"Malformed SHA256SUMS line: {line!r}")
        sums_entries[parts[1]] = parts[0]

    kit_mode, slot_map = _detect_exact_layout(kit_dir, sums_entries)

    blobs: dict[str, bytes] = {}
    for slot_key, rel_path in slot_map.items():
        p = kit_dir / rel_path
        need(p.is_file(), f"Missing required slot file: {rel_path}")
        b = p.read_bytes()
        need(len(b) == SIZE, f"Wrong size for {rel_path}: {len(b)} != {SIZE}")
        digest = sha(b)
        need(digest not in SUPERSEDED_DIGESTS.values(), f"Superseded binary found in kit: {rel_path}")
        need(digest == DIGESTS[slot_key], f"SHA-256 mismatch for {rel_path}: {digest} != {DIGESTS[slot_key]}")
        need(sums_entries.get(rel_path) == digest, f"SHA256SUMS mismatch for {rel_path}")
        need(binascii.crc_hqx(b, 0) == 0, f"CRC-16/XMODEM remainder non-zero for {rel_path}")
        blobs[slot_key] = b

    for rel_file, exp_hash in sums_entries.items():
        fp = kit_dir / rel_file
        need(fp.is_file(), f"SHA256SUMS target missing on disk: {rel_file}")
        got_hash = sha(fp.read_bytes())
        need(got_hash == exp_hash, f"SHA256SUMS mismatch for {rel_file}: {got_hash} != {exp_hash}")

    all_bins = sorted(p for p in kit_dir.rglob("*") if p.is_file() and p.suffix.upper() == ".BIN")
    need(len(all_bins) == len(slot_map), f"Expected {len(slot_map)} .BIN files, found {len(all_bins)}")

    opt_probe = kit_dir / "audit/probe_modified24_native_result.json"
    if opt_probe.is_file():
        prb = json.loads(opt_probe.read_text(encoding="utf-8"))
        need(
            prb.get("status") == "PASS"
            and prb.get("measured_candidate_sha256") == DIGESTS["modified24"]
            and "exception" not in prb
            and "error" not in prb,
            "Bundled probe_modified24_native_result.json is not a clean PASS report",
        )
    opt_upd = kit_dir / "audit/modified24_updater_audit.json"
    if not opt_upd.is_file():
        opt_upd = kit_dir / "audit/updater_audit.json"
    if opt_upd.is_file():
        upd = json.loads(opt_upd.read_text(encoding="utf-8"))
        need(
            upd.get("ok") is True
            and upd.get("measured_modified24_sha256") == DIGESTS["modified24"]
            and "exception" not in upd
            and "error" not in upd,
            "Bundled updater audit JSON is not a clean PASS report",
        )
    opt_qemu = kit_dir / "audit/qemu_modified24_result.json"
    if opt_qemu.is_file():
        qres = json.loads(opt_qemu.read_text(encoding="utf-8"))
        need(
            qres.get("ok") is True
            and qres.get("firmware_sha256") == DIGESTS["modified24"]
            and "error" not in qres,
            "Bundled qemu_modified24_result.json is not a clean PASS report",
        )

    host_path_re = re.compile(r"(?:(?<![A-Za-z0-9])[C-Zc-z]:[\\/]|/(?:Users|home)/)")
    for tf in sorted(kit_dir.rglob("*")):
        if tf.is_file() and tf.suffix.lower() not in (".bin", ".bi", ".png"):
            rel_tf = tf.relative_to(kit_dir).as_posix()
            if rel_tf == "verify.py":
                continue
            txt = tf.read_text(encoding="utf-8")
            need(not host_path_re.search(txt), f"Host filesystem path leak detected in kit file: {rel_tf}")

    manifest_file = kit_dir / "audit/modified24-manifest.json"
    if not manifest_file.is_file():
        fallback = _repo_recipe_fallback()
        if fallback is not None:
            manifest_file = fallback
    need(manifest_file.is_file(), "Missing audit/modified24-manifest.json")
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    edits = manifest["edits"]
    need(len(edits) == 112, f"Expected 112 patch sites in Modified24 manifest, got {len(edits)}")

    stock = blobs["stock"]
    m24 = blobs["modified24"]
    m23 = blobs.get("modified23")

    rebuilt_m24 = bytearray(stock)
    rebuilt_m23 = bytearray(stock) if m23 is not None else None
    prev_end = 0
    astro_ui_count = 0
    astro_red_count = 0
    iv_count = 0
    m600_count = 0

    for ed in edits:
        addr = int(ed["address"], 16)
        old_b = bytes.fromhex(ed["before"])
        new_b = bytes.fromhex(ed["after"])
        off = addr - BASE
        end = off + len(old_b)
        need(len(old_b) == len(new_b) > 0, f"Invalid edit span at {addr:#x}")
        need(prev_end <= off and end <= SIZE - 2, f"Unsorted or overlapping span at {addr:#x}")
        prev_end = end

        need(stock[off:end] == old_b, f"Stock anchor mismatch at {addr:#x}")
        need(m24[off:end] == new_b, f"Modified24 patch mismatch at {addr:#x}")
        rebuilt_m24[off:end] = new_b

        grp = ed["group"]
        if grp.startswith("astro_red_"):
            astro_red_count += 1
            if m23 is not None:
                need(m23[off:end] == old_b, f"Astro Red span at {addr:#x} unexpectedly present in Modified23")
        else:
            if grp.startswith("m600_"):
                m600_count += 1
            elif "interval" in grp:
                iv_count += 1
            else:
                astro_ui_count += 1
            if m23 is not None and rebuilt_m23 is not None:
                need(m23[off:end] == new_b, f"Modified23 baseline span mismatch at {addr:#x}")
                rebuilt_m23[off:end] = new_b

    need(astro_ui_count == 18, f"Expected 18 Astro RAW / Color space sites, got {astro_ui_count}")
    need(astro_red_count == 7, f"Expected 7 Astro Red Display sites, got {astro_red_count}")
    need(iv_count == 3, f"Expected 3 Interval Timer sites, got {iv_count}")
    need(m600_count == 84, f"Expected 84 Extended Shutter m600_v2 sites, got {m600_count}")

    _apply_crc(rebuilt_m24)
    need(bytes(rebuilt_m24) == m24, "Rebuilt Modified24 diverged from packaged EG162080.BIN")
    if m23 is not None and rebuilt_m23 is not None:
        _apply_crc(rebuilt_m23)
        need(bytes(rebuilt_m23) == m23, "Rebuilt Modified23 diverged from 02_BACK_TO_MODIFIED23/EG162080.BIN")

    need(
        m24[0x1002D900 - BASE : 0x1002D908 - BASE] == bytes.fromhex("4df6a061ccf24c21"),
        "fn_is_astro_r0 does not read 0xC24CDEA0 (PID 0x0526)",
    )
    need(
        stock[0x1014BB28 - BASE : 0x1014BB2A - BASE] == bytes.fromhex("01d1")
        and m24[0x1014BB28 - BASE : 0x1014BB2A - BASE] == bytes.fromhex("00bf"),
        "0x1014BB28 PID 0x130A sRGB lock missing",
    )
    need(
        stock[0x100A34D0 - BASE : 0x100A34D6 - BASE] == bytes.fromhex("a270e270e9e7")
        and m24[0x100A34D0 - BASE : 0x100A34D6 - BASE] == bytes.fromhex("8af744bbe9e7")
        and m24[0x1002DB5C - BASE : 0x1002DB94 - BASE] == bytes.fromhex(TRAMP_A34D0_HEX),
        "0x100A34D0 uncompressed format-3 hardware bit-packer hook missing",
    )
    need(
        m24[0x1002E1B0 - BASE : 0x1002E1B4 - BASE] == bytes.fromhex("0e461d46"),
        "Astro Red Free Hole B cave header missing at 0x1002E1B0",
    )
    need(
        m24[0x1040E7D8 - BASE : 0x1040E7DA - BASE] == bytes.fromhex("0024")
        and m24[0x1043A1E0 - BASE : 0x1043A1E2 - BASE] == bytes.fromhex("18e0"),
        "Astro Red DISP Light-on-dark lock missing at 0x1040E7D8 / 0x1043A1E0",
    )
    for h_addr, orig_hex in (
        (0x10243422, "0e461d46"),
        (0x102435AE, "6a6800218450"),
        (0x10244154, "c0f81856"),
        (0x104C013C, "bde8ff81"),
    ):
        span_len = len(orig_hex) // 2
        need(
            stock[h_addr - BASE : h_addr - BASE + span_len] == bytes.fromhex(orig_hex)
            and m24[h_addr - BASE : h_addr - BASE + span_len] != bytes.fromhex(orig_hex),
            f"Astro Red hook missing at {h_addr:#x}",
        )
    for auto_iso_addr, span_len in ((0x1040AD00, 4), (0x1014F678, 2)):
        off = auto_iso_addr - BASE
        need(
            m24[off : off + span_len] == stock[off : off + span_len],
            f"Auto ISO Stock invariant violated at {auto_iso_addr:#x}",
        )

    return {
        "status": "PASS",
        "kit_mode": kit_mode,
        "verified_slots": len(blobs),
        "total_edits": len(edits),
        "astro_ui_edits": astro_ui_count,
        "astro_red_edits": astro_red_count,
        "interval_edits": iv_count,
        "m600_edits": m600_count,
        "digests": {k: sha(v) for k, v in blobs.items()},
    }


def _default_kit_dir() -> Path:
    here = Path(__file__).resolve().parent
    if (here / "SHA256SUMS.txt").is_file():
        return here
    resolved = Path(__file__).resolve()
    if len(resolved.parents) > 2:
        return resolved.parents[2] / "outputs/Nikon-Z6-C380-Modified24-Astro-Firmware"
    return here


def main() -> None:
    if not __debug__:
        raise RuntimeError("verify_modified24_kit.py must not be executed with Python -O/-OO.")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("kit_dir", type=Path, nargs="?")
    args = ap.parse_args()

    target = (args.kit_dir or _default_kit_dir()).resolve()
    res = check_kit(target)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

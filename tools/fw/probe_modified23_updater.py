"""Offline updater & flash-scheduler audit for Nikon Z6 C3.80 Modified23 firmware.

SPDX-License-Identifier: GPL-3.0-or-later

Works both on a full research checkout and on a clean open-source clone supplied
only with official `Z_6_0380.bin` (synthesizing historical M20/M21/M22 and M23 in
memory when prebuilt `.BIN`/`.bi` files are not on disk).
"""
from __future__ import annotations
if not __debug__:
    raise RuntimeError(
        "probe_modified23_updater.py must not be executed with Python -O/-OO "
        "(imported probe helpers rely on debug assertions)."
    )

import argparse
import binascii
import gc
import json
from pathlib import Path
import re
import sys
THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from prepare_modified22_lab import (  # noqa: E402
    M20_SHA,
    M21_SHA,
    STOCK_SHA,
    _apply_spans,
    collect_m22_edits,
    update_crc,
)
from prepare_modified23_lab import collect_m23_edits  # noqa: E402
import probe_eg_update_route as eg  # noqa: E402
from probe_preflash_review import AuditRig, schedule  # noqa: E402
from probe_raw_candidates import BASE, ROOT, sha  # noqa: E402
from z6_astro_ui_color_space_v2 import (  # noqa: E402
    build_all_m20_astro_ui_spans,
    build_all_m21_astro_ui_spans,
)
from z6_c380_container import load_stock_eg_module  # noqa: E402
from z6_interval_post_exposure import build_all_m20_interval_spans  # noqa: E402
from z6_m600_v2 import build_all_m600_v2_spans  # noqa: E402

MODIFIED22_SHA = "c6a23ea40f03d83c6c721e96e8b5af8a8422a7b4ed81d39222392b7635681771"
MODIFIED23_SHA = "47a5caa9521c4d81e57958626baf9660fefdc489da120840b931525968a11029"

EXPECTED_HASHES = {
    "stock": STOCK_SHA,
    "modified20": M20_SHA,
    "modified21": M21_SHA,
    "modified22": MODIFIED22_SHA,
    "modified23": MODIFIED23_SHA,
}

def require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def _sanitize_error_text(msg: str) -> str:
    cleaned = re.sub(r"(?<![A-Za-z0-9])[C-Zc-z]:[\\/][^\s\"']*", "<redacted-path>", msg)
    cleaned = re.sub(r"/(?:Users|home)/[^\s\"']*", "<redacted-path>", cleaned)
    return cleaned[:240]


def _validate_m23_binary(data: bytes) -> dict[str, str | int]:
    require(len(data) == 33502842, f"Unexpected Modified23 size: {len(data)}")
    digest = sha(data)
    require(digest == MODIFIED23_SHA, "Modified23 SHA-256 mismatch")
    require(binascii.crc_hqx(data, 0) == 0, "Modified23 CRC-16/XMODEM remainder non-zero")
    crc_hex = f"0x{data[-2:].hex()}"
    require(crc_hex == "0xc083", f"Unexpected Modified23 CRC-16 trailer: {crc_hex}")
    require(
        data[0x100A34D0 - BASE : 0x100A34D6 - BASE] == bytes.fromhex("8af744bbe9e7"),
        "Binary missing 0x100A34D0 uncompressed pack hook or corrupted 0x100A34D4",
    )
    return {
        "sha256": digest,
        "crc16_hqx": crc_hex,
        "size_bytes": len(data),
    }


def _apply_edit_dicts(stock: bytes, edits: list[dict]) -> bytes:
    buf = bytearray(stock)
    for ed in edits:
        off = int(ed["address"], 16) - BASE
        after = bytes.fromhex(ed["after"])
        buf[off : off + len(after)] = after
    update_crc(buf)
    return bytes(buf)


def _load_or_build_blobs(stock_arg: Path | None, candidate_arg: Path | None) -> dict[str, bytes]:
    stock = load_stock_eg_module(stock_arg, ROOT)
    require(sha(stock) == STOCK_SHA, "Stock EG SHA-256 mismatch")
    m600_spans = build_all_m600_v2_spans(stock)
    iv20_spans, _ = build_all_m20_interval_spans(stock)

    m20_path = ROOT / "outputs/Z6-C380-modified20-reviewed-2026-11-16/01_TEST_MODIFIED20/EG162080.BIN"
    if m20_path.is_file():
        m20 = m20_path.read_bytes()
    else:
        m20_ui, _ = build_all_m20_astro_ui_spans(stock)
        m20 = _apply_spans(stock, m20_ui + iv20_spans + m600_spans)

    m21_path = ROOT / "outputs/Z6-C380-modified21-reviewed-2026-11-16/01_TEST_MODIFIED21/EG162080.BIN"
    if m21_path.is_file():
        m21 = m21_path.read_bytes()
    else:
        m21_ui, _ = build_all_m21_astro_ui_spans(stock)
        m21 = _apply_spans(stock, m21_ui + iv20_spans + m600_spans)

    m22_path = ROOT / "outputs/Z6-C380-modified22-reviewed-2026-11-17/01_TEST_MODIFIED22/EG162080.BIN"
    if m22_path.is_file():
        m22 = m22_path.read_bytes()
    else:
        edits22, _ = collect_m22_edits(stock)
        m22 = _apply_edit_dicts(stock, edits22)

    default_cand = ROOT / "analysis/modified23-preflash-2026-11-18/lab-build/modified23-candidate.bi"
    if candidate_arg is not None:
        m23 = candidate_arg.resolve().read_bytes()
    elif default_cand.is_file():
        m23 = default_cand.read_bytes()
    else:
        edits23, _ = collect_m23_edits(stock)
        m23 = _apply_edit_dicts(stock, edits23)

    blobs = {
        "stock": stock,
        "modified20": m20,
        "modified21": m21,
        "modified22": m22,
        "modified23": m23,
    }
    for name, expected in EXPECTED_HASHES.items():
        require(sha(blobs[name]) == expected, f"Hash mismatch for {name}")
    return blobs


def main() -> None:
    if not __debug__:
        raise RuntimeError("probe_modified23_updater.py must not be executed with Python -O/-OO.")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--stock",
        type=Path,
        default=None,
        help="Path to official Z_6_0380.bin or decoded eg1620_038000.bi",
    )
    ap.add_argument(
        "--candidate",
        type=Path,
        default=None,
        help="Optional path to built Modified23 .bi/.BIN",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified23-preflash-2026-11-18/updater-audit",
    )
    args = ap.parse_args()
    out_target = args.output.resolve()
    if out_target.suffix.lower() == ".json":
        out_file = out_target
        out_file.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_target.mkdir(parents=True, exist_ok=True)
        out_file = out_target / "updater_audit.json"

    blobs = _load_or_build_blobs(args.stock, args.candidate)
    measured_m23 = _validate_m23_binary(blobs["modified23"])

    m22_rejected = False
    try:
        _validate_m23_binary(blobs["modified22"])
    except ValueError:
        m22_rejected = True
    require(m22_rejected, "Modified22 binary was not rejected by Modified23 validator")

    report: dict = {
        "ok": False,
        "scope": "Offline updater & flash-scheduler audit for Nikon Z6 C3.80 Modified23.",
        "measured_modified23_sha256": measured_m23["sha256"],
        "measured_modified23_crc16_hqx": measured_m23["crc16_hqx"],
        "measured_modified23_size_bytes": measured_m23["size_bytes"],
        "negative_m22_binary_rejected": m22_rejected,
        "file_checks": [],
        "scheduler": [],
        "physical_flash": False,
        "model": "OS/file and low-level flash adapters; native validation and scheduler code.",
    }
    try:
        for rom, target in (
            ("modified22", "modified23"),
            ("stock", "modified23"),
            ("modified21", "modified23"),
            ("modified23", "modified22"),
            ("modified23", "stock"),
        ):
            label = f"{rom}_to_{target}"
            rig = AuditRig(blobs[rom])
            row = eg.run(rig, label, blobs[target], "EG162080.BIN")
            require(
                row["discovery_return"] == 0
                and row["integrity_return"] == 0
                and row["component_precheck_return"] == 0,
                f"Updater validation failed on {label}",
            )
            require(
                row["loaded_buffer_sha256"] == EXPECTED_HASHES[target],
                f"Loaded buffer SHA-256 mismatch on {label}",
            )
            report["file_checks"].append({"running_rom": rom, "target": target, **row})
            del rig
            gc.collect()

        bad = bytearray(blobs["modified23"])
        bad[0x834D0] ^= 1
        for label, data, name in (
            ("bad_crc", bytes(bad), "EG162080.BIN"),
            ("wrong_filename", blobs["modified23"], "EG172080.BIN"),
        ):
            rig = AuditRig(blobs["modified22"])
            row = eg.run(rig, label, data, name)
            if label == "bad_crc":
                require(
                    row["discovery_return"] == 0 and row["integrity_return"] == 3,
                    "Corrupted CRC image was not rejected with integrity_return == 3",
                )
            else:
                require(row["discovery_return"] != 0, "Wrong filename was not rejected by discovery")
            report["file_checks"].append({"expected_rejection": True, **row})
            del rig
            gc.collect()

        for rom, target, failure in (
            ("modified22", "modified23", None),
            ("stock", "modified23", None),
            ("modified23", "modified22", None),
            ("modified23", "stock", None),
            ("modified22", "modified23", "erase"),
        ):
            rig = AuditRig(blobs[rom])
            row = schedule(rig, f"{rom}_to_{target}", blobs[target], failure)
            require(
                row.get("prefix_preserved") is True and row.get("tail_canary_preserved") is True,
                f"Flash region boundary canary violated in {rom}_to_{target}",
            )
            if failure is None:
                require(
                    row.get("erase_service_calls") == 330 and row.get("program_service_calls") == 330,
                    f"Unexpected sector erase/program counts in {rom}_to_{target}",
                )
            else:
                require(
                    row.get("program_service_calls") == 0,
                    "Erase failure injection did not abort before sector programming",
                )
            report["scheduler"].append(row)
            del rig
            gc.collect()

        report["ok"] = True
    except Exception as exc:
        report["ok"] = False
        report["error"] = {
            "type": type(exc).__name__,
            "message": _sanitize_error_text(str(exc)),
        }
        raise
    finally:
        txt = json.dumps(report, indent=2) + "\n"
        out_file.write_bytes(txt.encode("utf-8"))
    print(
        f"MODIFIED23 UPDATER AUDIT OK: {len(report['file_checks'])} file checks, "
        f"{len(report['scheduler'])} scheduler passes."
    )

if __name__ == "__main__":
    main()

"""Offline camera firmware updater & flash-scheduler audit for Nikon Z6 C3.80 Modified24.

SPDX-License-Identifier: GPL-3.0-or-later

Works both on a full research checkout and on a clean open-source clone supplied
only with official `Z_6_0380.bin` (synthesizing Modified22, Modified23, and
Modified24 in memory when prebuilt `.BIN`/`.bi` files are not present on disk).
"""
from __future__ import annotations

if not __debug__:
    raise RuntimeError(
        "probe_modified24_updater.py must not be executed with Python -O/-OO "
        "(imported probe helpers rely on debug assertions)."
    )

import argparse
import gc
import json
from pathlib import Path
import re
import sys

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from prepare_modified22_lab import STOCK_SHA, collect_m22_edits, update_crc  # noqa: E402
from prepare_modified23_lab import M22_SHA  # noqa: E402
from prepare_modified24_lab import DEFAULT_LAB_OUT, M23_SHA, M24_SHA, collect_m24_edits  # noqa: E402
import probe_eg_update_route as eg  # noqa: E402
from probe_modified24_native import validate_m24_binary  # noqa: E402
from probe_preflash_review import AuditRig, schedule  # noqa: E402
from probe_raw_candidates import BASE, ROOT, sha  # noqa: E402
from z6_c380_container import load_stock_eg_module  # noqa: E402


def require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def _sanitize_error_text(msg: str) -> str:
    cleaned = re.sub(r"(?<![A-Za-z0-9])[C-Zc-z]:[\\/][^\s\"']*", "<redacted-path>", msg)
    cleaned = re.sub(r"/(?:Users|home)/[^\s\"']*", "<redacted-path>", cleaned)
    return cleaned[:240]


def _apply_edit_dicts(stock: bytes, edits: list[dict]) -> bytes:
    buf = bytearray(stock)
    for ed in edits:
        off = int(ed["address"], 16) - BASE
        after = bytes.fromhex(ed["after"])
        buf[off : off + len(after)] = after
    update_crc(buf)
    return bytes(buf)


def _load_or_build_blobs(
    stock_arg: Path | None, candidate_arg: Path | None
) -> tuple[dict[str, bytes], str]:
    stock = load_stock_eg_module(stock_arg, ROOT)
    require(sha(stock) == STOCK_SHA, "Stock EG SHA-256 mismatch")

    m22_path = ROOT / "outputs/Z6-C380-modified22-reviewed-2026-11-17/01_TEST_MODIFIED22/EG162080.BIN"
    if m22_path.is_file():
        m22 = m22_path.read_bytes()
    else:
        edits22, _ = collect_m22_edits(stock)
        m22 = _apply_edit_dicts(stock, edits22)
    require(sha(m22) == M22_SHA, "Modified22 SHA-256 mismatch")

    m23_built, _, m24_edits, _, _ = collect_m24_edits(stock)
    m23_path = ROOT / "outputs/Nikon-Z6-C380-Modified23-Astro-Firmware/01_MODIFIED23/EG162080.BIN"
    m23 = m23_path.read_bytes() if m23_path.is_file() else m23_built
    require(sha(m23) == M23_SHA, "Modified23 SHA-256 mismatch")

    expected_m24 = _apply_edit_dicts(stock, m24_edits)
    expected_m24_sha = sha(expected_m24)
    require(expected_m24_sha == M24_SHA, f"Modified24 synthesis SHA mismatch: {expected_m24_sha}")

    default_cand = DEFAULT_LAB_OUT / "modified24-candidate.bi"
    if candidate_arg is not None:
        cand_p = candidate_arg.resolve()
        if not cand_p.is_file():
            raise FileNotFoundError(f"Explicit --candidate file does not exist: {cand_p.name}")
        m24 = cand_p.read_bytes()
    elif default_cand.is_file():
        m24 = default_cand.read_bytes()
    else:
        m24 = expected_m24
    require(sha(m24) == expected_m24_sha, "Modified24 candidate SHA-256 mismatch")

    blobs = {
        "stock": stock,
        "modified22": m22,
        "modified23": m23,
        "modified24": m24,
    }
    return blobs, expected_m24_sha


def main() -> None:
    if not __debug__:
        raise RuntimeError("probe_modified24_updater.py must not be executed with Python -O/-OO.")
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
        help="Optional path to built Modified24 .bi/.BIN",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified24-release-2026-11-21/updater-audit",
    )
    args = ap.parse_args()
    out_target = args.output.resolve()
    if out_target.suffix.lower() == ".json":
        out_file = out_target
        out_file.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_target.mkdir(parents=True, exist_ok=True)
        out_file = out_target / "modified24_updater_audit.json"

    blobs, expected_m24_sha = _load_or_build_blobs(args.stock, args.candidate)
    measured_m24 = validate_m24_binary(blobs["modified24"], expected_m24_sha)

    expected_hashes = {
        "stock": STOCK_SHA,
        "modified22": M22_SHA,
        "modified23": M23_SHA,
        "modified24": expected_m24_sha,
    }

    m23_rejected = False
    try:
        validate_m24_binary(blobs["modified23"], expected_m24_sha)
    except ValueError:
        m23_rejected = True
    require(m23_rejected, "Modified23 binary was not rejected by Modified24 validator")

    stock_rejected = False
    try:
        validate_m24_binary(blobs["stock"], expected_m24_sha)
    except ValueError:
        stock_rejected = True
    require(stock_rejected, "Stock binary was not rejected by Modified24 validator")

    report: dict = {
        "ok": False,
        "scope": "Offline updater & flash-scheduler audit for Nikon Z6 C3.80 Modified24.",
        "measured_modified24_sha256": measured_m24["sha256"],
        "measured_modified24_crc16_hqx": measured_m24["crc16_hqx"],
        "measured_modified24_size_bytes": measured_m24["size_bytes"],
        "base_modified23_sha256": M23_SHA,
        "negative_m23_binary_rejected": m23_rejected,
        "negative_stock_binary_rejected": stock_rejected,
        "file_checks": [],
        "scheduler": [],
        "physical_flash": False,
        "model": "OS/file and low-level flash adapters; native validation and scheduler code.",
    }
    try:
        for rom, target in (
            ("stock", "modified24"),
            ("modified23", "modified24"),
            ("modified22", "modified24"),
            ("modified24", "modified23"),
            ("modified24", "stock"),
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
                row["loaded_buffer_sha256"] == expected_hashes[target],
                f"Loaded buffer SHA-256 mismatch on {label}",
            )
            report["file_checks"].append({"running_rom": rom, "target": target, **row})
            del rig
            gc.collect()

        bad = bytearray(blobs["modified24"])
        bad[0x24341E] ^= 1
        for label, data, name in (
            ("bad_crc", bytes(bad), "EG162080.BIN"),
            ("wrong_filename", blobs["modified24"], "EG172080.BIN"),
        ):
            rig = AuditRig(blobs["stock"])
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
            ("stock", "modified24", None),
            ("modified23", "modified24", None),
            ("modified24", "modified23", None),
            ("modified24", "stock", None),
            ("stock", "modified24", "erase"),
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
        f"MODIFIED24 UPDATER AUDIT OK: {len(report['file_checks'])} file checks, "
        f"{len(report['scheduler'])} scheduler passes."
    )


if __name__ == "__main__":
    main()

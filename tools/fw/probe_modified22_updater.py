"""Offline updater & flash-scheduler audit for Nikon Z6 C3.80 Modified22.

Works both on a full research checkout and on a clean open-source clone supplied
only with official `Z_6_0380.bin` (synthesizing historical M20/M21 and M22 in memory
when prebuilt `.BIN`/`.bi` files are not on disk).
"""
from __future__ import annotations
import argparse
import gc
import json
from pathlib import Path
import sys
import traceback

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from prepare_modified22_lab import (
    M20_SHA,
    M21_SHA,
    STOCK_SHA,
    _apply_spans,
    collect_m22_edits,
    update_crc,
)
import probe_eg_update_route as eg
from probe_preflash_review import AuditRig, schedule
from probe_raw_candidates import BASE, ROOT, sha
from z6_astro_ui_color_space_v2 import (
    build_all_m20_astro_ui_spans,
    build_all_m21_astro_ui_spans,
)
from z6_c380_container import load_stock_eg_module
from z6_interval_post_exposure import build_all_m20_interval_spans
from z6_m600_v2 import build_all_m600_v2_spans

MODIFIED22_SHA = "c6a23ea40f03d83c6c721e96e8b5af8a8422a7b4ed81d39222392b7635681771"

EXPECTED_HASHES = {
    "stock": STOCK_SHA,
    "modified20": M20_SHA,
    "modified21": M21_SHA,
    "modified22": MODIFIED22_SHA,
}


def _load_or_build_blobs(stock_arg: Path | None, candidate_arg: Path | None) -> dict[str, bytes]:
    stock = load_stock_eg_module(stock_arg, ROOT)
    assert sha(stock) == STOCK_SHA, "Stock EG SHA-256 mismatch"

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

    default_cand = ROOT / "analysis/modified22-preflash-2026-11-17/lab-build/modified22-candidate.bi"
    if candidate_arg is not None:
        m22 = candidate_arg.resolve().read_bytes()
    elif default_cand.is_file():
        m22 = default_cand.read_bytes()
    else:
        edits, _ = collect_m22_edits(stock)
        buf = bytearray(stock)
        for ed in edits:
            off = int(ed["address"], 16) - BASE
            after = bytes.fromhex(ed["after"])
            buf[off : off + len(after)] = after
        update_crc(buf)
        m22 = bytes(buf)

    blobs = {
        "stock": stock,
        "modified20": m20,
        "modified21": m21,
        "modified22": m22,
    }
    for name, expected in EXPECTED_HASHES.items():
        assert sha(blobs[name]) == expected, f"Hash mismatch for {name}"
    return blobs


def main() -> None:
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
        help="Optional path to built Modified22 .bi/.BIN",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified22-preflash-2026-11-17/updater-audit",
    )
    args = ap.parse_args()
    out_dir = args.output.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    blobs = _load_or_build_blobs(args.stock, args.candidate)

    report = {
        "ok": False,
        "scope": "Offline updater & flash-scheduler audit for Nikon Z6 C3.80 Modified22.",
        "file_checks": [],
        "scheduler": [],
        "physical_flash": False,
        "model": "OS/file and low-level flash adapters; native validation and scheduler code.",
    }
    try:
        for rom, target in (
            ("modified21", "modified22"),
            ("modified20", "modified22"),
            ("stock", "modified22"),
            ("modified22", "modified21"),
            ("modified22", "stock"),
        ):
            label = f"{rom}_to_{target}"
            rig = AuditRig(blobs[rom])
            row = eg.run(rig, label, blobs[target], "EG162080.BIN")
            assert row["discovery_return"] == row["integrity_return"] == row["component_precheck_return"] == 0
            assert row["loaded_buffer_sha256"] == EXPECTED_HASHES[target]
            report["file_checks"].append({"running_rom": rom, "target": target, **row})
            del rig
            gc.collect()

        bad = bytearray(blobs["modified22"])
        bad[0x8E3A6] ^= 1
        for label, data, name in (
            ("bad_crc", bytes(bad), "EG162080.BIN"),
            ("wrong_filename", blobs["modified22"], "EG172080.BIN"),
        ):
            rig = AuditRig(blobs["modified21"])
            row = eg.run(rig, label, data, name)
            if label == "bad_crc":
                assert row["discovery_return"] == 0 and row["integrity_return"] == 3
            else:
                assert row["discovery_return"] != 0
            report["file_checks"].append({"expected_rejection": True, **row})
            del rig
            gc.collect()

        for rom, target, failure in (
            ("modified21", "modified22", None),
            ("modified20", "modified22", None),
            ("modified22", "stock", None),
            ("modified21", "modified22", "erase"),
        ):
            rig = AuditRig(blobs[rom])
            row = schedule(rig, f"{rom}_to_{target}", blobs[target], failure)
            report["scheduler"].append(row)
            del rig
            gc.collect()

        report["ok"] = True
    except Exception:
        report["exception"] = traceback.format_exc()
        raise
    finally:
        txt = json.dumps(report, indent=2)
        (out_dir / "updater_audit.json").write_text(txt, encoding="utf-8")
    print(
        f"MODIFIED22 UPDATER AUDIT OK: {len(report['file_checks'])} file checks, "
        f"{len(report['scheduler'])} scheduler passes."
    )


if __name__ == "__main__":
    main()

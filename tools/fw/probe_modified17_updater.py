"""Native Nikon Z6 C3.80 firmware updater and rollback flash scheduler check for Modified17."""
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

import probe_eg_update_route as eg
from probe_preflash_review import AuditRig, schedule
from probe_raw_candidates import ROOT, sha

FILES = {
    "stock": (
        "firmware/decoded/eg1620_038000.bi",
        "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c",
    ),
    "modified15": (
        "outputs/Z6-C380-modified15-reviewed-2026-11-15/01_TEST_MODIFIED15/EG162080.BIN",
        "0f5ea787e02d982625ae0dbca47e389a4b368893ac485285081d8d1246f7be2c",
    ),
    "modified16": (
        "outputs/Z6-C380-modified16-reviewed-2026-11-15/01_TEST_MODIFIED16/EG162080.BIN",
        "4cca328ccbac4a025111bcf5fd6d88ca8667eb2da0b543ce3db42cf0d8da91cf",
    ),
    "modified17": (
        "analysis/modified17-preflash-2026-11-15/lab-build/modified17-candidate.bi",
        "d72daf2d0f0e367d1c4da23ec506cfd3a73f8009713ed8c046298d7b846d3281",
    ),

}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified17-preflash-2026-11-15/updater-audit",
    )
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    blobs = {n: (ROOT / f).read_bytes() for n, (f, _) in FILES.items()}
    for n, (_, h) in FILES.items():
        assert sha(blobs[n]) == h, f"Hash mismatch for {n}"

    report = {
        "ok": False,
        "scope": __doc__,
        "file_checks": [],
        "scheduler": [],
        "physical_flash": False,
        "model": "OS/file and low-level flash adapters; native validation and scheduler code.",
    }
    try:
        # 1. Critical update & rollback transitions
        for rom, target in (
            ("modified16", "modified17"),
            ("stock", "modified17"),
            ("modified17", "modified16"),
            ("modified17", "stock"),
        ):
            label = f"{rom}_to_{target}"
            rig = AuditRig(blobs[rom])
            row = eg.run(rig, label, blobs[target], "EG162080.BIN")
            assert row["discovery_return"] == row["integrity_return"] == row["component_precheck_return"] == 0
            assert row["loaded_buffer_sha256"] == FILES[target][1]
            report["file_checks"].append({"running_rom": rom, "target": target, **row})
            del rig
            gc.collect()

        # 2. Negative checks (bad crc, wrong filename)
        bad = bytearray(blobs["modified17"])
        bad[0x8E3A6] ^= 1
        for label, data, name in (
            ("bad_crc", bytes(bad), "EG162080.BIN"),
            ("wrong_filename", blobs["modified17"], "EG172080.BIN"),
        ):
            rig = AuditRig(blobs["modified16"])
            row = eg.run(rig, label, data, name)
            if label == "bad_crc":
                assert row["discovery_return"] == 0 and row["integrity_return"] == 3
            else:
                assert row["discovery_return"] != 0
            report["file_checks"].append({"expected_rejection": True, **row})
            del rig
            gc.collect()

        # 3. Flash scheduler checks & fault injection
        for rom, target, failure in (
            ("modified16", "modified17", None),
            ("modified17", "modified16", None),
            ("modified17", "stock", None),
            ("modified16", "modified17", "erase"),
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
        (args.output / "result.json").write_text(txt, encoding="utf8")
        (args.output / "updater_audit.json").write_text(txt, encoding="utf8")
    print(f"Modified17 updater check ok: {len(report['file_checks'])} file checks, {len(report['scheduler'])} scheduler passes.")


if __name__ == "__main__":
    main()

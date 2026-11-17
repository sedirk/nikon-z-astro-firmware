"""Native Nikon Z6 C3.80 firmware updater and rollback flash scheduler check for Modified14."""
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
    "modified12": (
        "outputs/Z6-C380-modified12-reviewed-2026-11-14/01_TEST_MODIFIED12/EG162080.BIN",
        "9734012be0e063fa8f2ccbf77c2dd5a63a76be2f45887aa6b806b97b441cb67c",
    ),
    "modified13": (
        "outputs/Z6-C380-modified13-reviewed-2026-11-14/01_TEST_MODIFIED13/EG162080.BIN",
        "3602bcb0fbe1f9cac6722f9a229afafc0cb063c7bd660778f9ccc31089198749",
    ),
    "modified14": (
        "analysis/modified14-preflash-2026-11-14/lab-build/modified14-candidate.bi",
        "6d970609c18ac64302e82a7e4f4bfba9d8d4b14a606b55bf2cbc56dc37ea754b",
    ),
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified14-preflash-2026-11-14/updater-audit",
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
        pairs = (
            ("modified13", "modified14"),
            ("modified12", "modified14"),
            ("stock", "modified14"),
            ("modified14", "modified13"),
            ("modified14", "modified12"),
            ("modified14", "stock"),
        )
        for rom, target in pairs:
            label = f"{rom}_to_{target}"
            rig = AuditRig(blobs[rom])
            row = eg.run(rig, label, blobs[target], "EG162080.BIN")
            assert row["discovery_return"] == row["integrity_return"] == row["component_precheck_return"] == 0
            assert row["loaded_buffer_sha256"] == FILES[target][1]
            report["file_checks"].append({"running_rom": rom, "target": target, **row})
            del rig
            gc.collect()

        bad = bytearray(blobs["modified14"])
        bad[0x8E3A6] ^= 1
        for label, data, name, size in (
            ("bad_crc", bytes(bad), "EG162080.BIN", None),
            ("wrong_model", blobs["modified14"], "EG172080.BIN", None),
            ("oversize", blobs["modified14"], "EG162080.BIN", 0x2940001),
        ):
            rig = AuditRig(blobs["modified13"])
            row = eg.run(rig, label, data, name, reported_size=size)
            if label == "bad_crc":
                assert row["discovery_return"] == 0 and row["integrity_return"] == 3
            else:
                assert row["discovery_return"] != 0
            report["file_checks"].append({"expected_rejection": True, **row})
            del rig
            gc.collect()

        for rom, target, failure in (
            ("modified13", "modified14", None),
            ("modified14", "modified13", None),
            ("modified14", "modified12", None),
            ("modified14", "stock", None),
            ("modified13", "modified14", "erase"),
            ("modified14", "modified13", "readback"),
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
    print(f"Modified14 updater check ok: {len(report['file_checks'])} file checks, {len(report['scheduler'])} scheduler passes.")


if __name__ == "__main__":
    main()

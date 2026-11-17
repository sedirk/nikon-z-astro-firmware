"""Native Nikon updater & flash-scheduler audit for Z6 C3.80 Modified20."""
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
    "modified19": (
        "outputs/Z6-C380-modified19-reviewed-2026-11-16/01_TEST_MODIFIED19/EG162080.BIN",
        "c4629a3700c947846b6c535567beb57055613db1b4120d024b7473cd1e27667a",
    ),
    "modified20": (
        "analysis/modified20-preflash-2026-11-16/lab-build/modified20-candidate.bi",
        "8003fac8111e059d8b64d7800e471524247eab451dc1f84da2b163ed2e255ac1",
    ),
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified20-preflash-2026-11-16/updater-audit",
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
        for rom, target in (
            ("modified19", "modified20"),
            ("stock", "modified20"),
            ("modified20", "modified19"),
            ("modified20", "stock"),
        ):
            label = f"{rom}_to_{target}"
            rig = AuditRig(blobs[rom])
            row = eg.run(rig, label, blobs[target], "EG162080.BIN")
            assert row["discovery_return"] == row["integrity_return"] == row["component_precheck_return"] == 0
            assert row["loaded_buffer_sha256"] == FILES[target][1]
            report["file_checks"].append({"running_rom": rom, "target": target, **row})
            del rig
            gc.collect()

        bad = bytearray(blobs["modified20"])
        bad[0x8E3A6] ^= 1
        for label, data, name in (
            ("bad_crc", bytes(bad), "EG162080.BIN"),
            ("wrong_filename", blobs["modified20"], "EG172080.BIN"),
        ):
            rig = AuditRig(blobs["modified19"])
            row = eg.run(rig, label, data, name)
            if label == "bad_crc":
                assert row["discovery_return"] == 0 and row["integrity_return"] == 3
            else:
                assert row["discovery_return"] != 0
            report["file_checks"].append({"expected_rejection": True, **row})
            del rig
            gc.collect()

        for rom, target, failure in (
            ("modified19", "modified20", None),
            ("modified20", "modified19", None),
            ("modified20", "stock", None),
            ("modified19", "modified20", "erase"),
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
        (args.output / "updater_audit.json").write_text(txt, encoding="utf-8")
    print(
        f"MODIFIED20 UPDATER AUDIT OK: {len(report['file_checks'])} file checks, "
        f"{len(report['scheduler'])} scheduler passes."
    )


if __name__ == "__main__":
    main()

"""Native Nikon updater discovery, CRC integrity, component precheck, and flash scheduler verification for Modified19."""
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
    "modified18": (
        "outputs/Z6-C380-modified18-reviewed-2026-11-15/01_TEST_MODIFIED18/EG162080.BIN",
        "5d404ea3707796c895782ebe75288763a67a238b7cac6cfce6dec71ba04dd157",
    ),
    "modified19": (
        "analysis/modified19-preflash-2026-11-16/lab-build/modified19-candidate.bi",
        "c4629a3700c947846b6c535567beb57055613db1b4120d024b7473cd1e27667a",
    ),
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis/modified19-preflash-2026-11-16/updater-audit",
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
            ("modified18", "modified19"),
            ("stock", "modified19"),
            ("modified19", "modified18"),
            ("modified19", "stock"),
        ):
            label = f"{rom}_to_{target}"
            rig = AuditRig(blobs[rom])
            row = eg.run(rig, label, blobs[target], "EG162080.BIN")
            assert row["discovery_return"] == row["integrity_return"] == row["component_precheck_return"] == 0
            assert row["loaded_buffer_sha256"] == FILES[target][1]
            report["file_checks"].append({"running_rom": rom, "target": target, **row})
            del rig
            gc.collect()

        bad = bytearray(blobs["modified19"])
        bad[0x8E3A6] ^= 1
        for label, data, name in (
            ("bad_crc", bytes(bad), "EG162080.BIN"),
            ("wrong_filename", blobs["modified19"], "EG172080.BIN"),
        ):
            rig = AuditRig(blobs["modified18"])
            row = eg.run(rig, label, data, name)
            if label == "bad_crc":
                assert row["discovery_return"] == 0 and row["integrity_return"] == 3
            else:
                assert row["discovery_return"] != 0
            report["file_checks"].append({"expected_rejection": True, **row})
            del rig
            gc.collect()

        for rom, target, failure in (
            ("modified18", "modified19", None),
            ("modified19", "modified18", None),
            ("modified19", "stock", None),
            ("modified18", "modified19", "erase"),
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
    print(f"MODIFIED19 UPDATER AUDIT OK: {len(report['file_checks'])} file checks, {len(report['scheduler'])} scheduler passes.")


if __name__ == "__main__":
    main()

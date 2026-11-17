"""Native Nikon Z6 C3.80 firmware updater and rollback flash scheduler check for Modified10."""
from pathlib import Path
import argparse, gc, json, traceback
import probe_eg_update_route as eg
from probe_preflash_review import AuditRig, schedule
from probe_raw_candidates import ROOT, sha

FILES = {
    "stock": ("firmware/decoded/eg1620_038000.bi", "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c"),
    "modified1": ("outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN", "eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875"),
    "modified4": ("outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN", "bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b"),
    "modified9": ("outputs/Z6-C380-production-modified9-2026-11-12/01_TEST_MODIFIED9/EG162080.BIN", "70ecc8d583b5207761fbad1b51411906900ba8fb82886dce0fe241595f7d182c"),
    "modified10": ("analysis/modified10-preflash-2026-11-13/lab-build/modified10-candidate.bi", "85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4"),
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)

    blobs = {n: (ROOT / f).read_bytes() for n, (f, _) in FILES.items()}
    for n, (_, h) in FILES.items():
        assert sha(blobs[n]) == h, f"Hash mismatch for {n}"

    for n in (Path(__file__).name, "probe_eg_update_route.py", "probe_preflash_review.py"):
        (args.output / n).write_bytes((ROOT / "tools/fw" / n).read_bytes())

    report = dict(
        ok=False,
        scope=__doc__,
        file_checks=[],
        scheduler=[],
        physical_flash=False,
        model="OS/file and low-level flash adapters; native validation and scheduler code.",
    )
    try:
        pairs = (
            ("modified9", "modified10"),
            ("modified4", "modified10"),
            ("modified1", "modified10"),
            ("stock", "modified10"),
            ("modified10", "modified9"),
            ("modified10", "modified4"),
            ("modified10", "modified1"),
            ("modified10", "stock"),
        )
        for rom, target in pairs:
            label = f"{rom}_to_{target}"
            rig = AuditRig(blobs[rom])
            row = eg.run(rig, label, blobs[target], "EG162080.BIN")
            assert row["discovery_return"] == row["integrity_return"] == row["component_precheck_return"] == 0
            assert row["loaded_buffer_sha256"] == FILES[target][1]
            report["file_checks"].append(dict(running_rom=rom, target=target, **row))
            del rig
            gc.collect()

        bad = bytearray(blobs["modified10"])
        bad[0x8e3a6] ^= 1
        for label, data, name, size in (
            ("bad_crc", bytes(bad), "EG162080.BIN", None),
            ("wrong_model", blobs["modified10"], "EG172080.BIN", None),
            ("oversize", blobs["modified10"], "EG162080.BIN", 0x2940001),
        ):
            rig = AuditRig(blobs["modified9"])
            row = eg.run(rig, label, data, name, reported_size=size)
            if label == "bad_crc":
                assert row["discovery_return"] == 0 and row["integrity_return"] == 3
            else:
                assert row["discovery_return"] != 0
            report["file_checks"].append(dict(expected_rejection=True, **row))
            del rig
            gc.collect()

        for rom, target, failure in (
            ("modified9", "modified10", None),
            ("modified10", "modified9", None),
            ("modified10", "stock", None),
            ("modified9", "modified10", "erase"),
            ("modified10", "modified9", "readback"),
        ):
            rig = AuditRig(blobs[rom])
            row = schedule(rig, f"{rom}_to_{target}", blobs[target], failure)
            report["scheduler"].append(row)
            del rig
            gc.collect()

        report["ok"] = True
    except Exception:
        report["error"] = traceback.format_exc()
        raise
    finally:
        (args.output / "result.json").write_text(json.dumps(report, indent=2), encoding="utf8")
        print(json.dumps(dict(ok=report["ok"], file_checks=len(report["file_checks"]), scheduler=len(report["scheduler"]))))


if __name__ == "__main__":
    main()

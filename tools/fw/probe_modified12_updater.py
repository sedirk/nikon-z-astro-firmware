"""Native Nikon Z6 C3.80 firmware updater and rollback flash scheduler check for Modified12."""
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
    "modified10": ("outputs/Z6-C380-modified10-reviewed-2026-11-13/01_TEST_MODIFIED10/EG162080.BIN", "85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4"),
    "modified11": ("outputs/Z6-C380-modified11-reviewed-2026-11-14/01_TEST_MODIFIED11/EG162080.BIN", "4b6b8989d1f18f20fd1a6e86c99b885eeab2bad88c4310fe144be3620970df7a"),
    "modified12": ("analysis/modified12-preflash-2026-11-14/lab-build/modified12-candidate.bi", "9734012be0e063fa8f2ccbf77c2dd5a63a76be2f45887aa6b806b97b441cb67c"),
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    blobs = {n: (ROOT / f).read_bytes() for n, (f, _) in FILES.items()}
    for n, (_, h) in FILES.items():
        assert sha(blobs[n]) == h, f"Hash mismatch for {n}"

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
            ("modified10", "modified12"),
            ("modified9", "modified12"),
            ("stock", "modified12"),
            ("modified12", "modified10"),
            ("modified12", "modified9"),
            ("modified12", "stock"),
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

        bad = bytearray(blobs["modified12"])
        bad[0x8e3a6] ^= 1
        for label, data, name, size in (
            ("bad_crc", bytes(bad), "EG162080.BIN", None),
            ("wrong_model", blobs["modified12"], "EG172080.BIN", None),
            ("oversize", blobs["modified12"], "EG162080.BIN", 0x2940001),
        ):
            rig = AuditRig(blobs["modified10"])
            row = eg.run(rig, label, data, name, reported_size=size)
            if label == "bad_crc":
                assert row["discovery_return"] == 0 and row["integrity_return"] == 3
            else:
                assert row["discovery_return"] != 0
            report["file_checks"].append(dict(expected_rejection=True, **row))
            del rig
            gc.collect()

        for rom, target, failure in (
            ("modified10", "modified12", None),
            ("modified12", "modified10", None),
            ("modified12", "stock", None),
            ("modified10", "modified12", "erase"),
            ("modified12", "modified10", "readback"),
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
        (args.output / "result.json").write_text(json.dumps(report, indent=2), encoding="utf8")
    print(f"Modified12 updater check ok: {len(report['file_checks'])} file checks, {len(report['scheduler'])} scheduler passes.")


if __name__ == "__main__":
    main()

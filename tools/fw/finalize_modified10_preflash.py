"""Final preservation check, zip packaging, and evidence-index generation for Modified10."""
from pathlib import Path
import datetime, hashlib, json, shutil, zipfile
from verify_modified10_kit import DIGESTS, check_kit

ROOT = Path(__file__).resolve().parents[2]
ROUND = ROOT / "analysis/modified10-preflash-2026-11-13"
KIT = ROOT / "outputs/Z6-C380-modified10-reviewed-2026-11-13"
ZIP_PATH = ROOT / "outputs/Z6-C380-modified10-reviewed-2026-11-13.zip"


def sha_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    # 1. Verify immutable baseline files
    preserved = {
        "firmware/original/Z_6_0380.bin": "ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54",
        "firmware/decoded/eg1620_038000.bi": DIGESTS["stock"],
        "analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/CAL38.bin": "914884aa8f0db4d407fd15eb6731ca6f7f388c62c109407e733d09d5ec760372",
        "analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3/ID35.bin": "d52210383ec47bb473f2faebf3e1b7dd60bcf77f3b018dcba89fdec2bef48baf",
        "outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN": DIGESTS["modified1"],
        "outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN": "bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b",
        "outputs/Z6-C380-cal33-control18-reviewed-2026-11-10/01_TEST_MODIFIED6/EG162080.BIN": "5c1cdfcd11ccfef301317118c43954bf6b55a50e6574ea66ba941e2f9a716003",
        "outputs/Z6-C380-cal33-control1a-reviewed-2026-11-12/01_TEST_MODIFIED7/EG162080.BIN": "0b4ebdd106da2ebf0100063bf604898b15dacdb175ccb7ee7d759610a3e32945",
        "outputs/Z6-C380-production-modified9-2026-11-12/01_TEST_MODIFIED9/EG162080.BIN": DIGESTS["modified9"],
    }
    checked_preserved = {}
    for rel, expected_sha in preserved.items():
        fp = ROOT / rel
        actual = sha_file(fp)
        assert actual == expected_sha, f"Preserved file altered: {rel}"
        checked_preserved[rel] = actual

    # 2. Verify packaged kit
    kit_check = check_kit(KIT)

    # 3. Create deterministic zip archive of kit if not already present
    assert not ZIP_PATH.exists(), f"Zip already exists: {ZIP_PATH}"
    with zipfile.ZipFile(ZIP_PATH, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for p in sorted(KIT.rglob("*"), key=lambda x: x.relative_to(KIT).as_posix()):
            if p.is_file():
                arc = f"{KIT.name}/{p.relative_to(KIT).as_posix()}"
                zf.write(p, arc)
    zip_sha = sha_file(ZIP_PATH)

    # 4. Snapshot scripts & documents into ROUND
    snap_scripts = ROUND / "script-snapshots"
    snap_docs = ROUND / "document-snapshots"
    snap_scripts.mkdir(exist_ok=True)
    snap_docs.mkdir(exist_ok=True)
    for s in (
        "prepare_modified10_lab.py",
        "probe_modified10_native.py",
        "review_modified10_bytes.py",
        "probe_modified10_updater.py",
        "qemu_modified10_probe.py",
        "verify_modified10_kit.py",
        "package_modified10_kit.py",
        "test_modified10_kit.py",
        "finalize_modified10_preflash.py",
    ):
        shutil.copy2(ROOT / "tools/fw" / s, snap_scripts / s)
    for d, dst_name in (
        ("README.md", "README.md"),
        ("docs/PROJECT_GOALS.md", "docs-PROJECT_GOALS.md"),
        ("docs/NEXT_STEPS.md", "docs-NEXT_STEPS.md"),
        ("docs/MODIFIED10_PREFLASH_REVIEW_2026-11-13.md", "docs-MODIFIED10_PREFLASH_REVIEW_2026-11-13.md"),
        ("patches/z6-c380-modified10-fullsize-convergence.json", "patches-z6-c380-modified10-fullsize-convergence.json"),
    ):
        shutil.copy2(ROOT / d, snap_docs / dst_name)

    verification = dict(
        ok=True,
        status="VERIFIED_OK",
        verified_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        candidate="modified10",
        candidate_sha256=DIGESTS["modified10"],
        kit_dir=KIT.relative_to(ROOT).as_posix(),
        zip_path=ZIP_PATH.relative_to(ROOT).as_posix(),
        zip_bytes=ZIP_PATH.stat().st_size,
        zip_sha256=zip_sha,
        kit_verification=kit_check,
        preserved_baselines=checked_preserved,
    )
    (ROUND / "verification.json").write_text(json.dumps(verification, indent=2), encoding="utf8")

    # 5. Build evidence-index.json over ROUND
    entries = []
    for p in sorted(ROUND.rglob("*"), key=lambda x: x.relative_to(ROUND).as_posix()):
        if p.is_file() and p.name != "evidence-index.json":
            entries.append(dict(
                path=p.relative_to(ROOT).as_posix(),
                bytes=p.stat().st_size,
                sha256=sha_file(p),
            ))
    (ROUND / "evidence-index.json").write_text(
        json.dumps(dict(ok=True, count=len(entries), files=entries), indent=2),
        encoding="utf8",
    )
    print(json.dumps(dict(
        ok=True,
        status="VERIFIED_OK",
        candidate_sha256=DIGESTS["modified10"],
        zip_sha256=zip_sha,
        evidence_files=len(entries),
    )))


if __name__ == "__main__":
    main()

"""Negative and positive self-tests for verify_modified10_kit.py."""
from pathlib import Path
import argparse, json, shutil, tempfile
from verify_modified10_kit import check_kit, check_card_contents

ROOT = Path(__file__).resolve().parents[2]


def expect_fail(fn, label: str) -> str:
    try:
        fn()
    except ValueError as exc:
        return f"{label}: caught ({exc})"
    raise AssertionError(f"Expected ValueError for {label}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kit", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)

    pos = check_kit(args.kit)
    negatives = []

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        card_ok = tmp / "card_ok"
        card_ok.mkdir()
        shutil.copy2(args.kit / "01_TEST_MODIFIED10/EG162080.BIN", card_ok / "EG162080.BIN")
        c_m10 = check_card_contents(card_ok, "modified10")

        negatives.append(expect_fail(lambda: check_card_contents(card_ok, "modified9"), "wrong_mode"))

        shutil.copy2(args.kit / "04_STOCK_C380/EG162080.BIN", card_ok / "EXTRA.BIN")
        negatives.append(expect_fail(lambda: check_card_contents(card_ok, "modified10"), "multiple_bins"))
        (card_ok / "EXTRA.BIN").unlink()

        corrupt = bytearray((card_ok / "EG162080.BIN").read_bytes())
        corrupt[0x8e3a6] ^= 1
        (card_ok / "EG162080.BIN").write_bytes(corrupt)
        negatives.append(expect_fail(lambda: check_card_contents(card_ok, "modified10"), "corrupt_byte"))

        (card_ok / "EG162080.BIN").rename(card_ok / "Z6_0380.BIN")
        negatives.append(expect_fail(lambda: check_card_contents(card_ok, "modified10"), "wrong_filename"))

        q_m5 = ROOT / "analysis/modified5-failure-2026-11-10/quarantine/modified5-EG162080.BIN.RECALLED"
        if q_m5.is_file():
            card_rev = tmp / "card_rev"
            card_rev.mkdir()
            shutil.copy2(q_m5, card_rev / "EG162080.BIN")
            negatives.append(expect_fail(lambda: check_card_contents(card_rev, "modified10"), "recalled_modified5"))

        kit_bad = tmp / "kit_bad"
        shutil.copytree(args.kit, kit_bad)
        (kit_bad / "rogue.bin").write_bytes(b"1234")
        negatives.append(expect_fail(lambda: check_kit(kit_bad), "rogue_kit_binary"))

    res = dict(ok=True, positive=pos, card_positive=c_m10, negative_cases_caught=len(negatives), negatives=negatives)
    (args.output / "result.json").write_text(json.dumps(res, indent=2), encoding="utf8")
    (args.output / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    (args.output / "verify_modified10_kit.py").write_bytes((ROOT / "tools/fw/verify_modified10_kit.py").read_bytes())
    print(json.dumps(dict(ok=True, negative_cases_caught=len(negatives))))


if __name__ == "__main__":
    main()

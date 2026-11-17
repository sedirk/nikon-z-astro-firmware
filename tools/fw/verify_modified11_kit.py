"""Independent offline verification of the final Modified11 delivery kit."""
from pathlib import Path
import argparse, binascii, hashlib, json, sys

DIGESTS = {
    "modified11": "4b6b8989d1f18f20fd1a6e86c99b885eeab2bad88c4310fe144be3620970df7a",
    "modified10": "85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4",
    "modified9": "70ecc8d583b5207761fbad1b51411906900ba8fb82886dce0fe241595f7d182c",
    "modified1": "eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875",
    "stock": "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c",
}
PATHS = {
    "modified11": "01_TEST_MODIFIED11/EG162080.BIN",
    "modified10": "02_BACK_TO_MODIFIED10/EG162080.BIN",
    "modified9": "03_BACK_TO_MODIFIED9/EG162080.BIN",
    "modified1": "04_DARK_ONLY_MODIFIED1/EG162080.BIN",
    "stock": "05_STOCK_C380/EG162080.BIN",
}

M1_EDITS = (
    (0x100c2654, "00f065fa", "4ff00000"),
    (0x100c267c, "00f045fa", "4ff00200"),
    (0x100c2690, "90f81a18", "4ff00201"),
)
M9_EXTRA_EDITS = (
    (
        0x1002d884,
        "00" * 68,
        "0f4900223c2341f82320013bfbd144f200028a620a65c1f8a020c1f8c82042f22002c2f22002c1f8f4202022a1f8f8200022c1f8fc20a1f8fa200120eff042be54379ac2",
    ),
    (0x1017d834, "01209ff787fe", "b0f626f8c046"),
)
M10_EXTRA_EDITS = (
    (0x100ae3a4, "0cf166f8", "0cf187f8"),
    (0x100c28b2, "84f86200", "84f86290"),
    (0x100c28c8, "84f86390", "84f86300"),
    (0x100c2964, "90f85f02", "4ff00100"),
    (0x1019741a, "59b1", "0ee0"),
    (0x10197868, "4e77", "4a77"),
    (0x10197876, "4078", "0020"),
)
M11_EXTRA_EDITS = (
    (0x10122cba, "41b1086818604868586088689860c868d860", "41f20000186058609860d86000bf00bf00bf"),
)

SUPPORT = {
    "START_HERE.txt",
    "README.txt",
    "FLAT_COMPARE.txt",
    "MANIFEST.json",
    "verify.py",
}


def need(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def check_kit(root: Path) -> dict:
    need(root.is_dir(), f"Not a directory: {root}")
    res = dict(bins={}, support={}, edits={})

    for key, rel in PATHS.items():
        fp = root / rel
        need(fp.is_file(), f"Missing binary: {rel}")
        data = fp.read_bytes()
        need(len(data) == 33502842, f"Invalid size for {rel}: {len(data)}")
        need(binascii.crc_hqx(data, 0) == 0, f"CRC error in {rel}")
        h = sha(data)
        need(h == DIGESTS[key], f"Hash mismatch for {key}: expected {DIGESTS[key]}, got {h}")
        res["bins"][key] = dict(rel=rel, sha256=h, bytes=len(data))

    stock_data = (root / PATHS["stock"]).read_bytes()
    m11_data = (root / PATHS["modified11"]).read_bytes()
    all_edits = list(M1_EDITS + M9_EXTRA_EDITS + M10_EXTRA_EDITS + M11_EXTRA_EDITS)
    diff_offsets = [i for i, (a, b) in enumerate(zip(stock_data, m11_data)) if a != b]
    expected_diff_count = 109
    need(len(diff_offsets) == expected_diff_count, f"Changed byte count mismatch: {len(diff_offsets)} != {expected_diff_count}")

    for addr, before, after in all_edits:
        off = addr - 0x10020000
        bb = bytes.fromhex(before)
        ab = bytes.fromhex(after)
        need(stock_data[off:off + len(bb)] == bb, f"Stock site mismatch at {addr:#x}")
        need(m11_data[off:off + len(ab)] == ab, f"Modified11 site mismatch at {addr:#x}")
    res["edits"]["total_verified_sites"] = len(all_edits)
    res["edits"]["total_changed_bytes"] = len(diff_offsets)

    for name in SUPPORT:
        fp = root / name
        need(fp.is_file(), f"Missing support file: {name}")
        res["support"][name] = fp.stat().st_size

    return res


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kit", type=Path, default=Path(__file__).resolve().parents[2] / "outputs/Z6-C380-modified11-reviewed-2026-11-14")
    args = ap.parse_args()
    report = check_kit(args.kit)
    print(json.dumps(report, indent=2))
    print(f"PASS: Kit {args.kit.name} fully verified.")


if __name__ == "__main__":
    main()

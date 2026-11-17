"""Independent offline verification of the final Modified12 delivery kit."""
from pathlib import Path
import argparse, binascii, hashlib, json, sys

DIGESTS = {
    "modified12": "9734012be0e063fa8f2ccbf77c2dd5a63a76be2f45887aa6b806b97b441cb67c",
    "modified11": "4b6b8989d1f18f20fd1a6e86c99b885eeab2bad88c4310fe144be3620970df7a",
    "modified10": "85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4",
    "modified1": "eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875",
    "stock": "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c",
}
PATHS = {
    "modified12": "01_TEST_MODIFIED12/EG162080.BIN",
    "modified11": "02_BACK_TO_MODIFIED11/EG162080.BIN",
    "modified10": "03_BACK_TO_MODIFIED10/EG162080.BIN",
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
M12_EXTRA_EDITS = (
    (0x10122cba, "41b1086818604868586088689860c868d860", "41b141f20000186058609860d86000bf00bf"),
)
M12_ALL_EDITS = M1_EDITS + M9_EXTRA_EDITS + M10_EXTRA_EDITS + M12_EXTRA_EDITS
BASE = 0x10020000
SIZE = 33502842


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def need(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def check_kit(kit_dir: Path) -> dict:
    blobs = {}
    for name, rel in PATHS.items():
        p = kit_dir / rel
        need(p.is_file(), f"Missing file: {rel}")
        b = p.read_bytes()
        need(len(b) == SIZE, f"Wrong size for {rel}: {len(b)} != {SIZE}")
        need(sha(b) == DIGESTS[name], f"Hash mismatch for {rel}")
        need(binascii.crc_hqx(b, 0) == 0, f"CRC failure for {rel}")
        blobs[name] = b

    stock = blobs["stock"]
    m12 = blobs["modified12"]

    # Verify site-by-site against Stock
    for addr, before_hex, after_hex in M12_ALL_EDITS:
        off = addr - BASE
        old_b = bytes.fromhex(before_hex)
        new_b = bytes.fromhex(after_hex)
        need(stock[off : off + len(old_b)] == old_b, f"Stock anchor mismatch at {addr:#x}")
        need(m12[off : off + len(new_b)] == new_b, f"Modified12 patch mismatch at {addr:#x}")

    # Reconstruct Modified12 directly from stock
    rebuilt = bytearray(stock)
    for addr, before_hex, after_hex in M12_ALL_EDITS:
        off = addr - BASE
        rebuilt[off : off + len(bytes.fromhex(after_hex))] = bytes.fromhex(after_hex)
    crc = binascii.crc_hqx(bytes(rebuilt[:-2]), 0)
    rebuilt[-2:] = crc.to_bytes(2, "big")
    need(bytes(rebuilt) == m12, "Rebuilt from stock diverged from distributed Modified12")

    return dict(status="OK", total_files=len(PATHS), sites=len(M12_ALL_EDITS))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("kit_dir", type=Path, nargs="?", default=Path("."))
    args = ap.parse_args()
    res = check_kit(args.kit_dir)
    print(f"PASS: {res}")


if __name__ == "__main__":
    main()

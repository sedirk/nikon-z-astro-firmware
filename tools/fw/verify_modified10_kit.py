"""Independent integrity, reconstruction, and card-root verifier for the Modified10 review kit."""
from pathlib import Path
import argparse, binascii, hashlib, json

SIZE, BASE = 33502842, 0x10020000
REVOKED = {
    "76474a8977a3bf4b456fe68f9594110714a04c09b4ec575f019ba27fadd0d2d7": "RECALLED modified5",
}
DIGESTS = {
    "modified10": "85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4",
    "modified9": "70ecc8d583b5207761fbad1b51411906900ba8fb82886dce0fe241595f7d182c",
    "modified1": "eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875",
    "stock": "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c",
}
PATHS = {
    "modified10": "01_TEST_MODIFIED10/EG162080.BIN",
    "modified9": "02_BACK_TO_MODIFIED9/EG162080.BIN",
    "modified1": "03_DARK_ONLY_MODIFIED1/EG162080.BIN",
    "stock": "04_STOCK_C380/EG162080.BIN",
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
SUPPORT = {
    "START_HERE.txt",
    "FLAT_COMPARE.txt",
    "REVIEW.md",
    "verify.py",
    "baseline112.json",
    "patch-recipe.json",
    "SHOT_LOG_TEMPLATE.txt",
}


def need(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def firmware_name(name: str) -> bool:
    low = name.lower()
    return Path(name).suffix.lower() in (".bin", ".bi", ".lab", ".recalled") or ".bin." in low


def read_module(path: Path, mode: str) -> bytes:
    need(mode in DIGESTS, f"Unknown firmware mode: {mode}")
    need(path.is_file(), f"Missing module: {path}")
    need(path.stat().st_size == SIZE, f"Wrong size: {path}")
    data = path.read_bytes()
    digest = sha(data)
    need(digest not in REVOKED, f"{REVOKED.get(digest, 'RECALLED')}: do not install")
    need(digest == DIGESTS[mode], f"Wrong SHA-256 for {mode}: {path}")
    need(binascii.crc_hqx(data, 0) == 0, f"CRC mismatch: {path}")
    return data


def reconstruct(stock: bytes, mode: str) -> bytes:
    need(sha(stock) == DIGESTS["stock"], "Wrong stock module")
    edits = {
        "modified1": M1_EDITS,
        "modified9": M1_EDITS + M9_EXTRA_EDITS,
        "modified10": M1_EDITS + M9_EXTRA_EDITS + M10_EXTRA_EDITS,
    }[mode]
    data = bytearray(stock)
    for address, before, after in edits:
        old, new = bytes.fromhex(before), bytes.fromhex(after)
        off = address - BASE
        need(data[off : off + len(old)] == old and len(old) == len(new), f"Anchor mismatch at {address:#x}")
        data[off : off + len(old)] = new
    data[-2:] = binascii.crc_hqx(data[:-2], 0).to_bytes(2, "big")
    return bytes(data)


def check_kit(root: Path) -> dict:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf8"))
    need(manifest.get("schema") == 7 and manifest.get("candidate") == "modified10", "Wrong kit kind")
    need(manifest.get("module_sha256") == DIGESTS, "Manifest firmware identities changed")
    expected = set(PATHS.values()) | SUPPORT
    listed = [r["path"] for r in manifest["files"]]
    need(len(listed) == len(expected) and set(listed) == expected, "Unexpected manifest paths")
    for row in manifest["files"]:
        path = root / row["path"]
        need(path.is_file(), f"Missing kit file: {path}")
        need(path.stat().st_size == row["bytes"] and sha(path.read_bytes()) == row["sha256"], f"Kit file changed: {path}")
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and firmware_name(p.name)}
    need(actual == set(PATHS.values()), "Unexpected firmware file inside kit")
    modules = {mode: read_module(root / name, mode) for mode, name in PATHS.items()}
    for mode in ("modified1", "modified9", "modified10"):
        need(reconstruct(modules["stock"], mode) == modules[mode], f"Exact reconstruction failed: {mode}")
    return dict(kit_files_checked=len(listed), module_sha256=DIGESTS, exact_patch_reconstruction=True)


def check_card_contents(root: Path, mode: str) -> dict:
    need(mode in PATHS, "Select modified10, modified9, modified1 or stock")
    need(root.is_dir(), "Card root is not a directory")
    names = [p.name for p in root.iterdir() if p.is_file() and firmware_name(p.name)]
    need(
        len(names) == 1 and names[0].upper() == "EG162080.BIN",
        "Keep exactly one firmware file named EG162080.BIN at card root; found " + repr(names),
    )
    data = read_module(root / names[0], mode)
    return dict(card_root=str(root), mode=mode, bytes=len(data), sha256=sha(data))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--kit", type=Path, default=Path(__file__).resolve().parent)
    p.add_argument("--card-root", type=Path)
    p.add_argument("--mode", choices=tuple(PATHS))
    a = p.parse_args()
    out = dict(ok=True, kit=check_kit(a.kit))
    if a.card_root is not None:
        need(a.mode is not None, "--mode is required when --card-root is given")
        out["card"] = check_card_contents(a.card_root, a.mode)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

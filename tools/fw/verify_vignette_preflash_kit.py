"""Read-only, version-pinned modified2 kit/card verifier; never copies or flashes."""
from pathlib import Path
import argparse, binascii, hashlib, json, sys

SIZE = 33502842
BASE = 0x10020000
DIGESTS = {
    'test': '6790186e7e088ae7c504677be052aecdbf3868616207bfda5606b36d37149038',
    'modified1': 'eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875',
    'stock': '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c',
}
PATHS = {'test': '01_TEST_MODIFIED2/EG162080.BIN',
         'modified1': '02_BACK_TO_MODIFIED1/EG162080.BIN',
         'stock': '03_STOCK_C380/EG162080.BIN'}
# Independent fixed locations: do not read allowable changes from the manifest/recipe.
EDITS = ((0x100c2654, '00f065fa', '4ff00000'),
         (0x100c267c, '00f045fa', '4ff00200'),
         (0x100c2690, '90f81a18', '4ff00201'),
         (0x100c28b2, '84f86200', '84f86290'),
         (0x100c28c8, '84f86390', '84f86300'),
         (0x100c2964, '90f85f02', '4ff00100'))
SUPPORT = {'START_HERE.txt', 'FLAT_COMPARE.txt', 'REVIEW.md', 'verify.py',
           'baseline112.json', 'patch-recipe.json', 'SHOT_LOG_TEMPLATE.txt'}


def need(test, message):
    if not test:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_module(path, mode):
    need(path.is_file(), f'Missing module: {path}')
    need(path.stat().st_size == SIZE, f'Wrong size: {path}')
    data = path.read_bytes()
    need(sha(data) == DIGESTS[mode], f'Wrong SHA-256 for {mode}: {path}')
    need(binascii.crc_hqx(data, 0) == 0, f'CRC mismatch: {path}')
    return data


def reconstruct(original, edits):
    need(len(original) == SIZE and sha(original) == DIGESTS['stock'], 'Wrong original')
    result = bytearray(original)
    for address, before, after in edits:
        offset = address - BASE
        need(result[offset:offset+4] == bytes.fromhex(before), 'Original instruction mismatch')
        result[offset:offset+4] = bytes.fromhex(after)
    result[-2:] = binascii.crc_hqx(result[:-2], 0).to_bytes(2, 'big')
    return bytes(result)


def check_kit(root):
    manifest = json.loads((root/'manifest.json').read_text(encoding='utf8'))
    need(manifest['schema'] == 2, 'Wrong manifest schema')
    expected = set(PATHS.values()) | SUPPORT
    listed = [r['path'] for r in manifest['files']]
    need(len(listed) == len(expected) and set(listed) == expected, 'Unexpected manifest paths')
    for row in manifest['files']:
        path = root/row['path']
        need(path.is_file(), f'Missing kit file: {path}')
        need(path.stat().st_size == row['bytes'] and sha(path.read_bytes()) == row['sha256'],
             f'Kit file changed: {path}')
    actual_bins = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and p.suffix.lower() in ('.bin', '.bi', '.lab')}
    need(actual_bins == set(PATHS.values()), 'Unexpected firmware file inside kit')
    modules = {mode: read_module(root/relative, mode) for mode, relative in PATHS.items()}
    need(reconstruct(modules['stock'], EDITS[:3]) == modules['modified1'], 'Modified1 edit mismatch')
    need(reconstruct(modules['stock'], EDITS) == modules['test'], 'Modified2 edit mismatch')
    return dict(kit_files_checked=len(listed), module_sha256=DIGESTS,
                exact_patch_reconstruction=True)


def check_card_contents(root, mode):
    need(mode in PATHS, 'Select test, modified1 or stock explicitly')
    need(root.is_dir(), 'Card root is not a directory')
    names = [p.name for p in root.iterdir() if p.is_file() and
             (p.suffix.lower() in ('.bin', '.bi', '.lab') or '.bin.' in p.name.lower())]
    need(len(names) == 1 and names[0].upper() == 'EG162080.BIN',
         'Keep exactly one firmware file at card root named EG162080.BIN; found '+repr(names))
    data = read_module(root/names[0], mode)
    return dict(card_root=str(root), mode=mode, firmware_file=names[0], bytes=len(data), sha256=sha(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kit', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--card-root', type=Path)
    parser.add_argument('--mode', choices=tuple(PATHS))
    args = parser.parse_args()
    try:
        result = check_kit(args.kit)
        if args.card_root:
            need(args.mode is not None, '--mode test, modified1 or stock is required')
            root = args.card_root.resolve(strict=True)
            need(root == Path(root.anchor) and len(root.drive) == 2 and root.drive[1] == ':',
                 '--card-root must be an actual Windows drive root, for example E:\\')
            result['card'] = check_card_contents(root, args.mode)
        else:
            need(args.mode is None, '--mode requires --card-root')
        result.update(ok=True, read_only=True, physical_installation_verified=False,
                      physical_recovery_verified=False, ring_removal_verified=False)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps(dict(ok=False, error=str(exc), read_only=True)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

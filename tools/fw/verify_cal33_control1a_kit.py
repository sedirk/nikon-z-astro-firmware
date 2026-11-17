"""Read-only fixed-byte verifier for the Z6 C3.80 modified7 control1a test kit."""
from pathlib import Path
import argparse, binascii, hashlib, json, sys

SIZE, BASE, START, END = 33502842, 0x10020000, 0x1017d7b6, 0x1017d83e
REVOKED = '76474a8977a3bf4b456fe68f9594110714a04c09b4ec575f019ba27fadd0d2d7'
DIGESTS = {
    'test': '0b4ebdd106da2ebf0100063bf604898b15dacdb175ccb7ee7d759610a3e32945',
    'modified4': 'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b',
    'modified1': 'eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875',
    'stock': '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c',
}
PATHS = {'test': '01_TEST_MODIFIED7/EG162080.BIN',
    'modified4': '02_BACK_TO_MODIFIED4/EG162080.BIN',
    'modified1': '03_DARK_ONLY_MODIFIED1/EG162080.BIN',
    'stock': '04_STOCK_C380/EG162080.BIN'}
EDITS = ((0x100c2654, '00f065fa', '4ff00000'), (0x100c267c, '00f045fa', '4ff00200'),
    (0x100c2690, '90f81a18', '4ff00201'), (0x100c28b2, '84f86200', '84f86290'),
    (0x100c28c8, '84f86390', '84f86300'), (0x100c2964, '90f85f02', '4ff00100'),
    (0x1019741a, '59b1', '0ee0'), (0x10197868, '4e77', '4a77'),
    (0x10197876, '4078', '0020'), (0x100f64b4, '90f85902', '4ff00200'))
# Hard-coded independently of the kit's manifest and patch recipe.
BEFORE = bytes.fromhex('70b59ff7c2fefe489ff77bff01210446fc48a0f79bf90443fa48a0f786fa0443f848a0f761fb0443f648a0f79afc0443f448a0f7b2fc0443f248a0f76dfd0443f048a0f7b7fd0443ee48a0f748fe0443ec48a0f7c0fe0443ea48a0f753ff0443e8480121a1f791f80443e548a1f77cf940ea0405e348a1f7c4f940ea050401209ff787fe204670bd')
AFTER = bytes.fromhex('70b59ff7c2fefe489ff77bff01210446fc48a0f79bf90443fa48a0f786fa0443f848a0f761fb0443f648a0f79afc0443f448a0f7b2fcf248a0f76efd43f24971ccf29a210870ee48a0f7b4fded48a0f746fe0443eb48a0f7befe0443e948a0f751ff0443e7480121a1f78ff80443e448a1f77af90443e248a1f7c3f9044301209ff787fe204670bd')
SUPPORT = {'START_HERE.txt', 'FLAT_COMPARE.txt', 'REVIEW.md', 'verify.py',
    'baseline112.json', 'patch-recipe.json', 'SHOT_LOG_TEMPLATE.txt'}

def need(value, message):
    if not value:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def read_module(path, mode):
    need(mode in DIGESTS, 'Unknown firmware mode')
    need(path.is_file(), f'Missing module: {path}')
    need(path.stat().st_size == SIZE, f'Wrong size: {path}')
    data = path.read_bytes()
    digest = sha(data)
    need(digest != REVOKED, 'RECALLED modified5: do not install')
    need(digest == DIGESTS[mode], f'Wrong SHA-256 for {mode}: {path}')
    need(binascii.crc_hqx(data, 0) == 0, f'CRC mismatch: {path}')
    return data

def reconstruct(stock, count, test=False):
    need(sha(stock) == DIGESTS['stock'], 'Wrong stock module')
    data = bytearray(stock)
    for address, before, after in EDITS[:count]:
        old, new = bytes.fromhex(before), bytes.fromhex(after)
        off = address - BASE
        need(data[off:off + len(old)] == old and len(old) == len(new), 'Inherited patch mismatch')
        data[off:off + len(old)] = new
    if test:
        need(count == 10 and len(BEFORE) == len(AFTER) == END - START, 'Wrong function bounds')
        need(data[START - BASE:END - BASE] == BEFORE, 'Static function mismatch')
        data[START - BASE:END - BASE] = AFTER
    data[-2:] = binascii.crc_hqx(data[:-2], 0).to_bytes(2, 'big')
    return bytes(data)

def firmware_name(name):
    return Path(name).suffix.lower() in ('.bin', '.bi', '.lab', '.recalled') or '.bin.' in name.lower()

def check_kit(root):
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf8'))
    need(manifest['schema'] == 6 and manifest['candidate'] == 'modified7', 'Wrong kit kind')
    need(manifest['module_sha256'] == DIGESTS, 'Manifest firmware identities changed')
    expected = set(PATHS.values()) | SUPPORT
    listed = [r['path'] for r in manifest['files']]
    need(len(listed) == len(expected) and set(listed) == expected, 'Unexpected manifest paths')
    for row in manifest['files']:
        path = root / row['path']
        need(path.is_file(), f'Missing kit file: {path}')
        need(path.stat().st_size == row['bytes'] and sha(path.read_bytes()) == row['sha256'], f'Kit file changed: {path}')
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and firmware_name(p.name)}
    need(actual == set(PATHS.values()), 'Unexpected firmware file inside kit')
    modules = {mode: read_module(root / name, mode) for mode, name in PATHS.items()}
    for mode, count, test in (('modified1', 3, False), ('modified4', 10, False), ('test', 10, True)):
        need(reconstruct(modules['stock'], count, test) == modules[mode], f'Exact reconstruction failed: {mode}')
    return dict(kit_files_checked=len(listed), module_sha256=DIGESTS, exact_patch_reconstruction=True)

def check_card_contents(root, mode):
    need(mode in PATHS, 'Select test, modified4, modified1 or stock')
    need(root.is_dir(), 'Card root is not a directory')
    names = [p.name for p in root.iterdir() if p.is_file() and firmware_name(p.name)]
    need(len(names) == 1 and names[0].upper() == 'EG162080.BIN',
        'Keep exactly one firmware file named EG162080.BIN at card root; found ' + repr(names))
    data = read_module(root / names[0], mode)
    return dict(card_root=str(root), mode=mode, bytes=len(data), sha256=sha(data))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kit', type=Path, default=Path(__file__).resolve().parent)
    p.add_argument('--card-root', type=Path)
    p.add_argument('--mode', choices=tuple(PATHS))
    a = p.parse_args()
    try:
        result = check_kit(a.kit)
        if a.card_root:
            need(a.mode is not None, '--mode required with --card-root')
            root = a.card_root.resolve(strict=True)
            need(root == Path(root.anchor) and len(root.drive) == 2 and root.drive[1] == ':',
                'Use an actual Windows drive root, e.g. E:\\')
            result['card'] = check_card_contents(root, a.mode)
        else:
            need(a.mode is None, '--mode requires --card-root')
        result.update(ok=True, read_only=True, physical_modified7_test=False, ring_removal_verified=False)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps(dict(ok=False, error=str(exc), read_only=True)), file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())

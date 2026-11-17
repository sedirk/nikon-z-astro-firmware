"""Exercise fixed-hash kit/card acceptance and deliberate corruption in private copies."""
from pathlib import Path
import argparse, binascii, json, shutil, traceback
from verify_cal33_control1a_kit import check_kit, check_card_contents, DIGESTS, PATHS, need, sha

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / 'outputs/Z6-C380-cal33-control1a-reviewed-2026-11-12'

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    out = p.parse_args().output.resolve()
    need(out.is_relative_to(ROOT / 'analysis'), 'Private output must be under project analysis')
    out.mkdir(parents=True, exist_ok=False)
    (out / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    (out / 'verify_cal33_control1a_kit.py').write_bytes((ROOT / 'tools/fw/verify_cal33_control1a_kit.py').read_bytes())
    before = {n: sha((KIT / f).read_bytes()) for n, f in PATHS.items()}
    report = dict(ok=False, scope=__doc__, rows=[], physical_card_or_camera_touched=False)
    scratch = out / 'private-copies'
    scratch.mkdir()
    try:
        def accept(label, fn):
            value = fn()
            report['rows'].append(dict(label=label, accepted=True, result=value))
        def reject(label, fn, expected):
            try:
                fn()
            except (ValueError, OSError, KeyError, TypeError) as exc:
                need(expected in str(exc), label + ': unexpected failure ' + str(exc))
                report['rows'].append(dict(label=label, accepted=False, expected_error=str(exc)))
            else:
                raise AssertionError('Invalid input accepted: ' + label)
        accept('exact_kit', lambda: check_kit(KIT))
        card = scratch / 'card'
        card.mkdir()
        file = card / 'EG162080.BIN'
        for mode, name in PATHS.items():
            shutil.copyfile(KIT / name, file)
            accept('card_' + mode, lambda: check_card_contents(card, mode))
        data = (KIT / PATHS['test']).read_bytes()
        file.write_bytes(data)
        reject('test_labeled_rollback', lambda: check_card_contents(card, 'modified4'), 'Wrong SHA-256')
        file.write_bytes(data[:-1])
        reject('truncated', lambda: check_card_contents(card, 'test'), 'Wrong size')
        changed = bytearray(data)
        changed[0x15d7fa] ^= 1
        file.write_bytes(changed)
        reject('changed_payload', lambda: check_card_contents(card, 'test'), 'Wrong SHA-256')
        changed[-2:] = binascii.crc_hqx(changed[:-2], 0).to_bytes(2, 'big')
        need(binascii.crc_hqx(changed, 0) == 0, 'Negative sample CRC')
        file.write_bytes(changed)
        reject('changed_payload_valid_crc', lambda: check_card_contents(card, 'test'), 'Wrong SHA-256')
        shutil.copyfile(ROOT / 'analysis/modified5-failure-2026-11-10/quarantine/modified5-EG162080.BIN.RECALLED', file)
        reject('recalled_modified5', lambda: check_card_contents(card, 'test'), 'RECALLED')
        file.write_bytes(data)
        wrong = card / 'EG172080.BIN'
        file.rename(wrong)
        reject('wrong_filename', lambda: check_card_contents(card, 'test'), 'exactly one')
        wrong.rename(file)
        extra = card / 'Z_6_0380.bin'
        extra.write_bytes(b'not firmware')
        reject('second_firmware', lambda: check_card_contents(card, 'test'), 'exactly one')
        extra.unlink()
        extra = card / 'EG162080.BIN.bak'
        extra.write_bytes(b'not firmware')
        reject('bin_backup', lambda: check_card_contents(card, 'test'), 'exactly one')
        extra.unlink()
        private = scratch / 'kit'
        shutil.copytree(KIT, private)
        manifest_path = private / 'manifest.json'
        manifest_original = manifest_path.read_bytes()
        manifest = json.loads(manifest_original)
        manifest['files'][0]['path'] = '../outside.bin'
        manifest_path.write_text(json.dumps(manifest), encoding='utf8')
        reject('manifest_path_escape', lambda: check_kit(private), 'Unexpected manifest paths')
        manifest_path.write_bytes(manifest_original)
        manifest = json.loads(manifest_original)
        manifest['files'].append(manifest['files'][0])
        manifest_path.write_text(json.dumps(manifest), encoding='utf8')
        reject('manifest_duplicate', lambda: check_kit(private), 'Unexpected manifest paths')
        manifest_path.write_bytes(manifest_original)
        rollback = private / PATHS['modified4']
        rollback.unlink()
        reject('missing_rollback', lambda: check_kit(private), 'Missing kit file')
        shutil.copyfile(KIT / PATHS['modified4'], rollback)
        candidate = private / PATHS['test']
        candidate.write_bytes(changed)
        manifest = json.loads(manifest_original)
        next(r for r in manifest['files'] if r['path'] == PATHS['test'])['sha256'] = sha(changed)
        manifest_path.write_text(json.dumps(manifest), encoding='utf8')
        reject('manifest_rehashed_corruption', lambda: check_kit(private), 'Wrong SHA-256')
        candidate.write_bytes(data)
        manifest_path.write_bytes(manifest_original)
        support = private / 'START_HERE.txt'
        original_text = support.read_bytes()
        support.write_bytes(original_text + b'changed')
        reject('support_changed', lambda: check_kit(private), 'Kit file changed')
        support.write_bytes(original_text)
        extra = private / 'EG162080.BIN.bak'
        extra.write_bytes(b'unexpected')
        reject('extra_kit_firmware', lambda: check_kit(private), 'Unexpected firmware')
        extra.unlink()
        accept('restored_private_kit', lambda: check_kit(private))
        need(before == DIGESTS and before == {n: sha((KIT / f).read_bytes()) for n, f in PATHS.items()}, 'Delivery modified')
        report['ok'] = True
    except Exception:
        report['error'] = traceback.format_exc()
        raise
    finally:
        # Only disposable private copies; resolve and check before recursive deletion.
        target = scratch.resolve(strict=True)
        need(target.is_relative_to(out) and out.is_relative_to(ROOT / 'analysis') and target.name == 'private-copies', 'Unsafe cleanup path')
        shutil.rmtree(target)
        report['temporary_copy_directory_removed'] = str(target)
        (out / 'result.json').write_text(json.dumps(report, indent=2), encoding='utf8')
        print(json.dumps(dict(ok=report['ok'], cases=len(report['rows']), source_firmware_preserved=before == DIGESTS)))

if __name__ == '__main__':
    main()

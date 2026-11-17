"""Build reversible experimental decoded modules, preserving the original input.

These are not camera update containers. Each candidate is applied independently,
with exact version/hash/preimage checks and the module's CRC16 repaired. No
updater acceptance, hardware behavior or pixel effect is implied by a valid CRC.
"""
from pathlib import Path
import argparse
import binascii
import hashlib
import json

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / 'patches/z6-c380-raw-candidates.json'
SOURCE = ROOT / 'firmware/decoded/eg1620_038000.bi'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def apply_candidate(source, catalog, candidate):
    if len(source) != catalog['source_size'] or sha(source) != catalog['source_sha256']:
        raise ValueError('Source size/SHA-256 does not match the pinned Z6 C3.80 module')
    if binascii.crc_hqx(source, 0) != 0:
        raise ValueError('Source module CRC16 is invalid')
    output = bytearray(source)
    edits, used = [], set()
    for edit in candidate['edits']:
        address = int(edit['address'], 0)
        offset = address - int(catalog['load_base'], 0)
        before, after = bytes.fromhex(edit['before']), bytes.fromhex(edit['after'])
        if not before or len(before) != len(after) or not 0 <= offset < offset+len(before) <= len(source)-2:
            raise ValueError('Invalid edit extent/length')
        extent = set(range(offset, offset+len(before)))
        if extent & used:
            raise ValueError('Overlapping edits')
        if source[offset:offset+len(before)] != before:
            raise ValueError('Instruction preimage mismatch')
        used |= extent
        output[offset:offset+len(after)] = after
        edits.append(dict(edit, file_offset=hex(offset)))
    crc = binascii.crc_hqx(output[:-2], 0).to_bytes(2, 'big')
    output[-2:] = crc
    output = bytes(output)
    if binascii.crc_hqx(output, 0) != 0:
        raise ValueError('Repaired module CRC16 is invalid')
    actual_changes = [i for i, (old, new) in enumerate(zip(source, output)) if old != new]
    if set(actual_changes) - used - {len(source)-2, len(source)-1}:
        raise ValueError('Unexpected changed byte outside edits and CRC')
    restored = bytearray(output)
    for edit in edits:
        off = int(edit['file_offset'], 0)
        before = bytes.fromhex(edit['before'])
        restored[off:off+len(before)] = before
    restored[-2:] = source[-2:]
    if restored != source:
        raise ValueError('Exact rollback verification failed')
    manifest = dict(candidate, source_sha256=sha(source), output_sha256=sha(output),
        module_size=len(output), edits=edits, changed_byte_offsets=[hex(i) for i in actual_changes],
        crc_offset=hex(len(source)-2), crc_before=source[-2:].hex(), crc_after=crc.hex(),
        module_crc_remainder=0, exact_rollback_verified=True, camera_update_container=False,
        hardware_pixels_verified=False)
    return output, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=SOURCE)
    parser.add_argument('--catalog', type=Path, default=CATALOG)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    blob = source.read_bytes()
    catalog = json.loads(args.catalog.read_text(encoding='utf-8'))
    # Validate all candidates before creating any output directory.
    builds = [(c['id'], *apply_candidate(blob, catalog, c)) for c in catalog['candidates']]
    if len({name for name, _, _ in builds}) != len(builds):
        raise ValueError('Duplicate candidate id')
    for name, _, _ in builds:
        if not name or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in name):
            raise ValueError('Invalid candidate id')
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output/'builder-source.py').write_bytes(Path(__file__).read_bytes())
    (args.output/'catalog.json').write_bytes(args.catalog.read_bytes())
    result = dict(source=str(source), source_sha256=sha(blob), catalog_sha256=sha(args.catalog.read_bytes()),
                  builder_sha256=sha(Path(__file__).read_bytes()), candidates=[])
    for name, data, manifest in builds:
        filename = f'{name}.bi'
        with (args.output/filename).open('xb') as stream:
            stream.write(data)
        if sha((args.output/filename).read_bytes()) != manifest['output_sha256']:
            raise ValueError('Output readback mismatch')
        manifest['file'] = filename
        (args.output/f'{name}.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        result['candidates'].append(manifest)
    if source.read_bytes() != blob:
        raise ValueError('Source changed while building')
    result['original_preserved'] = True
    (args.output/'build.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({'ok': True, 'output': str(args.output), 'candidates':
        [{'id': m['id'], 'sha256': m['output_sha256'], 'changed_bytes': len(m['changed_byte_offsets'])}
         for m in result['candidates']]}, indent=2))


if __name__ == '__main__':
    main()

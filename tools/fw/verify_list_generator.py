"""Verify saved generator experiments without rerunning either emulator."""
from pathlib import Path
from collections import Counter
import ast
import hashlib
import json
import re
import struct

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/list-generator-2026-11-02'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def main():
    firmware = {
        'firmware/original/Z_6_0380.bin': 'ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54',
        'firmware/decoded/eg1620_038000.bi': '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c',
        'firmware/decoded/ex1620_037000.bi': '72f1fb29e24b36b872eec697a486abeff8bcef77f6020fa89473fd014aa18131',
        'firmware/decoded/vr1620_010200.bi': '48aaa4d82d709ff6a97b9618cfdbbb706304588642a7f1a73bfc4a525c22a37a',
        'firmware/decoded/_tpj01_v140.bin': 'e60998537d46a15c430154aeeb589026aca015256d27e2d5990589d23a59c88e',
    }
    for name, expected in firmware.items():
        assert digest(ROOT / name) == expected, name
    main_sha = firmware['firmware/decoded/eg1620_038000.bi']
    names = ('empty', 'one-point', 'pair', 'weighted', 'next-row', 'outside-row', 'invalid-marker')
    cases = {}
    for name in names:
        result = read(OUT / name / 'result.json')
        blob = (OUT / name / 'generated.bin').read_bytes()
        assert result['ok'] and result['output_guard'] and result['workspace_guard'], name
        assert result['firmware_sha256'] == main_sha
        assert not any(result[key] for key in ('code_patches', 'service_stubs', 'memory_write_hooks'))
        assert len(blob) == 0xdfff8 and blob[0xd767c:0xd7680] == b'ENDM'
        assert hashlib.sha256(blob).hexdigest() == result['output_sha256']
        cases[name] = result
    for name, row, word in (
        ('one-point', 32, 0xa0190000), ('pair', 32, 0xe0190000),
        ('weighted', 32, 0x00192000), ('next-row', 33, 0xa0190000),
    ):
        stream = cases[name]['groups'][0]['streams'][0]
        assert stream['nonempty_count'] == 1
        assert stream['nonempty'][0]['row'] == row
        assert int(stream['nonempty'][0]['word'], 16) == word
        blob = (OUT / name / 'generated.bin').read_bytes()
        # Group 0 stream 0 starts at byte zero; each preceding empty row is a sentinel.
        assert blob[:row * 4] == b'\xff' * (row * 4)
        assert struct.unpack_from('<I', blob, row * 4)[0] == word
    empty = (OUT / 'empty/generated.bin').read_bytes()
    for name in ('outside-row', 'invalid-marker'):
        assert (OUT / name / 'generated.bin').read_bytes() == empty
    for group, rows in zip(cases['empty']['groups'], (104, 88, 88, 56, 88, 72, 104)):
        assert all(s['sentinels'] == rows and s['nonempty_count'] == 0 for s in group['streams'])

    qemu = read(OUT / 'qemu-crosscheck/result.json')
    assert qemu['ok'] and qemu['firmware_unchanged'] and qemu['firmware_sha256'] == main_sha
    assert qemu['allocation_freed'] and int(qemu['native_free_call']['return_r0'], 16) == 1
    assert [c['name'] for c in qemu['cases']] == list(names[:4])
    for case in qemu['cases']:
        assert case['matches_unicorn'] and case['guards']
        assert case['output_sha256'] == case['expected_sha256'] == cases[case['name']]['output_sha256']
        assert int(case['call']['return_r0'], 16) == 1

    release = read(OUT / 'release-observation/result.json')
    assert release['ok'] and release['firmware_unchanged'] and release['firmware_sha256'] == main_sha
    capture = release['capture_probe']
    assert capture['physical_input_submitted'] and capture['exposure_completed'] is None
    assert not capture['firmware_code_modified'] and not capture['timing_verified']
    assert [int(e['switch_mask'], 16) for e in capture['events']] == [0x80000000, 0xc0000000, 0x80000000, 0]
    for snapshot in (capture['before'], capture['after']):
        assert snapshot['active_inhibit_ids'] == ['0x24']
        assert snapshot['release_inhibit_submask'] == '0xc' and snapshot['application']['stage'] == 0
    events = read(OUT / 'release-observation/path-observations.json')
    assert len(events) == release['path_observation_count']
    window = events[release['capture_probe_path_event_start']:release['capture_probe_path_event_end']]
    counts = Counter(e['event'] for e in window)
    assert len(window) == 24 and counts['list_group_select'] == 5
    assert counts['list_mmio_write_before'] == counts['list_mmio_write_after'] == 5
    assert not any(e['event'] == 'list_generator_entry' for e in events)
    for event in window:
        if event['event'] == 'list_group_select':
            assert int(event['registers']['r0'], 16) == 6
            request = bytes.fromhex(event['memory']['capture_request']['head'])
            assert struct.unpack_from('<I', request, 8)[0] == 0 and request[12:14] == b'\x03\x00'
    selector = read(OUT / 'group-selection.json')
    assert selector['cases'] == 112 and len(selector['rows']) == 14
    for mode, row in enumerate(selector['rows']):
        expected = [0] * 8
        if mode == 3:
            expected = [6] * 8
        elif mode in (7, 11):
            expected = [4] * 8
        elif mode in (2, 5, 9):
            expected[4:6] = [2, 3]
        elif mode in (4, 8):
            expected[4:6] = [1, 3]
        assert row == {'mode': mode, 'submodes_0_to_7': expected}

    scripts = [ROOT / 'tools/fw' / name for name in (
        'probe_list_generator.py', 'qemu_generator_probe.py', 'probe_group_selector.py',
        'qemu_baseline_probe.py', 'qemu_path_observer.py', 'verify_list_generator.py',
    )]
    for script in scripts:
        ast.parse(script.read_text(encoding='utf-8'), filename=str(script))
    docs = [ROOT / name for name in ('docs/LIST_GENERATOR_2026-11-02.md', 'docs/NEXT_STEPS.md', 'README.md')]
    for doc in docs:
        for link in re.findall(r'\]\(([^)]+)\)', doc.read_text(encoding='utf-8')):
            if '://' not in link and not link.startswith('#'):
                target = (doc.parent / link.split('#')[0]).resolve()
                assert target.exists() or target == OUT / 'verification.json', (doc, link)
    source = ROOT / 'work/src/z6-qemu-419a1f2a91a1f2d3a0209027c29606475f7fe26f/qemu/nikon-z6.c'
    assert digest(source) == '9a92f19510f6730312158079cea39717826648da0d245d766ed39ce412e9091c'
    files = sorted(p for p in OUT.rglob('*') if p.is_file() and p.name != 'verification.json')
    files += scripts + docs
    report = dict(
        ok=True, firmware_hashes_unchanged=firmware, native_cases=7, qemu_crosschecks=4,
        group_selector_cases=112, release_window_events=len(window), release_event_counts=counts,
        exposure_completed=None, exposure_status='Not demonstrated; diagnostic value is null.',
        qemu_source_sha256=digest(source),
        scope='Rechecks saved artifacts and recorded QEMU hashes, not a new emulator run or physical camera validation.',
        assertions=['native output hashes and guard reports valid', 'coordinate and boundary examples verified',
                    'four recorded full QEMU hashes match native artifacts', 'native allocation released',
                    'capture input submitted but static exposure remains unconfirmed',
                    '112 group selections match recorded branch behavior', 'script syntax and document links valid'],
        evidence=[dict(file=p.relative_to(ROOT).as_posix(), bytes=p.stat().st_size, sha256=digest(p)) for p in files],
    )
    (OUT / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('ok', 'native_cases', 'qemu_crosschecks', 'group_selector_cases', 'release_window_events')}, indent=2))
    print(f'Hashed {len(files)} evidence files; original firmware unchanged.')


if __name__ == '__main__':
    main()

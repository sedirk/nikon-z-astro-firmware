"""Recheck saved C3.80 capture-gate evidence; does not run QEMU or a camera."""
from pathlib import Path
import ast
import hashlib
import json
import re
import struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/capture-inhibit-2026-11-02'
BASE = 0x10020000
COMMIT = '419a1f2a91a1f2d3a0209027c29606475f7fe26f'
SOURCE_SHA = '9a92f19510f6730312158079cea39717826648da0d245d766ed39ce412e9091c'
BINARY_SHA = '9719480046775a5d40e22b6e22d13fa100a415dae1d52f0ff40a8d57764b9d63'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def reg(event, name='r0'):
    return int(event['registers'][name], 16)


def event(events, name):
    matches = [e for e in events if e['event'] == name]
    assert len(matches) == 1, (name, len(matches))
    return matches[0]


def main():
    assert __debug__, 'Run without -O; this verifier uses assertions.'
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
    blob = (ROOT / 'firmware/decoded/eg1620_038000.bi').read_bytes()

    names = ('af-status-probe', 'effective-mask-probe', 'native-api-probe',
             'native-storage-probe', 'without-card-probe')
    runs, events = {}, {}
    for name in names:
        r = runs[name] = read(OUT / name / 'result.json')
        es = events[name] = read(OUT / name / 'events.json')
        assert r['ok'] and r['firmware_unchanged']
        assert r['firmware_sha256'] == main_sha and r['upstream_commit'] == COMMIT
        assert r['event_count'] == len(es)
        actions = [json.loads(line) for line in (OUT / name / 'session/actions.jsonl').read_text(encoding='utf-8').splitlines()]
        boot = [a for a in actions if a['kind'] == 'boot']
        assert len(boot) == 1
        boot = boot[0]
        assert boot['firmware_sha256'] == main_sha
        assert not boot['firmware_modified'] and not boot['camera_access']
        assert boot['guest_state_modified']  # Explicit upstream diagnostic fixtures.
        assert boot['build']['binary_sha256'] == BINARY_SHA
        assert boot['build']['sources']['qemu/nikon-z6.c'] == SOURCE_SHA

    af = runs['af-status-probe']
    assert af['baseline']['active_inhibit_ids'] == ['0x24']
    assert len(af['phases']) == 3
    for item, label, status, active in zip(af['phases'],
            ('status-1', 'status-2', 'restore-status'), (1, 2, 0),
            (['0x24'], [], ['0x24'])):
        assert item['phase'] == label and item['synthetic_status'] == status
        assert item['after']['active_inhibit_ids'] == active
        es = [e for e in events['af-status-probe'] if e['phase'] == label]
        callback, queued = event(es, 'af_status_callback'), event(es, 'queued_af_status')
        assert reg(callback) == 0x04260011
        assert bytes.fromhex(callback['input'])[0] == bytes.fromhex(queued['input'])[0] == status
        name = 'clear_inhibit' if status == 2 else 'set_inhibit'
        bit_event = [e for e in es if e['event'] == name and reg(e) == 0x24]
        assert len(bit_event) == 1
        assert es.index(callback) < es.index(queued) < es.index(bit_event[0])

    mask = runs['effective-mask-probe']
    assert mask['native_summary_getters'] == {'overall': 1, 'special': 0}
    for name in names[1:]:
        baseline = runs[name]['baseline']
        assert baseline['active_inhibit_ids'] == ['0x24']
        assert baseline['effective_inhibit_ids'] == baseline['special_inhibit_ids'] == []
        assert baseline['release_inhibit_submask'] == '0xc'
        values = []
        for s, pointer in zip(baseline['inhibit_bitsets'], (0xc2376d60, 0xc2376d70, 0xc2376d80)):
            assert s['bit_count'] == 97 and int(s['pointer'], 16) == pointer
            value = int.from_bytes(bytes.fromhex(s['bytes']), 'little')
            assert value == s['value']
            values.append(value)
        active, enabled, special = values
        assert active == 1 << 0x24 and enabled & active == special & active == 0
        assert baseline['inhibit_summary_words'][:2] == [1, 0]

    for capture in (af['phases'][1]['capture_probe'], mask['unmodified_status_capture']):
        assert capture['physical_input_submitted'] and capture['exposure_completed'] is None
        assert not capture['firmware_code_modified']
        assert [int(e['switch_mask'], 16) for e in capture['events']] == [0x80000000, 0xc0000000, 0x80000000, 0]

    for name in names[2:]:
        r = runs[name]
        api = r['native_capture_api']
        is_without = name == 'without-card-probe'
        expected = 0 if is_without else 3
        payload = bytearray(32)
        payload[2] = int(is_without)
        struct.pack_into('<I', payload, 16, 1)
        assert bytes.fromhex(api['payload']) == payload
        assert int(api['function'], 16) == 0x101eedb4
        assert api['arguments'] == [{'scratch_offset': 0}, '0x10524b7f']
        assert int(api['return_r0'], 16) == expected
        es = [e for e in events[name] if e['phase'] == 'native-capture-api']
        for check in ('capture_busy_result', 'release_state_result', 'release_context_result',
                      'release_stage_result', 'capture_flag17_result'):
            assert reg(event(es, check)) == 0
        assert reg(event(es, 'capture_mask_result')) == 1
        dest = event(es, 'destination_check_result')
        assert reg(dest) == expected
        assert reg(event(es, 'initiate_capture_exit')) == expected
        if not is_without:
            assert not any(e['event'] == 'prepare_result' for e in es)
        if name != 'native-api-probe':  # This observer was added in the later runs.
            assert bytes.fromhex(event(es, 'destination_validator_entry')['input']) == payload[:20]

    es = events['native-storage-probe']
    rejected = event(es, 'storage_flag_maps_error3')
    assert reg(rejected, 'r15') == 0x101edefe and reg(rejected) == 0x00010008
    assert es.index(rejected) < es.index(event(es, 'destination_check_result'))

    accepted = runs['without-card-probe']
    prep = accepted['calls'][0]['result']
    assert prep['function'] == '0x101efaa8' and prep['arguments'] == ['0x1']
    assert int(prep['return_r0'], 16) == 1
    assert accepted['calls'][1]['result']['function'] == '0x101eedb4'
    es = [e for e in events['without-card-probe'] if e['phase'] == 'native-capture-api']
    prepared = event(es, 'prepare_result')
    assert reg(prepared) == 0 and reg(prepared, 'r15') == 0x101ef04a
    assert es.index(event(es, 'destination_check_result')) < es.index(prepared) < es.index(event(es, 'initiate_capture_exit'))
    marker = [e for e in es if e['event'] == 'set_inhibit' and reg(e) == 0x27]
    assert len(marker) == 1 and reg(marker[0], 'r14') == 0x10200d15
    assert bytes.fromhex(accepted['baseline']['capture_service_context'])[8] == 0
    for key in ('after_api', 'after_settle'):
        s = accepted[key]
        assert bytes.fromhex(s['capture_service_context'])[8] == 3
        assert s['active_inhibit_ids'] == ['0x24', '0x27', '0x2d']
        assert s['effective_inhibit_ids'] == ['0x27', '0x2d']
        assert s['application']['stage'] == 0
    groups = [e for e in es if e['event'] == 'list_group_select']
    assert groups and all(reg(e) == 6 and bytes.fromhex(e['list_request'])[12] == 3 for e in groups)

    keys = read(OUT / 'physical-key-records.json')
    for key in keys:
        start = int(key['address'], 16) - BASE
        record = blob[start:start + 40]
        assert record.hex() == key['record']
        assert record[:32].split(b'\0')[0].decode('ascii') == key['name']
        assert struct.unpack_from('<I', record, 32)[0] == key['unknown_word_32']
        assert struct.unpack_from('<I', record, 36)[0] == int(key['mask'], 16)
        assert int(key['name'][5]) == key['bank_from_name']
    key_masks = {k['name']: int(k['mask'], 16) for k in keys}
    assert key_masks['ID_SW0_RELEASE_HALF'] == 0x80000000
    assert key_masks['ID_SW0_RELEASE_ON'] == 0x40000000

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    checked_ranges = 0
    for name in ('curated-evidence', 'accepted-transition'):
        evidence = read(OUT / (name + '.json'))
        assert evidence['firmware_sha256'] == main_sha
        for span in evidence['ranges']:
            lo, hi = int(span['start'], 16), int(span['end'], 16)
            assert span['decoded_to_end'] and span['decoded_end'] == span['end']
            decoded = list(md.disasm(blob[lo - BASE:hi - BASE], lo))
            assert len(decoded) == len(span['instructions'])
            assert decoded[-1].address + decoded[-1].size == hi
            for ins, row in zip(decoded, span['instructions']):
                assert (hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str) == (row['pc'], row['bytes'], row['mnemonic'], row['operands'])
                if 'literal_address' in row:
                    value = struct.unpack_from('<I', blob, int(row['literal_address'], 16) - BASE)[0]
                    assert value == int(row['literal_value'], 16)
            checked_ranges += 1

    scripts = [ROOT / 'tools/fw' / n for n in ('qemu_inhibit_probe.py', 'inspect_native.py', 'verify_capture_gates.py')]
    docs = [ROOT / n for n in ('README.md', 'docs/NEXT_STEPS.md', 'docs/LIST_GENERATOR_2026-11-02.md', 'docs/CAPTURE_GATES_2026-11-02.md')]
    for script in scripts:
        ast.parse(script.read_text(encoding='utf-8'), filename=str(script))
    for doc in docs:
        for link in re.findall(r'\]\(([^)]+)\)', doc.read_text(encoding='utf-8')):
            if '://' not in link and not link.startswith('#'):
                target = (doc.parent / link.split('#')[0]).resolve()
                assert target.exists() or target == OUT / 'verification.json', (doc, link)
    source = ROOT / f'work/src/z6-qemu-{COMMIT}/qemu/nikon-z6.c'
    assert digest(source) == SOURCE_SHA
    files = sorted(p for p in OUT.rglob('*') if p.is_file() and p != OUT / 'verification.json') + scripts + docs
    report = dict(
        ok=True, firmware_hashes_unchanged=firmware, saved_runs=len(runs),
        event_counts={name: len(events[name]) for name in names},
        decoded_ranges_checked=checked_ranges,
        default_api_return=3, default_destination_flags='0x00010008',
        without_card_api_return=0, capture_service_state_after=3,
        exposure_completed=None, nef_generated=None,
        scope='Rechecks recorded artifacts, original firmware bytes, and file hashes. No new emulator run. Exposure, NEF output and RAW correction changes remain unverified.',
        qemu_source_sha256=SOURCE_SHA, recorded_qemu_binary_sha256=BINARY_SHA,
        assertions=['AF consumer transitions and native bit operations recorded',
                    'raw inhibit 0x24 excluded by participation mask',
                    'two default native requests rejected by destination check',
                    'observed bit 16 branch maps 0x00010008 to error 3',
                    'original without-card parameters accepted, state advanced to 3',
                    'physical key records and curated instruction bytes match firmware',
                    'script syntax, document links and five firmware hashes checked'],
        evidence=[dict(file=p.relative_to(ROOT).as_posix(), bytes=p.stat().st_size, sha256=digest(p)) for p in files],
    )
    (OUT / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('ok', 'saved_runs', 'event_counts', 'decoded_ranges_checked', 'without_card_api_return', 'capture_service_state_after')}, indent=2))
    print(f'Hashed {len(files)} evidence files; original firmware unchanged.')


if __name__ == '__main__':
    main()

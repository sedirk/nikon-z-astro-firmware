"""Recheck saved image-state/resource/event evidence against original C3.80."""
from pathlib import Path
from datetime import datetime, timezone
import ast
import hashlib
import json
import re
import struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/image-completion-2026-11-02'
BASE = 0x10020000
COMMIT = '419a1f2a91a1f2d3a0209027c29606475f7fe26f'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reg(event, index=0):
    return int(event['registers'][f'r{index}'], 16)


def word(data, offset):
    return struct.unpack_from('<I', bytes.fromhex(data), offset)[0]


def only(events, name):
    matches = [e for e in events if e['event'] == name]
    assert len(matches) == 1, (name, len(matches))
    return matches[0]


def main():
    assert __debug__, 'Run without -O.'
    previous = read(ROOT / 'analysis/capture-state-2026-11-02/verification.json')
    firmware = previous['firmware_hashes_unchanged']
    assert len(firmware) == 5
    assert firmware['firmware/decoded/eg1620_038000.bi'] == '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
    for name, expected in firmware.items():
        assert digest(ROOT / name) == expected, name
    blob = (ROOT / 'firmware/decoded/eg1620_038000.bi').read_bytes()
    runs, windows = {}, {}
    counts = {'producer-probe': 108, 'producer-focused-probe': 90, 'lower-probe': 103}
    for name, count in counts.items():
        r = runs[name] = read(OUT / name / 'result.json')
        events = read(OUT / name / 'events.json')
        es = windows[name] = [e for e in events if e['phase'] == 'native-capture-api']
        assert r['event_count'] == len(events) == count
        assert r['state_trace'] and r['completion_trace'] and r['firmware_unchanged']
        assert r['firmware_sha256'] == firmware['firmware/decoded/eg1620_038000.bi']
        assert r['upstream_commit'] == COMMIT
        api = r['native_capture_api']
        assert api['function'] == '0x101eedb4' and int(api['return_r0'], 16) == 0
        assert api['payload'] == '0000010000000000000000000000000001000000000000000000000000000000'
        actions = [json.loads(line) for line in (OUT / name / 'session/actions.jsonl').read_text(encoding='utf-8').splitlines()]
        boots = [a for a in actions if a['kind'] == 'boot']
        assert len(boots) == 1
        boot = boots[0]
        assert boot['guest_state_modified'] and not boot['firmware_modified'] and not boot['camera_access']
        assert boot['build']['binary_sha256'] == previous['recorded_qemu_binary_sha256']
        assert boot['build']['sources']['qemu/nikon-z6.c'] == previous['qemu_source_sha256']
        if name == 'producer-probe':
            # Incomplete instrumentation run: never count this as successful.
            assert not r['ok'] and 'after_settle' not in r
            assert 'AssertionError' in r['traceback'] and '0x101430d8' in r['error']
            continue
        assert r['ok']
        assert bytes.fromhex(r['baseline']['image_control_context'])[0x1a] == 0
        assert r['baseline']['active_frame_pointer'] == '0x0'
        event, store = only(es, 'image_state_event'), only(es, 'image_state_store')
        assert reg(event) == 0 and reg(event, 14) == 0x101413d9
        assert reg(store) == 4 and reg(store, 5) == 0xc18b7cc0
        assert bytes.fromhex(store['image_control_context'])[0x1a] == 0
        worker = only(es, 'image_state_worker')
        assert bytes.fromhex(worker['image_control_context'])[0x1a] == 4
        assert reg(only(es, 'image_state_allocate')) == 0  # 1013f4fa result
        chain = [event, store, only(es, 'image_state_worker_queue'), worker,
                 only(es, 'image_state_work_branch'), only(es, 'image_state_allocate'),
                 only(es, 'image_frame_allocated')]
        assert [es.index(e) for e in chain] == sorted(es.index(e) for e in chain)
        for key in ('after_api', 'after_settle'):
            state = r[key]
            assert bytes.fromhex(state['image_control_context'])[0x1a] == 4
            assert bytes.fromhex(state['capture_service_context'])[8] == 3
            assert bytes.fromhex(state['image_request_context'])[8] == 0
            assert word(state['image_service_context'], 0x4c) == 0
            assert word(state['image_service_context'], 0x24) == int(state['active_frame_pointer'], 16) != 0
            assert len(bytes.fromhex(state['active_frame'])) == 0x400
            assert word(state['active_frame'], 0x3a4) != 0
            assert int.from_bytes(bytes.fromhex(state['image_callback_slot_d']), 'little') == 0x101fe4c1
        assert r['after_api']['active_frame_pointer'] == r['after_settle']['active_frame_pointer']
        assert word(r['after_settle']['capture_sequence_context'], 0x14) == 0x100
        assert not any(e['event'] in ('controller_notify_d_gate', 'image_notify_d_normal',
            'image_notify_d_alternate', 'frame_completion_consumer', 'state3_cleanup') for e in es)
        assert not any(e['event'] == 'frame_callback' and reg(e) == 0x0415000d for e in es)
        assert all(len(c['result']['trace']) < 256 for c in r['calls'])

    r, es = runs['lower-probe'], windows['lower-probe']
    s = r['after_settle']
    chain = [only(es, name) for name in ('image_frame_allocated', 'frame_resource_init',
             'resource_first_result', 'frame_resource_ready', 'frame_resource_init_result')]
    assert [es.index(e) for e in chain] == sorted(es.index(e) for e in chain)
    assert reg(chain[1]) == int(s['active_frame_pointer'], 16)
    assert reg(chain[2]) == word(s['active_frame'], 0x1f8) != 0
    assert reg(chain[-1]) == 1  # raw 100c0362 result, before wrapper inverts it
    resource_offsets = (0x1f8, 0x220, 0x248, 0x270, 0x298, 0x2c0, 0x2e8)
    assert all(word(s['active_frame'], off) != 0 for off in resource_offsets)
    assert bytes.fromhex(s['frame_config_head'])[0x90] == word(s['frame_config_head'], 0x9c) == 0
    assert word(s['source_event_context'], 0x24) == 0x100714bb
    assert word(s['lower_controller_context'], 0x80 + 0x44) == 0x101430d5
    assert word(s['lower_controller_context'], 0x80 + 0x48) == 0x101474af
    assert not any(e['event'] in ('source_finish_entry', 'source_41f0004_emit',
        'source_41f0004_received', 'lower_notify_d_primary', 'lower_notify_d_secondary') for e in es)
    other = only(es, 'lower_frame_work')
    assert reg(other) != int(s['active_frame_pointer'], 16)
    assert word(other['frame_input'], 0) == 0xa2 and word(other['frame_input'], 0x28) == 0
    assert reg(only(es, 'lower_frame_check_result')) == 0

    curated = read(OUT / 'curated-evidence.json')
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    assert len(curated['ranges']) == 26
    instructions = {}
    for span in curated['ranges']:
        lo, hi = int(span['start'], 16), int(span['end'], 16)
        assert span['decoded_to_end'] and span['decoded_end'] == span['end']
        decoded = list(md.disasm(blob[lo - BASE:hi - BASE], lo))
        assert len(decoded) == len(span['instructions']) and decoded[-1].address + decoded[-1].size == hi
        for ins, row in zip(decoded, span['instructions']):
            instructions[ins.address] = row
            assert (hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str) == (row['pc'], row['bytes'], row['mnemonic'], row['operands'])
            if 'literal_address' in row:
                assert ins.mnemonic.startswith('ldr')
                assert struct.unpack_from('<I', blob, int(row['literal_address'], 16) - BASE)[0] == int(row['literal_value'], 16)
    # These table branches use PC+4, without the word alignment of LDR literals.
    tables = []
    for pc, size in ((0x1013fcda, 5), (0x101431a4, 16)):
        assert instructions[pc]['mnemonic'] == 'tbb' and 'literal_address' not in instructions[pc]
        address = pc + 4
        raw = blob[address - BASE:address - BASE + size]
        tables.append(dict(instruction=hex(pc), table_address=hex(address), bytes=raw.hex(),
                           targets=[hex(address + byte * 2) for byte in raw]))
    assert tables[0]['targets'] == ['0x1013fd68', '0x1013fdc0', '0x1013fd68', '0x1013fdc0', '0x1013fce4']
    assert tables[1]['targets'][0x0419000d - 0x0419000b] == '0x10143398'
    state_address = 0x114d4678
    rows = [list(blob[state_address - BASE + i * 14:state_address - BASE + (i + 1) * 14]) for i in range(5)]
    assert rows[0][0] == 4 and rows[4][1:4] == [5, 6, 0]
    table_report = dict(firmware_sha256=firmware['firmware/decoded/eg1620_038000.bi'],
        jump_tables=tables, state_table_address=hex(state_address), state_row_stride=14,
        state_rows_0_through_4=rows, ignored_transition_value=10,
        scope='Only the first five state-table rows are extracted. Numeric states are not assigned undocumented business names.')
    (OUT / 'decoded-tables.json').write_text(json.dumps(table_report, indent=2), encoding='utf-8')

    scripts = [ROOT / 'tools/fw' / n for n in ('qemu_inhibit_probe.py', 'inspect_native.py', 'verify_image_completion.py')]
    docs = [ROOT / n for n in ('README.md', 'docs/NEXT_STEPS.md', 'docs/CAPTURE_STATE_2026-11-02.md', 'docs/IMAGE_COMPLETION_2026-11-02.md')]
    for script in scripts:
        ast.parse(script.read_text(encoding='utf-8'))
    for doc in docs:
        for link in re.findall(r'\]\(([^)]+)\)', doc.read_text(encoding='utf-8')):
            if '://' not in link and not link.startswith('#'):
                target = (doc.parent / link.split('#')[0]).resolve()
                assert target.exists() or target == OUT / 'verification.json', (doc, link)
    source = ROOT / f'work/src/z6-qemu-{COMMIT}/qemu/nikon-z6.c'
    assert digest(source) == previous['qemu_source_sha256']
    files = sorted(p for p in OUT.rglob('*') if p.is_file() and p != OUT / 'verification.json') + scripts + docs
    report = dict(ok=True, generated_at_utc=datetime.now(timezone.utc).isoformat(),
        saved_runs=3, completed_diagnostics=2, incomplete_diagnostics=1,
        event_counts=counts, firmware_hashes_unchanged=firmware,
        decoded_ranges_checked=26, image_state_transition=[0, 4], capture_state=3, final_pending_mask='0x100',
        raw_resource_init_result=1, frame_resource_pointers={hex(off): hex(word(s['active_frame'], off)) for off in resource_offsets},
        static_event_chain=['0x041f0004', '0x0419000d', '0x0415000d'],
        event_chain_observed_end_to_end=False, exposure_completed=None, nef_generated=None,
        qemu_source_sha256=digest(source), recorded_qemu_binary_sha256=previous['recorded_qemu_binary_sha256'],
        scope='Offline check of saved synthetic-boot diagnostics and original firmware. The failed instrumentation run is retained, not counted as successful. Pointer initialization is not pixel or RAW-quality validation. Event absence applies only to observed windows.',
        evidence=[dict(file=p.relative_to(ROOT).as_posix(), bytes=p.stat().st_size, sha256=digest(p)) for p in files])
    (OUT / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('ok', 'saved_runs', 'completed_diagnostics', 'incomplete_diagnostics',
                     'event_counts', 'decoded_ranges_checked', 'final_pending_mask')}, indent=2))
    print(f'Hashed {len(files)} files; original firmware unchanged.')


if __name__ == '__main__':
    main()

"""Verify saved state/sequence/image-gate evidence without running an emulator."""
from pathlib import Path
import ast
import hashlib
import json
import re
import struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/capture-state-2026-11-02'
BASE = 0x10020000
COMMIT = '419a1f2a91a1f2d3a0209027c29606475f7fe26f'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reg(e, index=0):
    return int(e['registers'][f'r{index}'], 16)


def word(hex_data, offset):
    return struct.unpack_from('<I', bytes.fromhex(hex_data), offset)[0]


def only(events, name):
    rows = [e for e in events if e['event'] == name]
    assert len(rows) == 1, (name, len(rows))
    return rows[0]


def main():
    assert __debug__, 'Run without -O.'
    previous = read(ROOT / 'analysis/capture-inhibit-2026-11-02/verification.json')
    firmware = previous['firmware_hashes_unchanged']
    assert len(firmware) == 5
    assert firmware['firmware/decoded/eg1620_038000.bi'] == '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
    for name, expected in firmware.items():
        assert digest(ROOT / name) == expected, name
    blob = (ROOT / 'firmware/decoded/eg1620_038000.bi').read_bytes()
    runs, windows, all_events = {}, {}, {}
    names = ('state-probe', 'pending-probe', 'image-gate-probe')
    for name, count in zip(names, (58, 73, 142)):
        r = runs[name] = read(OUT / name / 'result.json')
        events = all_events[name] = read(OUT / name / 'events.json')
        es = windows[name] = [e for e in events if e['phase'] == 'native-capture-api']
        assert r['ok'] and r['firmware_unchanged'] and r['state_trace']
        assert r['firmware_sha256'] == firmware['firmware/decoded/eg1620_038000.bi']
        assert r['upstream_commit'] == COMMIT and r['event_count'] == len(events) == count
        api = r['native_capture_api']
        assert api['function'] == '0x101eedb4' and int(api['return_r0'], 16) == 0
        assert api['payload'] == '0000010000000000000000000000000001000000000000000000000000000000'
        assert [reg(e) for e in es if e['event'] == 'capture_state_set'] == [1, 2, 3]
        count_event, enter = only(es, 'count_update'), only(es, 'enter_state3')
        assert reg(count_event) == 1 and reg(count_event, 14) == 0x10200977
        assert word(count_event['capture_service_context'], 0x34) == 1
        assert word(count_event['capture_service_context'], 0x38) == 0
        assert word(enter['capture_service_context'], 0x38) == 1
        assert reg(enter) == 0 and es.index(count_event) < es.index(enter)
        assert bytes.fromhex(r['baseline']['capture_service_context'])[8] == 0
        for key in ('after_api', 'after_settle'):
            state = r[key]
            assert bytes.fromhex(state['capture_service_context'])[8] == 3
            assert word(state['capture_service_context'], 0x34) == word(state['capture_service_context'], 0x38) == 1
            seq = state['capture_sequence_context']
            assert word(seq, 4) == 0x10200df9 and word(seq, 8) == 0x200
            assert word(seq, 12) == 0x102009df and bytes.fromhex(seq)[16] == 4
        assert word(r['after_settle']['capture_sequence_context'], 0x14) == 0x100
        assert all(len(call['result']['trace']) < 256 for call in r['calls'])
        assert not any(e['event'] in ('completion_dispatch', 'state3_cleanup', 'frame_completion_consumer') for e in es)
        actions = [json.loads(line) for line in (OUT / name / 'session/actions.jsonl').read_text(encoding='utf-8').splitlines()]
        boot = [a for a in actions if a['kind'] == 'boot']
        assert len(boot) == 1
        boot = boot[0]
        assert boot['guest_state_modified'] and not boot['firmware_modified'] and not boot['camera_access']
        assert boot['build']['binary_sha256'] == previous['recorded_qemu_binary_sha256']
        assert boot['build']['sources']['qemu/nikon-z6.c'] == previous['qemu_source_sha256']

    for name in names[1:]:
        es = windows[name]
        assert reg(only(es, 'frame_submit_result')) == 0
        pending = [e for e in es if e['event'] == 'pending_stage_mask_result']
        assert [reg(e) for e in pending] == [0x120, 0x100]
        stores = [e for e in es if e['event'] == 'sequence_pending_store' and reg(e) == 0x100]
        assert len(stores) == 1 and reg(stores[0], 1) == 0x120
        resumed = [e for e in es if e['event'] == 'sequence_resume' and reg(e) == 0xc2376050 and reg(e, 2) == 0x20]
        assert len(resumed) == 1
        assert es.index(pending[0]) < es.index(resumed[0]) < es.index(pending[1])

    es = windows['image-gate-probe']
    submitted, worker = only(es, 'frame_submit'), only(es, 'frame_worker')
    request = bytes.fromhex(submitted['sequence_payload'])
    message = bytes.fromhex(worker['sequence_payload'])
    assert len(request) == 64 and len(message) == 72 and request == message[8:]
    assert reg(submitted, 1) == word(message.hex(), 4) == 0x101fe4c1
    assert reg(only(es, 'image_start_gate')) == 0x80
    assert reg(only(es, 'image_start_gate_result')) == 1
    chain = [submitted, worker, only(es, 'image_start_gate'), only(es, 'image_start_gate_result'),
             only(es, 'image_start'), only(es, 'image_start_inner')]
    assert [es.index(e) for e in chain] == sorted(es.index(e) for e in chain)
    assert int.from_bytes(bytes.fromhex(runs['image-gate-probe']['after_settle']['image_callback_slot_d']), 'little') == 0x101fe4c1
    assert not any(e['event'] == 'frame_callback' and reg(e) == 0x0415000d for e in es)
    assert not any(e['event'] in ('image_notify_d_normal', 'image_notify_d_alternate') for e in es)

    curated = read(OUT / 'curated-evidence.json')
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    assert len(curated['ranges']) == 19
    for span in curated['ranges']:
        lo, hi = int(span['start'], 16), int(span['end'], 16)
        assert span['decoded_to_end'] and span['decoded_end'] == span['end']
        decoded = list(md.disasm(blob[lo - BASE:hi - BASE], lo))
        assert len(decoded) == len(span['instructions']) and decoded[-1].address + decoded[-1].size == hi
        for ins, row in zip(decoded, span['instructions']):
            assert (hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str) == (row['pc'], row['bytes'], row['mnemonic'], row['operands'])
            if 'literal_address' in row:
                assert struct.unpack_from('<I', blob, int(row['literal_address'], 16) - BASE)[0] == int(row['literal_value'], 16)

    scripts = [ROOT / 'tools/fw' / n for n in ('qemu_inhibit_probe.py', 'inspect_native.py', 'verify_capture_state.py')]
    docs = [ROOT / n for n in ('README.md', 'docs/NEXT_STEPS.md', 'docs/CAPTURE_GATES_2026-11-02.md', 'docs/CAPTURE_STATE_2026-11-02.md')]
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
    report = dict(ok=True, firmware_hashes_unchanged=firmware, saved_runs=3,
        event_counts={n: len(all_events[n]) for n in names}, decoded_ranges_checked=19,
        state_transitions=[0, 1, 2, 3], pending_stage='0x200', pending_mask='0x100',
        expected_notification='0x0415000d', image_start_gate_passed=True,
        exposure_completed=None, nef_generated=None,
        qemu_source_sha256=digest(source), recorded_qemu_binary_sha256=previous['recorded_qemu_binary_sha256'],
        scope='Offline recheck of saved diagnostic runs and original firmware. No new emulation, camera test or RAW-quality validation. Missing events apply only to observed windows.',
        assertions=['native counter update precedes state 3', '0x20 dependency clears while 0x100 remains',
                    '64-byte request delivered intact to native worker', 'image-start gate passes and original start functions execute',
                    'completion slot remains registered; no completion event observed',
                    '19 instruction ranges, five firmware hashes, syntax and document links checked'],
        evidence=[dict(file=p.relative_to(ROOT).as_posix(), bytes=p.stat().st_size, sha256=digest(p)) for p in files])
    (OUT / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('ok', 'saved_runs', 'event_counts', 'decoded_ranges_checked', 'pending_mask', 'image_start_gate_passed')}, indent=2))
    print(f'Hashed {len(files)} files; original firmware unchanged.')


if __name__ == '__main__':
    main()

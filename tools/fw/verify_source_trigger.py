"""Offline verification of native finish notification and the next image request."""
from pathlib import Path
from datetime import datetime, timezone
import ast
import hashlib
import json
import re
import struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/source-trigger-2026-11-03'
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
    rows = [e for e in events if e['event'] == name]
    assert len(rows) == 1, (name, len(rows))
    return rows[0]


def main():
    assert __debug__, 'Run without -O.'
    previous = read(ROOT / 'analysis/image-completion-2026-11-02/verification.json')
    firmware = previous['firmware_hashes_unchanged']
    assert len(firmware) == 5
    assert firmware['firmware/decoded/eg1620_038000.bi'] == '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
    for name, expected in firmware.items():
        assert digest(ROOT / name) == expected, name
    blob = (ROOT / 'firmware/decoded/eg1620_038000.bi').read_bytes()
    counts = {'source-probe': 99, 'wait-probe': 141, 'next-stage-probe': 157, 'extended-probe': 156}
    wait_arguments = dict(zip(counts, (1000, 5000, 5000, 10000)))
    runs, windows, trace_maxima = {}, {}, {}
    for name, count in counts.items():
        r = runs[name] = read(OUT / name / 'result.json')
        events = read(OUT / name / 'events.json')
        es = windows[name] = [e for e in events if e['phase'] == 'native-capture-api']
        assert r['ok'] and r['firmware_unchanged'] and r['source_trace']
        assert r['event_count'] == len(events) == count
        assert r['upstream_commit'] == COMMIT
        assert r['firmware_sha256'] == firmware['firmware/decoded/eg1620_038000.bi']
        saved_script = OUT / name / 'probe-source.py'
        assert digest(saved_script) == r['probe_sha256']
        ast.parse(saved_script.read_text(encoding='utf-8'))
        calls = [c['result'] for c in r['calls']]
        assert [c['function'] for c in calls] == ['0x101efaa8', '0x101eedb4', '0x10170cca', '0x10170cca']
        assert calls[0]['arguments'] == ['0x1']
        assert calls[-1]['arguments'] == [hex(wait_arguments[name])]
        assert int(r['native_capture_api']['return_r0'], 16) == 0
        assert r['native_capture_api']['payload'] == '0000010000000000000000000000000001000000000000000000000000000000'
        assert all(c['kind'] == 'synthetic diagnostic input; not a controller protocol model' for c in calls)
        trace_maxima[name] = max(len(c['trace']) for c in calls)
        assert trace_maxima[name] < 256
        flags = [reg(e) for e in es if e['event'] == 'source_worker_flags']
        assert 1 in flags and only(es, 'source_start_worker')
        assert word(r['after_settle']['source_work_object'], 0x2c) == 0x101e26f1
        assert bytes.fromhex(r['after_settle']['source_work_object'])[24:30] == b'CAPSEQ'
        assert word(r['after_settle']['source_work_object'], 0x30) == 0x364fffff
        for key in ('baseline', 'after_api', 'after_settle'):
            assert r[key]['error_flags'] == '0x80' and r[key]['error_active'] == 0
        assert [reg(e) for e in es if e['event'] == 'capture_state_set'] == [1, 2, 3]
        assert bytes.fromhex(r['after_settle']['capture_service_context'])[8] == 3
        actions = [json.loads(line) for line in (OUT / name / 'session/actions.jsonl').read_text(encoding='utf-8').splitlines()]
        boots = [a for a in actions if a['kind'] == 'boot']
        assert len(boots) == 1
        boot = boots[0]
        assert boot['guest_state_modified'] and not boot['firmware_modified'] and not boot['camera_access']
        assert boot['build']['binary_sha256'] == previous['recorded_qemu_binary_sha256']
        assert boot['build']['sources']['qemu/nikon-z6.c'] == previous['qemu_source_sha256']
        assert any(a['kind'] == 'exmcu-capture-sync-test' for a in actions)
        if name == 'source-probe':
            assert 2 not in flags and 0x100 not in flags
            assert word(r['after_settle']['capture_sequence_context'], 0x14) == 0x100
            assert bytes.fromhex(r['after_settle']['image_control_context'])[0x1a] == 4
            assert not any(e['event'] == 'source_finish_entry' for e in es)
            continue

        # The device wait succeeds; the observed path does not force a timeout
        # or inject the software completion notification.
        wait = only(es, 'source_device_wait')
        assert [reg(wait, i) for i in (0, 1, 3)] == [0xc236d284, 4, 3000]
        assert reg(only(es, 'source_device_request_result')) == 1
        assert reg(only(es, 'source_device_wait_result')) == 1
        phases = [word(e['source_control_context'], 0x8c) for e in es if e['event'] == 'source_phase_dispatch']
        assert phases == [0, 1]
        assert reg(only(es, 'source_phase1_signal'), 1) == 2
        assert flags.count(2) == 1 and flags.count(0x100) == 2
        chain = [only(es, n) for n in ('source_start_worker', 'source_device_wait', 'source_device_wait_result',
            'source_start_schedule', 'source_phase_timer_callback', 'source_phase0', 'source_phase1',
            'source_phase1_signal', 'source_finish_selected', 'source_finish_entry',
            'source_41f0004_emit', 'source_41f0004_received', 'lower_notify_d_primary',
            'controller_notify_d_gate', 'image_notify_d_alternate', 'frame_completion_consumer')]
        assert [es.index(e) for e in chain] == sorted(es.index(e) for e in chain)
        assert reg(only(es, 'source_41f0004_emit'), 2) == 0x100714bb
        assert reg(only(es, 'source_41f0004_received'), 1) == 0x041f0004
        assert reg(only(es, 'lower_notify_d_primary'), 2) == 0x101430d5
        assert reg(only(es, 'controller_notify_d_gate')) == 0x0419000d
        callbacks = [e for e in es if e['event'] == 'frame_callback' and reg(e) == 0x0415000d]
        assert len(callbacks) == 1
        assert only(es, 'frame_completion_consumer')['completion_payload'] == '00'
        resume = [e for e in es if e['event'] == 'sequence_resume' and reg(e) == 0xc2376050 and reg(e, 2) == 0x100]
        assert len(resume) == 1
        cleared = [e for e in es if e['event'] == 'pending_stage_mask_result' and reg(e) == 0]
        assert len(cleared) == 1 and es.index(resume[0]) < es.index(cleared[0])
        assert [reg(e) for e in es if e['event'] == 'image_state_store'] == [4, 5, 6]
        state = r['after_settle']
        assert word(state['capture_sequence_context'], 8) == 0x800
        assert word(state['capture_sequence_context'], 12) == 0x1020072f
        assert word(state['capture_sequence_context'], 20) == 0x200
        assert bytes.fromhex(state['capture_sequence_context'])[16] == 4
        assert state['image_callback_slot_d'] == '00000000'
        assert not any(e['event'] in ('state3_cleanup', 'next_frame_completion_consumer') for e in es)

    for name in ('next-stage-probe', 'extended-probe'):
        es, r = windows[name], runs[name]
        submit, worker = only(es, 'next_frame_submit'), only(es, 'next_frame_worker')
        assert submit['next_payload'] == '0000000000000000'
        assert bytes.fromhex(worker['next_payload'])[8:] == bytes.fromhex(submit['next_payload'])
        assert word(worker['next_payload'], 4) == reg(submit, 1) == 0x101fe4c1
        assert reg(only(es, 'next_frame_submit_result')) == 0
        ready, process = only(es, 'next_frame_ready_check'), only(es, 'next_frame_process')
        assert word(ready['image_service_context'], 0x44) == 1
        assert es.index(submit) < es.index(worker) < es.index(ready) < es.index(process)
        lower, returned = only(es, 'next_frame_lower_submit'), only(es, 'next_frame_lower_return')
        assert len(bytes.fromhex(lower['next_payload'])) == 40
        assert word(lower['next_payload'], 0) == int(r['after_settle']['active_frame_pointer'], 16)
        assert es.index(process) < es.index(lower) < es.index(returned)
        assert reg(returned) == 0
        assert reg(only(es, 'next_pending_mask_result')) == 0x200
        assert word(r['after_settle']['image_callback_slots'], 0xe * 4) == 0x101fe4c1
    es = windows['extended-probe']
    assert not any(e['event'] in ('next_notify_producer', 'next_notify_wait', 'next_notify_wait_result', 'next_notify_emit') for e in es)

    curated = read(OUT / 'curated-evidence.json')
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    assert len(curated['ranges']) == 30
    for span in curated['ranges']:
        lo, hi = int(span['start'], 16), int(span['end'], 16)
        assert span['decoded_to_end']
        decoded = list(md.disasm(blob[lo - BASE:hi - BASE], lo))
        assert len(decoded) == len(span['instructions']) and decoded[-1].address + decoded[-1].size == hi
        for ins, row in zip(decoded, span['instructions']):
            assert (hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str) == (row['pc'], row['bytes'], row['mnemonic'], row['operands'])
            if 'literal_address' in row:
                assert ins.mnemonic.startswith('ldr')
                assert struct.unpack_from('<I', blob, int(row['literal_address'], 16) - BASE)[0] == int(row['literal_value'], 16)
    jump = 0x101fe540
    table = blob[jump - BASE:jump - BASE + 18]
    assert jump + 2 * table[1] == 0x101fe71c  # event 0415000e
    assert blob[0x114d4678 - BASE + 5 * 14 + 4] == 6
    scripts = [ROOT / 'tools/fw' / n for n in ('qemu_inhibit_probe.py', 'inspect_native.py', 'verify_source_trigger.py')]
    docs = [ROOT / n for n in ('README.md', 'docs/NEXT_STEPS.md', 'docs/IMAGE_COMPLETION_2026-11-02.md', 'docs/SOURCE_TRIGGER_2026-11-03.md')]
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
        saved_runs=4, event_counts=counts, wait_arguments=wait_arguments, max_trace_per_call=trace_maxima,
        firmware_hashes_unchanged=firmware, decoded_ranges_checked=30,
        native_notification_chain_observed_in=list(counts)[1:], old_pending_mask_cleared='0x100',
        current_stage='0x800', current_pending_mask='0x200', current_image_state=6,
        next_notification='0x0415000e', next_notification_observed=False,
        exposure_validated=False, raw_pixels_validated=False, nef_generated=None,
        qemu_source_sha256=digest(source), recorded_qemu_binary_sha256=previous['recorded_qemu_binary_sha256'],
        scope='Offline recheck of synthetic-boot diagnostic calls. Completion is native within that fixture, not proof of physical exposure or RAW quality. Observation points and scheduling differ across runs; this is not a precise latency measurement.',
        evidence=[dict(file=p.relative_to(ROOT).as_posix(), bytes=p.stat().st_size, sha256=digest(p)) for p in files])
    (OUT / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('ok', 'saved_runs', 'event_counts', 'decoded_ranges_checked',
                      'old_pending_mask_cleared', 'current_stage', 'current_pending_mask')}, indent=2))
    print(f'Hashed {len(files)} files; original firmware unchanged.')


if __name__ == '__main__':
    main()

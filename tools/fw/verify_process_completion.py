"""Recheck saved C3.80 frame-queue/readout evidence, including a failed observer run."""
from pathlib import Path
from datetime import datetime, timezone
import ast
import hashlib
import json
import re
import struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/process-completion-2026-11-03'
BASE = 0x10020000


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reg(event, n=0):
    return int(event['registers'][f'r{n}'], 16)


def word(data, offset):
    return struct.unpack_from('<I', bytes.fromhex(data), offset)[0]


def one(events, name):
    rows = [e for e in events if e['event'] == name]
    assert len(rows) == 1, (name, len(rows))
    return rows[0]


def main():
    assert __debug__, 'Run without -O.'
    previous = read(ROOT / 'analysis/source-trigger-2026-11-03/verification.json')
    firmware = previous['firmware_hashes_unchanged']
    assert len(firmware) == 5
    for name, expected in firmware.items():
        assert digest(ROOT / name) == expected, name
    runs, windows, results = {}, {}, {}
    for name in ('process-probe', 'readout-probe', 'readout-complete-probe', 'timer-probe'):
        r = runs[name] = read(OUT / name / 'result.json')
        events = read(OUT / name / 'events.json')
        es = windows[name] = [e for e in events if e['phase'] == 'native-capture-api']
        assert r['firmware_unchanged'] and r['process_trace']
        assert r['event_count'] == len(events)
        assert r['firmware_sha256'] == firmware['firmware/decoded/eg1620_038000.bi']
        assert r['upstream_commit'] == '419a1f2a91a1f2d3a0209027c29606475f7fe26f'
        script = OUT / name / 'probe-source.py'
        assert digest(script) == r['probe_sha256']
        ast.parse(script.read_text(encoding='utf-8'))
        calls = [c['result'] for c in r['calls']]
        expected_calls = ['0x101efaa8', '0x101eedb4', '0x10170cca']
        if name != 'readout-probe':
            assert r['ok'], (name, r.get('error'))
            expected_calls.append('0x10170cca')
            assert int(calls[-1]['arguments'][0], 16) == r['arguments']['settle_ticks']
        else:
            assert not r['ok'] and r['error'] == 'timed out'
            assert 'TimeoutError' in r['traceback'] and 'remote.receive()' in r['traceback']
            assert 'after_settle' not in r and 'final' not in r
        assert [c['function'] for c in calls] == expected_calls
        assert calls[0]['arguments'] == ['0x1']
        assert int(r['native_capture_api']['return_r0'], 16) == 0
        assert r['native_capture_api']['payload'] == '0000010000000000000000000000000001000000000000000000000000000000'
        assert all(c['kind'] == 'synthetic diagnostic input; not a controller protocol model' for c in calls)
        assert max(len(c['trace']) for c in calls) < 256
        actions = [json.loads(line) for line in (OUT / name / 'session/actions.jsonl').read_text(encoding='utf-8').splitlines()]
        boots = [a for a in actions if a['kind'] == 'boot']
        assert len(boots) == 1
        boot = boots[0]
        assert boot['guest_state_modified'] and not boot['firmware_modified'] and not boot['camera_access']
        assert boot['build']['binary_sha256'] == previous['recorded_qemu_binary_sha256']
        assert boot['build']['sources']['qemu/nikon-z6.c'] == previous['qemu_source_sha256']
        assert any(a['kind'] == 'exmcu-capture-sync-test' for a in actions)

        # The second request really reaches and appends its frame to FRONTEND.
        lower = one(es, 'next_frame_lower_submit')
        before, after = one(es, 'frame_queue_append'), one(es, 'frame_queue_appended')
        returned = one(es, 'next_frame_lower_return')
        frame = word(lower['next_payload'], 0)
        assert reg(before) == 0xc2528d40 and reg(before, 1) == frame
        assert word(before['lower_frame_queue'], 0x18) == 0
        assert word(after['lower_frame_queue'], 0x18) == 1
        assert word(returned['lower_controller_context'], 0x9c) == 0x1f
        assert reg(returned) == 0
        assert es.index(lower) < es.index(before) < es.index(after) < es.index(returned)
        assert [reg(e) for e in es if e['event'] == 'image_state_store'] == [4, 5, 6]
        assert reg(one(es, 'next_pending_mask_result')) == 0x200
        assert not any(e['event'] in ('frame_dependency_clear', 'image_finish_worker',
            'image_finish_select', 'next_notify_producer', 'next_frame_completion_consumer') for e in es)
        state = r.get('final', es[-1])
        assert word(state['capture_sequence_context'], 8) == 0x800
        assert word(state['capture_sequence_context'], 0x14) == 0x200
        assert word(state['lower_controller_context'], 0x9c) == 0x1f
        assert word(state['lower_frame_queue'], 0x18) == 1
        assert bytes.fromhex(state['image_control_context'])[0x1a] == 6
        assert word(state['lower_controller_context'], 0xc4) == 0x101430d5
        assert word(state['lower_controller_context'], 0xc8) == 0x101474af
        for key in ('baseline', 'after_api', 'after_settle', 'final'):
            if key in r:
                assert r[key]['error_flags'] == '0x80' and r[key]['error_active'] == 0
        results[name] = dict(ok=r['ok'], events=len(events),
            final_snapshot_available='final' in r,
            settle_argument=r['arguments']['settle_ticks'],
            max_trace_in_completed_calls=max(len(c['trace']) for c in calls))

    for name in ('readout-probe', 'readout-complete-probe', 'timer-probe'):
        es = windows[name]
        assert runs[name]['readout_trace']
        assert reg(one(es, 'source_readout_policy_result')) == 0
        assert reg(one(es, 'readout_command_policy_result')) == 0
        request = bytes.fromhex(one(es, 'readout_normal_entry')['source_extended_request'])
        assert request[0xec] == 1 and request[0xb6] == 0 and request[0xb7] == 0
        chain = []
        for label, obj, mask in (('readout_wait8', 0xc236d284, 8),
                                ('readout_wait1', 0xc236d284, 1),
                                ('readout_sync_wait1', 0xc236d290, 1)):
            start, end = one(es, label), one(es, label + '_return')
            assert [reg(start, i) for i in (0, 1, 2, 3)] == [obj, mask, 0, 3000]
            assert reg(end) == 1  # Original wrapper maps lower OS result 0 to 1.
            chain.extend((es.index(start), es.index(end)))
        assert chain == sorted(chain)
        submit, done = one(es, 'readout_finish_submit'), one(es, 'readout_normal_return')
        assert chain[-1] < es.index(submit) < es.index(done)
        assert bytes.fromhex(done['source_control_context'])[0] == 5
        assert not any(e['event'] in ('readout_timer_wait', 'readout_command_submit',
            'readout_command_short_submit', 'special_readout_wait') for e in es)

    for name in ('readout-complete-probe', 'timer-probe'):
        es = windows[name]
        begin, end = one(es, 'sensor_finish_device_call'), one(es, 'sensor_finish_device_return')
        assert es.index(begin) < es.index(end) and reg(end) == 0
        assert bytes.fromhex(end['sensor_control_context'])[0] == 0xf
        assert bytes.fromhex(end['sensor_control_context'])[7] == 0
        assert not any(e['event'] in ('source_event5_producer', 'source_event5_emit') for e in es)
        assert word(runs[name]['final']['sensor_work_object'], 0x2c) == 0x100f4cc3
        assert bytes.fromhex(runs[name]['final']['sensor_work_object'])[24:29] == b'CAPTG'

    # Recover the clock selector from the actual argument structure, rather
    # than assuming that a successful submission means a clock was emulated.
    es, r = windows['timer-probe'], runs['timer-probe']
    assert r['timer_trace'] and r['arguments']['rsp_timeout'] == 180
    assert reg(one(es, 'sensor_finish_op0_return')) == 0
    assert reg(one(es, 'sensor_finish_op1_return')) == 0
    submits = [e for e in es if e['event'] == 'sensor_timer_submit' and reg(e) == 0xc18b7938]
    assert len(submits) == 1
    submit = submits[0]
    assert [reg(submit, i) for i in (2, 3, 14)] == [0, 0, 0x101931ff]
    configs = [e for e in es if e['event'] == 'sensor_timer_configure' and reg(e) == 8]
    assert len(configs) == 1
    configure = configs[0]
    assert reg(configure, 1) == 0xc18b793c and reg(configure, 4) == 0xc18b7938
    obj_offset = 0xc18b7938 - 0xc18b7808
    b = configure['sensor_timing_context']
    assert word(b, obj_offset + 4) == 1  # custom-config branch of 1010ecae
    assert word(b, obj_offset + 8) == 0
    assert word(b, obj_offset + 12) == 0  # byte passed to low-level clock selector
    assert word(b, obj_offset + 0x10) == 0xffffffff
    assert word(b, obj_offset + 0x14) == 0xfffffffe
    assert word(b, obj_offset + 0x34) == 0x10193181
    assert word(b, obj_offset + 0x38) == 1
    started = [e for e in es if e['event'] == 'sensor_timer_started' and reg(e, 4) == 0xc18b7938]
    assert len(started) == 1 and reg(started[0]) == 0
    assert reg(one(es, 'sensor_finish_timer_return')) == 0
    assert not any(e['event'] in ('sensor_finish_timer_callback', 'sensor_finish_callback_mask',
        'sensor_finish_hw_request') for e in es)
    assert word(r['final']['sensor_timing_context'], obj_offset + 0x30) == 1
    assert word(r['final']['sensor_timing_context'], obj_offset + 0x34) == 0x10193181
    qlog = (OUT / 'timer-probe/session/qemu-1.log').read_text(encoding='utf-8')
    assert qlog.count('Z6_CHANNEL_PRESET channel=8 value=0xfffffffe') == 1
    assert 'Z6_COUNTER_START channel=8 ' not in qlog
    assert 'Z6_COUNTER_TERMINAL channel=8 ' not in qlog

    blob = (ROOT / 'firmware/decoded/eg1620_038000.bi').read_bytes()
    curated = read(OUT / 'curated-evidence.json')
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    assert len(curated['ranges']) == 49
    for span in curated['ranges']:
        lo, hi = int(span['start'], 16), int(span['end'], 16)
        assert span['decoded_to_end']
        decoded = list(md.disasm(blob[lo-BASE:hi-BASE], lo))
        assert decoded[-1].address + decoded[-1].size == hi
        assert len(decoded) == len(span['instructions'])
        for ins, row in zip(decoded, span['instructions']):
            assert (hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str) == (row['pc'], row['bytes'], row['mnemonic'], row['operands'])
            if 'literal_address' in row:
                assert ins.mnemonic.startswith('ldr')
                assert struct.unpack_from('<I', blob, int(row['literal_address'], 16)-BASE)[0] == int(row['literal_value'], 16)
    scripts = [ROOT / 'tools/fw' / n for n in ('qemu_inhibit_probe.py', 'inspect_native.py', 'verify_process_completion.py')]
    docs = [ROOT / n for n in ('README.md', 'docs/NEXT_STEPS.md', 'docs/PROCESS_COMPLETION_2026-11-03.md')]
    for script in scripts:
        ast.parse(script.read_text(encoding='utf-8'))
    for doc in docs:
        for link in re.findall(r'\]\(([^)]+)\)', doc.read_text(encoding='utf-8')):
            if '://' not in link and not link.startswith('#'):
                target = (doc.parent / link.split('#')[0]).resolve()
                assert target.exists() or target == OUT / 'verification.json', (doc, link)
    source = ROOT / 'work/src/z6-qemu-419a1f2a91a1f2d3a0209027c29606475f7fe26f/qemu/nikon-z6.c'
    assert digest(source) == previous['qemu_source_sha256']
    model = source.read_text(encoding='utf-8')
    assert 'if ((*value & (1U << ch)) && s->channel_config[ch][1][1] == 0x31)' in model
    assert 'other clock selectors remain unclocked' in model
    files = sorted(p for p in OUT.rglob('*') if p.is_file() and p != OUT / 'verification.json') + scripts + docs
    report = dict(ok=True, generated_at_utc=datetime.now(timezone.utc).isoformat(),
        runs=results, firmware_hashes_unchanged=firmware, decoded_ranges_checked=len(curated['ranges']),
        current_stage='0x800', current_pending_mask='0x200', frontend_dependency_mask='0x1f',
        frontend_queue_count=1, image_state=6, readout_waits_succeeded=True,
        timer_gap=dict(logical_timer_id=8, object='0xc18b7938', selector=0,
            callback='0x10193181', callback_observed=False, modeled_clock_selector='0x31',
            counter_preset='0xfffffffe', start_log_observed=False,
            interpretation='Observed native configuration selects an unclocked mode in the pinned QEMU source. Causal sufficiency for clearing 0x200 still requires a separate model A/B experiment.',
            model_modified=False),
        next_notification_observed=False, exposure_validated=False, raw_pixels_validated=False,
        qemu_source_sha256=digest(source), recorded_qemu_binary_sha256=previous['recorded_qemu_binary_sha256'],
        scope='Local synthetic boot and native diagnostic API. The failed observer run has no final snapshot; only saved events before its host socket timeout are checked. No forced completion, no physical exposure/RAW-quality result.',
        evidence=[dict(file=p.relative_to(ROOT).as_posix(), bytes=p.stat().st_size, sha256=digest(p)) for p in files])
    (OUT / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('ok', 'runs', 'decoded_ranges_checked',
        'current_pending_mask', 'frontend_dependency_mask')}, indent=2))
    print(f'Hashed {len(files)} files; original firmware unchanged.')


if __name__ == '__main__':
    main()

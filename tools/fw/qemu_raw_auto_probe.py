"""Bounded automatic-parameter and cache observations; no added hardware or pixel algorithm.

Uses the pinned upstream synthetic boot and a native CaptureWithoutCard request.
Optional cache experiment changes declared guest RAM in this disposable session.
No firmware code change, completion injection or physical camera access.
"""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import struct
import sys
import traceback

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--repo', type=Path, required=True)
p.add_argument('--firmware', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--settle-ticks', type=int, default=5000)
p.add_argument('--cache-experiment', action='store_true')
p.add_argument('--auto-crosscheck', type=Path)
a = p.parse_args()
assert 1 <= a.settle_ticks <= 10000
a.output.mkdir(parents=True, exist_ok=False)
source = Path(__file__).read_bytes()
(a.output / 'probe-source.py').write_bytes(source)
sys.path.insert(0, str(a.repo / 'tools'))
import interactive as ui
import probe

ui.FIRMWARE = a.firmware.resolve(strict=True)
ui.BUILD_MANIFEST = a.repo / '.local/build-manifest.json'
digest = ui.checked_firmware(ui.FIRMWARE)
camera = ui.Camera(8787, profile='shooting', capture_control_test=True,
                   raw_source=ui.active_manifest('native0'), exmcu_no_lens=True,
                   tg_periodic_test=True, tg_paired_test=True,
                   raw_ingress_test=ui.active_ingress(), isp_boundary_test=True,
                   orientation_fixture=0, keep_awake=True, photo_liveview=True,
                   firmware_sha256=digest)
camera.exposure_probe = True
camera.isp_disable_cache = False
camera.tg_period_ms = None
points = {
    0x101149b4: 'context_initialize', 0x101149f8: 'context_initialized',
    0x10114aca: 'outer_parameters_entry', 0x10114b1e: 'outer_parameters_result',
    0x1011457e: 'external_input_fallback', 0x101145a8: 'automatic_inputs_ready',
    0x10114136: 'signed_parameter_entry', 0x10114164: 'signed_parameter_return',
    0x1011308c: 'automatic_parameter_entry', 0x101132c8: 'automatic_parameter_return',
    0x1011300e: 'polynomial_entry', 0x10113084: 'polynomial_result',
    0x101b2a9a: 'external_coefficients', 0x101b2b14: 'external_scaling_flag',
    0x10186484: 'coefficient_provider_1', 0x101c1266: 'coefficient_provider_3',
    0x10076a08: 'still_lower_submit', 0x10114bb2: 'reused_parameters_entry',
    0x10114cc4: 'reused_parameters_return',
}
events = []
phase = 'synthetic-boot'
original = ui.call_fixture


def capture_memory(remote, label, address, size):
    if not address:
        return dict(address='0x0', skipped='null')
    blob = remote.memory(address, size)
    return dict(address=hex(address), size=size, bytes=blob.hex(),
                sha256=hashlib.sha256(blob).hexdigest())


def snapshot():
    remote = camera.remote
    state = {'parameter_context': capture_memory(remote, '', 0xc1884918, 0xa0),
             'config_290_29f': capture_memory(remote, '', 0xc20aaa58, 16),
             'external_context': capture_memory(remote, '', 0xc18844e8, 0x100),
             'cached_parameters': capture_memory(remote, '', 0xc1884d70, 0xac + 3 * 0x13),
             'mode_scale_bytes': capture_memory(remote, '', 0xc1884d53, 9),
             'capture_sequence': capture_memory(remote, '', 0xc2376050, 0x100)}
    context = bytes.fromhex(state['parameter_context']['bytes'])
    for off in (0x24, 0x30, 0x34, 0x38, 0x40):
        pointer = struct.unpack_from('<I', context, off)[0]
        state[f'parameter_pointer_{off:x}'] = capture_memory(remote, '', pointer, 0x300)
    return state


def observed(*args, **kwargs):
    def observe(remote, regs):
        pc = int(regs['r15'], 16)
        row = dict(phase=phase, event=points[pc], outer_call=hex(args[2]), registers=regs, memory={})
        events.append(row)  # Preserve a partially observed event if a read fails.
        areas = {'context': (0xc1884918, 0xa0), 'external_context': (0xc18844e8, 16)}
        ri = lambda n: int(regs[f'r{n}'], 16)
        if pc in (0x1011308c, 0x10114136) and ri(0) and ri(2):
            areas['automatic_inputs'] = (ri(2), 16)
            areas['request'] = (ri(0), 0x20)
            request = remote.memory(ri(0), 4)
            frame = struct.unpack('<I', request)[0]
            areas['frame_header'] = (frame, 0x138)
            frame_config = struct.unpack('<I', remote.memory(frame + 0x130, 4))[0]
            areas['frame_config'] = (frame_config, 0x580)
        if pc == 0x101145a8:
            areas['automatic_inputs'] = (ri(13) + 0x18, 16)
        if pc == 0x1011300e:
            areas['polynomial_coefficients'] = (ri(1), 12)
        if pc == 0x10113084:
            row['polynomial_output'] = regs['r0']
            row['polynomial_output_address'] = regs['r11']
        if pc in (0x10114136, 0x10114164, 0x10114b1e, 0x10114cc4):
            areas['parameters'] = (ri(3) if pc == 0x10114136 else ri(4), 0xac)
        if pc == 0x10114bb2:
            areas['reuse_input'] = (ri(0), 0x14)
        if pc in (0x10114136, 0x1011308c, 0x101132c8, 0x10114164):
            context = remote.memory(0xc1884918, 0xa0)
            for off in (0x24, 0x34):
                pointer = struct.unpack_from('<I', context, off)[0]
                areas[f'parameter_pointer_{off:x}'] = (pointer, 0x300)
        if pc == 0x101132c8:
            row['automatic_result_before_mov'] = regs['r9']
        for label, (address, size) in areas.items():
            row['memory'][label] = capture_memory(remote, label, address, size)
    observers = dict(kwargs.get('observers') or {})
    observers.update({pc: observe for pc in points})
    kwargs['observers'] = observers
    return original(*args, **kwargs)


ui.call_fixture = observed
report = dict(ok=False, firmware_sha256=digest, probe_sha256=hashlib.sha256(source).hexdigest(),
              upstream_commit='419a1f2a91a1f2d3a0209027c29606475f7fe26f', calls=[],
              points={hex(k): v for k, v in points.items()},
              arguments={k: str(v) if isinstance(v, Path) else v for k, v in vars(a).items()},
              scope='One hit per breakpoint per call_fixture; no repeated breakpoints requested. '
                    'External input and cached-parameter observations on pinned synthetic boot only; '
                    'no physical calibration, pixel calculation, NEF output or camera validation. '
                    'Upstream boot retains 0x29e=1 and sensor-pointer fallback. '
                    'Optional cache/scalar experiments change declared guest RAM, restoring explicit writes; '
                    'native function side effects are discarded with the session.')


def invoke(function, payload, arguments):
    global packet
    result = ui.call_fixture(camera.remote, packet, function, payload, arguments)
    packet = 'T05thread:' + result['return_cpu'] + ';'
    report['calls'].append(dict(phase=phase, function=hex(function), result=result))
    return result


def write_memory(address, data):
    assert camera.remote.command(f'M{address:x},{len(data):x}:' + data.hex()) == 'OK'


def cache_experiment():
    global phase
    phase = 'synthetic-cache-reuse'
    remote = camera.remote
    originals = {0xc1884934: remote.memory(0xc1884934, 4),
                 0xc20aaa64: remote.memory(0xc20aaa64, 1)}
    report['cache_experiment'] = dict(cases=[], explicit_restoration=False,
        scope='Direct native reuse calls with synthetic cached values and configuration byte. '
              'Not a physical capture, valid calibration, or pixel correction test.',
        original_memory={hex(k): v.hex() for k, v in originals.items()})
    result = report['cache_experiment']
    requests = [e for e in events if e['phase'] == 'native-settle' and e['event'] == 'reused_parameters_entry']
    assert len(requests) == 1
    request = bytes.fromhex(requests[0]['memory']['reuse_input']['bytes'])
    result['request_template'] = request.hex()
    try:
        for flag in (0, 1):
            for cached in (0x155, 0x3ff):
                for selector in (0, 1, 2):
                    payload = bytearray(b'Z' * 0x110)
                    payload[:len(request)] = request
                    payload[0x10] = selector
                    write_memory(0xc1884934, struct.pack('<I', cached))
                    write_memory(0xc20aaa64, bytes([flag]))
                    call = invoke(0x10114bb2, payload, [('scratch', 0), ('scratch', 0x40)])
                    output = bytes.fromhex(call['output'])
                    params = output[0x40:0x40 + 0xac]
                    slots = list(struct.unpack_from('<4H', params, 0x62))
                    expected = [0] * 4
                    expected[selector] = cached
                    row = dict(config_29c=flag, cached_input=cached, selector=selector,
                               parameters=params.hex(), slots=slots, call=call,
                               cache_after=remote.memory(0xc1884934, 4).hex(),
                               config_after=remote.memory(0xc20aaa64, 1).hex(),
                               guards_unchanged=output[0x20:0x40] == b'Z' * 32 and
                                               output[0xec:] == b'Z' * (0x110 - 0xec))
                    result['cases'].append(row)
                    assert int(call['return_r0'], 16) == 0
                    assert slots == expected and row['guards_unchanged']
                    assert row['cache_after'] == struct.pack('<I', cached).hex()
                    assert row['config_after'] == bytes([flag]).hex()
        # Refresh through the original disabled-parameter branch, then reuse.
        phase = 'synthetic-cache-refresh'
        write_memory(0xc1884934, struct.pack('<I', 0x155))
        write_memory(0xc20aaa64, b'\x01')
        payload = b'Z' * 0xd0
        # Flag=1 returns before dereferencing r0/r2; observe only output/context.
        refresh = invoke(0x10114136, payload, [0, 0, 0, ('scratch', 0)])
        result['refresh_call'] = refresh
        result['cache_after_refresh'] = remote.memory(0xc1884934, 4).hex()
        assert result['cache_after_refresh'] == '00000000'
        payload = bytearray(b'Z' * 0x110)
        payload[:len(request)] = request
        reused = invoke(0x10114bb2, payload, [('scratch', 0), ('scratch', 0x40)])
        result['reuse_after_refresh'] = reused
        assert bytes.fromhex(reused['output'])[0xa2:0xaa] == bytes(8)
    finally:
        for address, data in originals.items():
            write_memory(address, data)
        result['explicit_restoration'] = all(remote.memory(k, len(v)) == v for k, v in originals.items())
        assert result['explicit_restoration']


def auto_crosscheck():
    global phase
    phase = 'synthetic-auto-crosscheck'
    expected = json.loads(a.auto_crosscheck.read_text(encoding='utf-8'))
    assert expected['ok'] and expected['firmware_sha256'] == digest
    result = report['auto_crosscheck'] = dict(polynomial_cases=[], automatic_cases=[],
        expected_report_sha256=hashlib.sha256(a.auto_crosscheck.read_bytes()).hexdigest(),
        scope='Synthetic calibration/scalars, original firmware code, comparing with Unicorn; not pixel validation.',
        explicit_restoration=False)
    remote = camera.remote
    originals = {}

    def change(address, data):
        if address not in originals:
            originals[address] = remote.memory(address, len(data))
        write_memory(address, data)

    try:
        cases = [c for c in expected['polynomial_cases'] if c['x'] == 1000000]
        for case in cases:
            payload = bytearray(b'Z' * 0x50)
            struct.pack_into('<3i', payload, 0, *case['coefficients'])
            call = invoke(0x1011300e, payload, [case['x'], ('scratch', 0), ('scratch', 0x20)])
            actual = struct.unpack_from('<i', bytes.fromhex(call['output']), 0x20)[0]
            result['polynomial_cases'].append(dict(expected=case, call=call, actual=actual))
            assert actual == case['output']
        native = next(e for e in reversed(events) if e['event'] == 'automatic_parameter_entry'
                      and e['phase'] != phase)
        frame = struct.unpack_from('<I', bytes.fromhex(native['memory']['request']['bytes']))[0]
        frame_config = struct.unpack('<I', remote.memory(frame + 0x130, 4))[0]
        assert frame_config == int(native['memory']['frame_config']['address'], 16)
        cal = struct.unpack('<I', remote.memory(0xc188494c, 4))[0]
        changes = {0xc18844e8: 0}
        for offset, value in ((0x154, 4096), (0x1b8, 16), (0x1bc, 500), (0x1c0, 1000),
                              (0x1ac, 8000), (0x1b0, 15872), (0x1b4, 30000)):
            changes[cal + offset] = value
        for address, value in changes.items():
            change(address, struct.pack('<I', value))
        result['synthetic_calibration_writes'] = {hex(k): hex(v) for k, v in changes.items()}
        selected = {(128, 0, 0), (128, 2, 5), (512, 2, 0), (2048, 0, 5), (128, 1, 0), (512, 0, 9)}
        for case in expected['automatic_cases']:
            key = case['strength'], case['selector'], case['mode']
            if key not in selected:
                continue
            change(frame_config + 0x54, bytes([case['selector']]))
            payload = bytearray(0x40)
            struct.pack_into('<I', payload, 0, frame)
            struct.pack_into('<4i', payload, 0x20, case['strength'], *case['coefficients'])
            call = invoke(0x1011308c, payload, [('scratch', 0), case['mode'], ('scratch', 0x20)])
            actual = struct.unpack('<i', struct.pack('<I', int(call['return_r0'], 16)))[0]
            result['automatic_cases'].append(dict(expected=case, call=call, actual=actual))
            assert actual == case['automatic_call']['returned_signed'], (key, actual)
        assert len(result['automatic_cases']) == 6 and len(result['polynomial_cases']) == 4
    finally:
        result['original_memory'] = {hex(k): v.hex() for k, v in originals.items()}
        for address, data in originals.items():
            write_memory(address, data)
        result['explicit_restoration'] = all(remote.memory(k, len(v)) == v for k, v in originals.items())
        assert result['explicit_restoration']


try:
    print('BOOT', flush=True)
    camera.boot_shooting()
    camera.pause()
    packet = camera.run_to(0x100531bc)
    report['baseline'] = snapshot()
    print('BASELINE', len(events), flush=True)
    phase = 'native-without-card'
    invoke(0x101efaa8, bytes(8), [1])
    payload = bytearray(32)
    payload[2] = 1
    struct.pack_into('<I', payload, 0x10, 1)
    result = invoke(0x101eedb4, payload, [('scratch', 0), 0x10524b7f])
    print('API', result['return_r0'], flush=True)
    assert int(result['return_r0'], 16) == 0
    invoke(0x10170cca, bytes(8), [100])
    phase = 'native-settle'
    camera.remote.sock.settimeout(90)
    invoke(0x10170cca, bytes(8), [a.settle_ticks])
    report['final'] = snapshot()
    if a.cache_experiment:
        cache_experiment()
    if a.auto_crosscheck:
        auto_crosscheck()
    report['ok'] = True
except Exception as exc:
    report.update(error=str(exc), traceback=traceback.format_exc())
    print(report['traceback'], flush=True)
finally:
    camera.close_guest()
    report['firmware_unchanged'] = hashlib.sha256(ui.FIRMWARE.read_bytes()).hexdigest() == digest
    report['event_count'] = len(events)
    (a.output / 'events.json').write_text(json.dumps(events, indent=2), encoding='utf-8')
    (a.output / 'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    shutil.copytree(camera.directory, a.output / 'session')
    print('SAVED', report['ok'], len(events), flush=True)
sys.exit(0 if report['ok'] else 1)

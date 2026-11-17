"""Bounded parameter-path observations; no added hardware or pixel algorithm.

Uses the pinned upstream synthetic boot and a native CaptureWithoutCard request.
Does not change configuration after boot, force completion, or access a camera.
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
    0x10114136: 'signed_parameter_entry', 0x10114164: 'signed_parameter_return',
    0x1011424a: 'three_table_selector_entry', 0x101142dc: 'three_table_selector_return',
    0x101142de: 'parameter_builder_entry', 0x101146ec: 'parameter_builder_return',
    0x101146f4: 'alternate_parameter_builder', 0x10114cd4: 'indexed_parameter_entry',
    0x10114b1e: 'outer_parameter_result',
    0x1011d5aa: 'resource_b_parameter_builder', 0x1011d548: 'sensor_parameters_dispatch',
    0x100bc4a6: 'sparse_list_group', 0x1010b9fe: 'sparse_list_pointer_write',
    0x10076a08: 'still_lower_submit', 0x101eedb4: 'native_capture_entry',
    0x100a2098: 'reused_parameters_wrapper', 0x10114bb2: 'reused_parameters_entry',
    0x10114cc4: 'reused_parameters_return',
    0x100bed06: 'parameter_field_mapper', 0x100bf0f4: 'parameter_field_mapper_return',
    0x100d8582: 'packed_register_submit', 0x1010b958: 'signed_pair_register_write',
}
probe.TRACE_REPEAT = set(probe.TRACE_REPEAT) | {0x1010b958}
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
             'sensor_context': capture_memory(remote, '', 0xc18fa954, 0x100),
             'config_290_29f': capture_memory(remote, '', 0xc20aaa58, 16),
             'data_directory': capture_memory(remote, '', 0xc1880c78, 0x700),
             'capture_sequence': capture_memory(remote, '', 0xc2376050, 0x100)}
    context = bytes.fromhex(state['parameter_context']['bytes'])
    for off in (0x30, 0x34, 0x38, 0x3c, 0x40):
        pointer = struct.unpack_from('<I', context, off)[0]
        state[f'parameter_pointer_{off:x}'] = capture_memory(remote, '', pointer, 0x300)
    return state


def observed(*args, **kwargs):
    def observe(remote, regs):
        pc = int(regs['r15'], 16)
        row = dict(phase=phase, event=points[pc], outer_call=hex(args[2]), registers=regs, memory={})
        events.append(row)  # Preserve a partially observed event if a read fails.
        areas = {'context': (0xc1884918, 0xa0)}
        if pc in (0x10114136, 0x10114164, 0x101146ec, 0x10114b1e, 0x10114cc4):
            reg = 'r3' if pc == 0x10114136 else 'r4'
            areas['parameters'] = (int(regs[reg], 16), 0xac)
        if pc == 0x101142dc:
            areas['selector_output'] = (int(regs['r2'], 16), 0x30)
        if pc == 0x101142de:
            areas['builder_input'] = (int(regs['r0'], 16), 0x30)
        if pc == 0x100bc4a6:
            areas['list_request'] = (int(regs['r8'], 16), 0x30)
        if pc == 0x1010b9fe:
            areas['list_parameters'] = (int(regs['r1'], 16), 0x38)
            row['mmio_write'] = dict(address=hex(int(regs['r0'], 16) + 0x3e0), value=regs['r2'])
        if pc == 0x10076a08:
            areas['still_submit'] = (int(regs['r0'], 16), 40)
        if pc == 0x1011d548:
            areas['sensor_parameters'] = (0xc29a34c0, 0x60)
        if pc == 0x100bed06:
            areas['mapper_input'] = (int(regs['r1'], 16), 0xac)
        if pc == 0x100bf0f4:
            areas['mapped_parameters'] = (0xc25ee130, 0xe0)
        if pc == 0x100d8582:
            areas['register_parameters'] = (int(regs['r0'], 16), 0x50)
        if pc in (0x100a2098, 0x10114bb2):
            areas['reuse_input'] = (int(regs['r0'], 16), 0x14)
        if pc == 0x1010b958:
            row['mmio_write'] = dict(address=regs['r0'], value=regs['r6'])
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
              scope='One hit per breakpoint per call_fixture window except the repeated 1010b958 register write. '
                    'Upstream stops reinstalling a repeated breakpoint once trace length reaches 256; '
                    'other pending breakpoints may still be observed, so this is not a total trace cap. '
                    'No exhaustive trace, RAW pixel calculation, NEF output or physical camera validation. '
                    'Upstream boot still sets configuration 0x29e=1 and sensor pointer=0.')


def invoke(function, payload, arguments):
    global packet
    result = ui.call_fixture(camera.remote, packet, function, payload, arguments)
    packet = 'T05thread:' + result['return_cpu'] + ';'
    report['calls'].append(dict(phase=phase, function=hex(function), result=result))
    return result


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

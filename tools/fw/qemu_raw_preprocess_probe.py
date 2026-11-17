"""Observe original pre-encoding RAW configuration under the pinned QEMU fixture.

Breakpoints are read-only and fire once per call_fixture window, not every call.
The existing synthetic boot still applies its documented RAM/hardware fixtures.
No new guest patches, forced completion, or pixel-correction model are added.
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
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
source = Path(__file__).read_bytes()
(a.output / 'probe-source.py').write_bytes(source)
sys.path.insert(0, str(a.repo / 'tools'))
import interactive as ui

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
    0x10076a08: 'still_lower_submit',
    0x100ae33e: 'still_raw_processing_entry',
    0x100b4c78: 'processing_submit_wrapper',
    0x100b5716: 'processing_packet_builder',
    0x100b3f94: 'parameter_pointer_builder',
    0x100d67f4: 'instance_1_queue_submit',
    0x100d5c86: 'processing_driver',
    0x10106360: 'core_five_flags',
    0x1010657a: 'raw_input_address_packer',
    0x10106980: 'raw_output_address_packer',
    0x10106dd4: 'block_30_control_118',
    0x10107f9c: 'block_54_control_ae',
    0x100af648: 'still_raw_encoding_entry',
    0x100760b6: 'still_offset_input',
    0x101224ce: 'offset_calibration_lookup',
    0x1012257e: 'offset_calibration_return',
    0x1013f950: 'still_offset_stored',
    0x1019f3d0: 'four_slot_parameter_generator',
    0x10107262: 'four_slot_register_packer',
}
events, phase, last_object = [], 'synthetic-boot', 0
original = ui.call_fixture


def capture(remote, address, size):
    if not address:
        return dict(address='0x0', skipped='null')
    if not (0x40000000 <= address < 0xd0000000 and size <= 0x10000):
        return dict(address=hex(address), skipped='outside_snapshot_policy')
    data = remote.memory(address, size)
    return dict(address=hex(address), size=size, bytes=data.hex(),
                sha256=hashlib.sha256(data).hexdigest())


def readword(remote, address):
    return struct.unpack('<I', remote.memory(address, 4))[0]


def object_areas(remote, areas, obj):
    areas['still_capture_object'] = capture(remote, obj, 0x3c0)
    if not obj:
        return
    for off in (0x1f8, 0x1fc, 0x330):
        areas[f'still_handle_{off:x}'] = capture(remote, readword(remote, obj+off), 0x90)
    # The static caller uses *(object+3a4)+394 as request+35c.
    areas['still_parameter_owner'] = capture(remote, readword(remote, obj+0x3a4), 0x900)


def request_areas(remote, areas, request):
    areas['processing_request'] = capture(remote, request, 0x390)
    if request:
        for off, size in ((0x35c, 0x500), (0x360, 0x3c00), (0x364, 8)):
            areas[f'request_source_{off:x}'] = capture(remote, readword(remote, request+off), size)


def packet_areas(remote, areas, packet):
    areas['processing_packet'] = capture(remote, packet, 0xd4)
    if packet:
        for off, size in ((0, 0x44), (0xc, 0x50), (0x20, 0xc), (0x28, 0x20),
                          (0x30, 0x11c), (0x34, 0x70), (0x3c, 0xcc),
                          (0x54, 0xb0), (0x58, 0x18)):
            areas[f'packet_block_{off:x}'] = capture(remote, readword(remote, packet+off), size)


def snapshot():
    areas = {}
    if last_object:
        object_areas(camera.remote, areas, last_object)
    areas['capture_sequence'] = capture(camera.remote, 0xc2376050, 0x100)
    return areas


def observed(*args, **kwargs):
    def observe(remote, regs):
        global last_object
        ri = lambda n: int(regs[f'r{n}'], 16)
        pc = ri(15)
        areas = {}
        row = dict(phase=phase, event=points[pc], outer_call=hex(args[2]),
                   registers=regs, memory=areas)
        events.append(row)
        if pc == 0x10076a08:
            last_object = readword(remote, ri(0))
            object_areas(remote, areas, last_object)
        if pc in (0x100ae33e, 0x100af648):
            areas['stage_request'] = capture(remote, ri(0), 0x20)
            object_areas(remote, areas, readword(remote, ri(0)+0xc))
        if pc == 0x100b4c78:
            row['instance'] = ri(0)
            request_areas(remote, areas, ri(1))
        if pc in (0x100b5716, 0x100b3f94):
            request_areas(remote, areas, ri(0))
        if pc == 0x100d67f4:
            packet_areas(remote, areas, ri(0))
        if pc == 0x100d5c86:
            areas['driver'] = capture(remote, ri(0), 0x20)
            packet_areas(remote, areas, ri(1))
        if pc in (0x10106360, 0x10106dd4, 0x10107f9c):
            areas['driver'] = capture(remote, ri(0), 0x20)
            row['value'] = ri(1)
        if pc in (0x1010657a, 0x10106980):
            areas['driver'] = capture(remote, ri(0), 0x20)
            areas['address_parameters'] = capture(remote, ri(1), 0x44 if pc == 0x1010657a else 8)
        if pc == 0x100760b6:
            areas['source_descriptor'] = capture(remote, ri(0), 0x20)
            areas['source_selectors'] = capture(remote, ri(1), 8)
        if pc == 0x101224ce:
            areas['offset_lookup_input'] = capture(remote, ri(0), 0x14)
            areas['calibration_context'] = capture(remote, 0xc18fa954, 0x20)
            base = readword(remote, 0xc18fa954+0x14)
            if base:
                areas['offset_calibration_table'] = capture(remote, base+0xbc7f6, 7*33*12)
        if pc == 0x1012257e:
            row['return_value'] = ri(1)
        if pc == 0x1013f950:
            object_areas(remote, areas, ri(4))
            row['stored_value'] = ri(0)
        if pc == 0x1019f3d0:
            areas['parameter_context'] = capture(remote, ri(0), 0xf8)
            areas['generator_input'] = capture(remote, readword(remote, ri(0)), 0xa0)
            areas['generator_output_before'] = capture(remote, readword(remote, ri(0)+0xd0), 0x500)
        if pc == 0x10107262:
            areas['driver'] = capture(remote, ri(0), 0x20)
            areas['four_slot_input'] = capture(remote, ri(1), 0x1a)
    observers = dict(kwargs.get('observers') or {})
    observers.update({pc: observe for pc in points})
    kwargs['observers'] = observers
    return original(*args, **kwargs)


ui.call_fixture = observed
report = dict(ok=False, scope=__doc__, firmware_sha256=digest,
    probe_sha256=hashlib.sha256(source).hexdigest(), calls=[],
    upstream_commit='419a1f2a91a1f2d3a0209027c29606475f7fe26f',
    points={hex(k): v for k, v in points.items()},
    arguments={k: str(v) for k, v in vars(a).items()})


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
    assert int(result['return_r0'], 16) == 0
    invoke(0x10170cca, bytes(8), [100])
    phase = 'native-settle'
    camera.remote.sock.settimeout(90)
    invoke(0x10170cca, bytes(8), [5000])
    report['final'] = snapshot()
    report['ok'] = True
except Exception:
    report['error'] = traceback.format_exc()
    print(report['error'], flush=True)
finally:
    camera.close_guest()
    report['firmware_unchanged'] = hashlib.sha256(ui.FIRMWARE.read_bytes()).hexdigest() == digest
    report['event_count'] = len(events)
    (a.output / 'events.json').write_text(json.dumps(events, indent=2), encoding='utf-8')
    (a.output / 'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    shutil.copytree(camera.directory, a.output / 'session')
    print('SAVED', report['ok'], len(events), flush=True)
sys.exit(0 if report['ok'] else 1)

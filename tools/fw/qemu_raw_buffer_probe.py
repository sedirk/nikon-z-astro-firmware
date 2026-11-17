"""Observe native buffer ownership with pinned synthetic boot; no new RAM patches.

Only pre-existing boot fixtures and diagnostic CaptureWithoutCard calls run.
No hardware/pixel algorithm, completion injection, or physical camera access.
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
    0x100bc450: 'buffer_builder_entry',
    0x100bc5f4: 'buffer_builder_ready',
    0x1010b9d6: 'buffer_register_submit',
    0x1010ba0a: 'buffer_1_address_write',
    0x1010ba1c: 'buffer_2_address_write',
    0x100be9b4: 'buffer_builder_caller',
    0x1018511e: 'af_record_publish_entry',
    0x1018517e: 'af_record_payload_copied',
    0x10185502: 'af_record_publish_return',
    0x10076a08: 'still_lower_submit',
    0x100710ee: 'frame_consumer_entry',
    0x100a0eb4: 'pdaf_export_call',
    0x100d8594: 'pdaf_address_wrapper',
    0x1010b9ca: 'pdaf_bank_1_address_write',
    0x1010b9d0: 'pdaf_bank_0_address_write',
    0x100bf750: 'frame_af_handle_store',
    0x100ae33e: 'main_raw_processing_entry',
    0x100af648: 'main_raw_output_stage',
    0x100a323e: 'raw_io_descriptor_builder',
    0x101caad8: 'raw_io_queue_submit',
    0x101ca6c6: 'raw_io_field_mapper',
    0x10108f8a: 'raw_io_register_packer',
}
events = []
phase = 'synthetic-boot'
original = ui.call_fixture
last_capture_object = 0


def capture(remote, address, size):
    if not address:
        return dict(address='0x0', skipped='null')
    # Snapshot only known RAM aliases, never arbitrary MMIO readbacks.
    if not ((0x40000000 <= address < 0xd0000000) and size <= 0x10000):
        return dict(address=hex(address), skipped='outside_snapshot_policy')
    blob = remote.memory(address, size)
    return dict(address=hex(address), size=size, bytes=blob.hex(),
                sha256=hashlib.sha256(blob).hexdigest())


def snapshot():
    remote = camera.remote
    areas = {label: capture(remote, addr, size) for label, addr, size in (
        ('buffer_parameters', 0xc25ee130, 0x140),
        ('af_record_context', 0xc1882d08, 0x50),
        ('af_records', 0xc2152370, 8 * 0xc30),
        ('capture_sequence', 0xc2376050, 0x100),
        ('task_metadata_bases', 0xc1800028, 8),
    )}
    if last_capture_object:
        areas['still_capture_object'] = capture(remote, last_capture_object, 0x3c0)
        resolve_still_handles(remote, areas)
    return areas


def resolve_still_handles(remote, areas):
    obj = areas.get('still_capture_object', {})
    if 'bytes' not in obj:
        return
    data = bytes.fromhex(obj['bytes'])
    for off in (0x1f8, 0x1fc, 0x318, 0x330):
        pointer = struct.unpack_from('<I', data, off)[0]
        areas[f'still_handle_{off:x}'] = capture(remote, pointer, 0x90)


def observed(*args, **kwargs):
    def observe(remote, regs):
        global last_capture_object
        ri = lambda n: int(regs[f'r{n}'], 16)
        pc = ri(15)
        row = dict(phase=phase, event=points[pc], outer_call=hex(args[2]), registers=regs, memory={})
        events.append(row)
        areas = {'buffer_parameters': (0xc25ee130, 0x140)}
        if pc in (0x100bc450, 0x100be9b4):
            areas['buffer_request'] = (ri(0), 0x20)
        if pc == 0x1010b9d6:
            areas['submitted_parameters'] = (ri(1), 0x38)
        if pc in (0x1010ba0a, 0x1010ba1c):
            row['mmio_write'] = dict(address=hex(ri(0) + (0x3e8 if pc == 0x1010ba0a else 0x3f4)),
                                     value=hex(ri(2)))
        if pc == 0x100d8594:
            row['selected_bank'] = ri(0)
            row['pdaf_address'] = hex(ri(1))
        if pc in (0x1010b9ca, 0x1010b9d0):
            row['mmio_write'] = dict(address=hex(ri(0) + (0x3c8 if pc == 0x1010b9ca else 0x3c4)),
                                     value=hex(ri(2)))
        if pc == 0x100bf750:
            areas['frame'] = (ri(4), 0x140)
            areas['assigned_af_handle'] = (ri(8), 0x90)
        if pc == 0x1018511e:
            areas['request'] = (ri(0), 0x28)
            if ri(0):
                frame = struct.unpack('<I', remote.memory(ri(0), 4))[0]
                areas['frame'] = (frame, 0x140)
        if pc == 0x10076a08:
            areas['still_request'] = (ri(0), 0x28)
            if ri(0):
                obj = struct.unpack('<I', remote.memory(ri(0), 4))[0]
                areas['still_capture_object'] = (obj, 0x3c0)
                last_capture_object = obj
        if pc in (0x100ae33e, 0x100af648):
            areas['stage_request'] = (ri(0), 0x20)
            obj = struct.unpack('<I', remote.memory(ri(0) + 0xc, 4))[0]
            areas['still_capture_object'] = (obj, 0x3c0)
        if pc == 0x100a323e:
            areas['raw_input_descriptor'] = (ri(0), 0x20)
            areas['raw_output_descriptor'] = (ri(1), 0x20)
        if pc == 0x101caad8:
            areas['raw_io_packet'] = (ri(0), 0x68)
        if pc == 0x101ca6c6:
            areas['raw_io_context'] = (0xc180b704, 0x20)
        if pc == 0x10108f8a:
            areas['raw_io_packed'] = (ri(1), 0x48)
        if pc in (0x1018517e, 0x10185502):
            areas['published_af_record'] = (ri(4), 0x140)
            areas['frame'] = (ri(7), 0x140)
        if pc == 0x100a0eb4:
            row['export_size'] = ri(1)
            areas['export_sample'] = (ri(0), 0x100)
        for label, (addr, size) in areas.items():
            row['memory'][label] = capture(remote, addr, size)
        resolve_still_handles(remote, row['memory'])
        # Resolve the handles passed to the buffer builder, each to its address vector.
        params = bytes.fromhex(row['memory']['buffer_parameters']['bytes'])
        for off in (0xc8, 0xcc, 0xd0, 0xe0):
            handle = struct.unpack_from('<I', params, off)[0]
            area = row['memory'][f'handle_{off:x}'] = capture(remote, handle, 0x20)
            if 'bytes' in area:
                vector = struct.unpack_from('<I', bytes.fromhex(area['bytes']), 4)[0]
                row['memory'][f'vector_{off:x}'] = capture(remote, vector, 0x20)
        area = row['memory'].get('frame', {})
        if 'bytes' in area:
            frame_data = bytes.fromhex(area['bytes'])
            for off, size in ((0x78, 0xac), (0x7c, 0x70)):
                addr = struct.unpack_from('<I', frame_data, off)[0]
                row['memory'][f'frame_payload_{off:x}'] = capture(remote, addr, size)
    observers = dict(kwargs.get('observers') or {})
    observers.update({pc: observe for pc in points})
    kwargs['observers'] = observers
    return original(*args, **kwargs)


ui.call_fixture = observed
report = dict(ok=False, firmware_sha256=digest, probe_sha256=hashlib.sha256(source).hexdigest(),
    upstream_commit='419a1f2a91a1f2d3a0209027c29606475f7fe26f', calls=[],
    points={hex(k): v for k, v in points.items()},
    arguments={k: str(v) if isinstance(v, Path) else v for k, v in vars(a).items()},
    scope='One hit per breakpoint per call_fixture, no repeated breakpoints. Pinned synthetic boot '
          'retains 0x29e=1, sensor-pointer fallback, synthetic input and hardware fixtures. '
          'No added guest RAM patches, firmware changes, pixel correction or physical validation. '
          'A submitted address is not proof that a hardware pixel operation completed.')


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
    call = invoke(0x101eedb4, payload, [('scratch', 0), 0x10524b7f])
    assert int(call['return_r0'], 16) == 0
    print('API', call['return_r0'], flush=True)
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

"""Observe native curve state under the pinned no-electronic-lens QEMU fixture.

Only bounded diagnostic calls and memory reads are added. Existing synthetic
boot assumptions remain; this is not a physical-camera or NEF pixel experiment.
"""
from pathlib import Path
import argparse, hashlib, json, shutil, struct, sys, traceback

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--repo', type=Path, required=True)
p.add_argument('--firmware', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--settle-ticks', type=int, default=5000)
p.add_argument('--selector-cases', action='store_true', help='After observation, test artificial properties in this private guest and restore them.')
a = p.parse_args()
assert 1 <= a.settle_ticks <= 10000
a.output.mkdir(parents=True, exist_ok=False)
source = Path(__file__).read_bytes()
(a.output/'probe-source.py').write_bytes(source)
sys.path.insert(0, str(a.repo/'tools'))
import interactive as ui
ui.FIRMWARE = a.firmware.resolve(strict=True)
ui.BUILD_MANIFEST = a.repo/'.local/build-manifest.json'
digest = ui.checked_firmware(ui.FIRMWARE)
assert digest == '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
camera = ui.Camera(8787, profile='shooting', capture_control_test=True,
    raw_source=ui.active_manifest('native0'), exmcu_no_lens=True,
    tg_periodic_test=True, tg_paired_test=True, raw_ingress_test=ui.active_ingress(),
    isp_boundary_test=True, orientation_fixture=0, keep_awake=True, photo_liveview=True,
    firmware_sha256=digest)
camera.exposure_probe = True
camera.isp_disable_cache = False
camera.tg_period_ms = None
points = {
    0x10076a08: 'still_front_submit',
    0x100ace06: 'still_curve_stage',
    0x100c29c6: 'still_curve_builder',
    0x100c24f2: 'still_main_builder',
    0x100c1fba: 'other_curve_builder',
    0x1017235a: 'curve_generator_entry',
    0x101723c0: 'curve_generator_return',
    0x100ad7d8: 'still_table_stage',
    0x100ae33e: 'still_raw_processing',
    0x100af648: 'still_raw_encoding',
    0x100a323e: 'encoder_descriptor_entry',
    0x1013c3a2: 'neutral_selector_property_138d',
    0x1013c3ae: 'neutral_selector_property_1c14',
    0x1013c3b8: 'neutral_selector_config_3e3',
    0x1013c3be: 'neutral_selector_helper_a8',
    0x1013c3e0: 'neutral_selector_helper_2c',
    0x1013c41c: 'neutral_selector_result',
    0x1013fa5a: 'still_neutral_flag_assignment',
}
events, phase, last_object = [], 'synthetic-boot', 0
original = ui.call_fixture
report = dict(ok=False, scope=__doc__, firmware_sha256=digest,
    probe_sha256=hashlib.sha256(source).hexdigest(), calls=[],
    points={hex(k): v for k, v in points.items()},
    arguments={k: str(v) for k, v in vars(a).items()}, limitations=[
        'Pinned synthetic boot, 0x29e=1, sensor-pointer fallback and input/device/time fixtures remain.',
        'No electronic lens is a model setting, not a captured physical lens exchange.',
        'Diagnostic CaptureWithoutCard and sleep calls are active guest calls.',
        'At most one hit per breakpoint per outer call; entry and return may belong to different invocations.',
        'No new pixel algorithm, event, wait-result replacement or firmware patch.',
        'A still-owner snapshot precedes downstream processing; isolated replay is reported separately.'])
for name in ('nikon-z6.c', 'nikon-z6-profile.h', 'nikon-functional-isp.h', 'nikon-isp-pixels.h'):
    report.setdefault('model_sources', {})[name] = hashlib.sha256((a.repo/'qemu'/name).read_bytes()).hexdigest()


def capture(remote, address, size):
    if not address:
        return dict(address='0x0', skipped='null')
    assert 0xa0000000 <= address < address+size <= 0xd0000000 and size <= 0x10000, (hex(address), size)
    data = remote.memory(address, size)
    return dict(address=hex(address), size=size, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest())


def word(remote, address):
    return struct.unpack('<I', remote.memory(address, 4))[0]


def object_areas(remote, areas, obj):
    areas['still_object'] = capture(remote, obj, 0x3c0)
    if not obj:
        return
    areas['owner'] = capture(remote, word(remote, obj+0x3a4), 0x3000)
    for off, size in ((0x1f8, 0x90), (0x1fc, 0x90), (0x270, 0xda0)):
        areas[f'still_resource_{off:x}'] = capture(remote, word(remote, obj+off), size)


def observed(*args, **kwargs):
    def observe(remote, regs):
        global last_object
        ri = lambda n: int(regs[f'r{n}'], 16)
        pc, areas = ri(15), {}
        events.append(dict(phase=phase, event=points[pc], outer_call=hex(args[2]), registers=regs, memory=areas))
        if points[pc].startswith('neutral_selector_'):
            # Registers at actual return sites, without replacing getters.
            return
        if pc == 0x10076a08:
            last_object = word(remote, ri(0))
        elif pc in (0x100ace06, 0x100ad7d8, 0x100ae33e, 0x100af648):
            last_object = word(remote, ri(0)+0xc)
        elif pc in (0x100c29c6, 0x100c24f2):
            areas['builder_input'] = capture(remote, ri(0), 0x34)
            last_object = word(remote, ri(0))
        elif pc == 0x100c1fba:
            obj = word(remote, ri(0))
            areas['other_object'] = capture(remote, obj, 0x140)
            areas['other_state'] = capture(remote, word(remote, obj+0x130), 0x2b00)
        elif pc == 0x1017235a:
            areas['arguments'] = capture(remote, ri(0), 12)
            areas['properties'] = capture(remote, word(remote, ri(0)), 108)
            areas['cache'] = capture(remote, word(remote, ri(0)+4), 32)
            areas['history'] = capture(remote, ri(1), 0x64)
            areas['output_vector'] = capture(remote, ri(2), 20)
        elif pc == 0x101723c0:
            ctx = ri(4)
            areas['context'] = capture(remote, ctx, 0x300)
            areas['properties'] = capture(remote, word(remote, ctx), 108)
            areas['history'] = capture(remote, word(remote, ctx+4), 0x64)
            for off, name, size in ((8,'curve',514),(12,'mixed_curve',514),(16,'state',32),(20,'coefficients',20)):
                areas[name] = capture(remote, word(remote, ctx+off), size)
        elif pc == 0x100a323e:
            areas['encoder_input'] = capture(remote, ri(0), 0x20)
            areas['encoder_output'] = capture(remote, ri(1), 0x20)
        elif pc == 0x1013fa5a:
            areas['assigned_owner'] = capture(remote, ri(1), 0x3000)
        if last_object:
            object_areas(remote, areas, last_object)
    observers = dict(kwargs.get('observers') or {})
    observers.update({pc: observe for pc in points if phase != 'property-counterfactual' or points[pc].startswith('neutral_selector_')})
    kwargs['observers'] = observers
    return original(*args, **kwargs)


ui.call_fixture = observed


def invoke(function, payload, arguments):
    global packet
    result = ui.call_fixture(camera.remote, packet, function, payload, arguments)
    packet = 'T05thread:'+result['return_cpu']+';'
    report['calls'].append(dict(phase=phase, function=hex(function), result=result))
    return result


try:
    print('BOOT', flush=True)
    camera.boot_shooting(); camera.pause(); packet = camera.run_to(0x100531bc)
    camera.remote.sock.settimeout(90)
    print('BASELINE_EVENTS', len(events), flush=True)
    phase = 'native-without-card'
    invoke(0x101efaa8, bytes(8), [1])
    request = bytearray(32); request[2] = 1; struct.pack_into('<I', request, 0x10, 1)
    result = invoke(0x101eedb4, request, [('scratch', 0), 0x10524b7f])
    assert int(result['return_r0'], 16) == 0
    invoke(0x10170cca, bytes(8), [100])
    phase = 'native-settle'
    invoke(0x10170cca, bytes(8), [a.settle_ticks])
    report['final'] = {}
    object_areas(camera.remote, report['final'], last_object)
    for address, size, name in ((0xc2763120,0xa0,'main_properties'),
            (0xc27b60fc,108,'still_curve_properties'),(0xc27e8168,0x64,'still_curve_history'),
            (0xc26bae04,108,'other_curve_properties'),(0xc26ece70,0x64,'other_curve_history'),
            (0xc18fa954,0x20,'calibration_pointer')):
        report['final'][name] = capture(camera.remote, address, size)
    if a.selector_cases:
        phase = 'property-counterfactual'
        identities = (0x138d,0x1325,0x1c14,0x1c1d,0x1c21)
        originals = {ident:int(invoke(0x10164bfa,bytes(8),[ident])['return_r0'],16) for ident in identities}
        config_address = 0xc20aa7c8+0x3e3
        original_config = camera.remote.memory(config_address,1)
        report['selector_cases'] = []
        report['selector_fixture'] = dict(original_properties={hex(k):v for k,v in originals.items()},
            original_config=original_config.hex(),config_address=hex(config_address),restored=False,
            scope='Artificial RAM property/config comparisons after final baseline snapshot; native getters, helpers and selector, original OS. No saved-image or lens-semantic claim.')
        try:
            for state in (0,2,3):
                for config in (0,1):
                    props = {0x138d:1,0x1325:4,0x1c14:state,0x1c1d:1,0x1c21:1}
                    start = len(report['calls'])
                    for ident,value in props.items():
                        invoke(0x10070366,bytes(8),[ident,value,('scratch',0)])
                    assert camera.remote.command(f'M{config_address:x},1:{config:02x}') == 'OK'
                    readback={ident:int(invoke(0x10164bfa,bytes(8),[ident])['return_r0'],16) for ident in identities}
                    assert readback == props
                    values={name:int(invoke(fn,bytes(8),[])['return_r0'],16) for name,fn in
                            (('helper_a8',0x101496a8),('helper_2c',0x1014962c),('neutral',0x1013c392))}
                    report['selector_cases'].append(dict(properties={hex(k):v for k,v in props.items()},
                        config_3e3=config,**values,calls_start=start,calls_end=len(report['calls'])))
                    assert values['neutral'] == int(state != 3 or config == 0), values
        finally:
            for ident,value in originals.items():
                invoke(0x10070366,bytes(8),[ident,value,('scratch',0)])
            assert camera.remote.command(f'M{config_address:x},1:'+original_config.hex()) == 'OK'
            restored={ident:int(invoke(0x10164bfa,bytes(8),[ident])['return_r0'],16) for ident in identities}
            assert restored == originals and camera.remote.memory(config_address,1) == original_config
            report['selector_fixture']['restored'] = True
    report['ok'] = True
except Exception:
    report['error'] = traceback.format_exc(); print(report['error'], flush=True)
finally:
    camera.close_guest()
    report['firmware_unchanged'] = hashlib.sha256(ui.FIRMWARE.read_bytes()).hexdigest() == digest
    report['event_count'] = len(events)
    (a.output/'events.json').write_text(json.dumps(events, indent=2), encoding='utf-8')
    (a.output/'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    shutil.copytree(camera.directory, a.output/'session')
    print('SAVED', report['ok'], len(events), flush=True)
sys.exit(0 if report['ok'] else 1)

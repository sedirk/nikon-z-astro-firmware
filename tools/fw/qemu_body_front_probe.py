"""Observe native body-table selection and front RAW submission in pinned QEMU.

Read-only breakpoints in the existing synthetic no-lens capture fixture. No new
guest patches, completion events, pixel algorithms, or firmware edits are used.
"""
from pathlib import Path
import argparse, hashlib, json, shutil, struct, sys, traceback

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--repo', type=Path, required=True)
p.add_argument('--firmware', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
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
    0x10179962:'still_source_entry', 0x1011dce0:'table32_selector',
    0x1011dcb2:'table32_selected', 0x1011df8c:'table144_selected',
    0x1011e112:'table144_built', 0x1011d548:'front_packet_dispatch',
    0x1010b330:'table32_upload', 0x1010b37e:'table144_upload',
    0x1010b2f0:'positive_scalar_upload', 0x1013f950:'negative_offset_assignment',
    0x10076a08:'still_front_submit', 0x100bd820:'front_geometry_entry',
    0x100bd8ec:'front_raw_address_ready',
    0x100ae33e:'still_raw_processing', 0x10107262:'four_offsets_and_720_upload',
    0x10106980:'replacement_raw_address_upload', 0x100af648:'still_raw_encoding',
    0x10179d4a:'temporary_front_gate_set',
    0x10179d94:'front_pre_wait_operation',
    0x10179da4:'front_event8_wait',
    0x10179da8:'front_event8_return',
    0x10179dd4:'temporary_front_gate_clear',
}
phase, events, last_object = 'synthetic-boot', [], 0
original = ui.call_fixture
report = dict(ok=False, scope=__doc__, firmware_sha256=digest,
    probe_sha256=hashlib.sha256(source).hexdigest(), calls=[],
    points={hex(k):v for k,v in points.items()}, limitations=[
        'Pinned synthetic boot keeps the pre-existing 0x29e and sensor/input/device/time fixtures.',
        'CaptureWithoutCard and sleep are diagnostic guest calls, not a physical exposure.',
        'At most one hit per breakpoint per outer call. Entries/returns are not paired invocations.',
        'No MMIO status reads or full RAW payload scans; configuration bytes are not output pixels.',
        'Neither calibration payloads nor source context are from a physical camera.'])
for name in ('nikon-z6.c','nikon-z6-profile.h','nikon-functional-isp.h','nikon-isp-pixels.h'):
    report.setdefault('model_sources', {})[name] = hashlib.sha256((a.repo/'qemu'/name).read_bytes()).hexdigest()

def capture(remote, address, size):
    if not address: return dict(address='0x0', skipped='null')
    assert 0x40000000 <= address < address+size <= 0xd0000000 and size <= 0x10000, (hex(address),size)
    data = remote.memory(address,size)
    return dict(address=hex(address),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())

def word(remote,address): return struct.unpack('<I',remote.memory(address,4))[0]

def shared(remote, areas):
    areas['calibration_state'] = capture(remote,0xc18fa954,0x20)
    areas['directory_38'] = capture(remote,0xc1881298,28)
    areas['source_context'] = capture(remote,0xc18fa844,0x94)
    areas['source_late_context'] = capture(remote,0xc18fa844+0x94,0x50)
    areas['source_packet'] = capture(remote,0xc29a34c0,0x60)

def object_areas(remote,areas,obj):
    areas['still_object'] = capture(remote,obj,0x3c0)
    if not obj: return
    areas['owner'] = capture(remote,word(remote,obj+0x3a4),0x400)
    for off in (0x1f8,0x1fc,0x330):
        areas[f'handle_{off:x}'] = capture(remote,word(remote,obj+off),0x90)

def observed(*args,**kwargs):
    def observe(remote,regs):
        global last_object
        ri = lambda n:int(regs[f'r{n}'],16)
        pc,areas = ri(15),{}
        events.append(dict(phase=phase,event=points[pc],outer_call=hex(args[2]),registers=regs,memory=areas))
        shared(remote,areas)
        if pc==0x10179962: areas['still_source_input']=capture(remote,ri(0),0x50)
        elif pc==0x1011dcb2: areas['table32_record']=capture(remote,ri(0),256)
        elif pc==0x1011df8c: areas['table144_record']=capture(remote,ri(0),588)
        elif pc in (0x1011e112,0x1011d548):
            for name,address,size in (('table32',0xc29a38a0,256),('table144_a',0xc29a39a0,288),('table144_b',0xc29a3ac0,288)):
                areas[name]=capture(remote,address,size)
        elif pc==0x1010b330: areas['upload_input']=capture(remote,ri(1),256)
        elif pc==0x1010b37e:
            areas['upload_a']=capture(remote,ri(1),288)
            areas['upload_b']=capture(remote,ri(2),288)
        elif pc==0x1010b2f0: areas['upload_input']=capture(remote,ri(1),12)
        elif pc==0x10076a08: last_object=word(remote,ri(0))
        elif pc==0x100bd820:
            areas['front_request']=capture(remote,ri(0),16)
            areas['front_handle']=capture(remote,word(remote,ri(0)+4),0x90)
        elif pc==0x100bd8ec: areas['front_parameters']=capture(remote,0xc25ee224,0x44)
        elif pc in (0x100ae33e,0x100af648): last_object=word(remote,ri(0)+0xc)
        elif pc in (0x10107262,0x10106980):
            areas['driver']=capture(remote,ri(0),0x20)
            areas['upload_input']=capture(remote,ri(1),0x20 if pc==0x10107262 else 8)
        if last_object: object_areas(remote,areas,last_object)
    observers=dict(kwargs.get('observers') or {})
    observers.update({pc:observe for pc in points})
    kwargs['observers']=observers
    return original(*args,**kwargs)

ui.call_fixture=observed
def invoke(fn,payload,arguments):
    global packet
    result=ui.call_fixture(camera.remote,packet,fn,payload,arguments)
    packet='T05thread:'+result['return_cpu']+';'
    report['calls'].append(dict(phase=phase,function=hex(fn),result=result))
    return result

try:
    print('BOOT',flush=True)
    camera.boot_shooting();camera.pause();packet=camera.run_to(0x100531bc)
    camera.remote.sock.settimeout(90)
    print('BASELINE',len(events),flush=True)
    phase='native-without-card';invoke(0x101efaa8,bytes(8),[1])
    request=bytearray(32);request[2]=1;struct.pack_into('<I',request,0x10,1)
    assert int(invoke(0x101eedb4,request,[('scratch',0),0x10524b7f])['return_r0'],16)==0
    invoke(0x10170cca,bytes(8),[100]);phase='native-settle'
    invoke(0x10170cca,bytes(8),[5000])
    report['final']={};shared(camera.remote,report['final'])
    object_areas(camera.remote,report['final'],last_object)
    report['ok']=True
except Exception:
    report['error']=traceback.format_exc();print(report['error'],flush=True)
finally:
    camera.close_guest()
    report['firmware_unchanged']=hashlib.sha256(ui.FIRMWARE.read_bytes()).hexdigest()==digest
    report['event_count']=len(events)
    (a.output/'events.json').write_text(json.dumps(events,indent=2),encoding='utf-8')
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    shutil.copytree(camera.directory,a.output/'session')
    print('SAVED',report['ok'],len(events),flush=True)
sys.exit(0 if report['ok'] else 1)

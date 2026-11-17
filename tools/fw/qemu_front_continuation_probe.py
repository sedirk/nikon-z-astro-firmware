"""Repeated native observations across the temporary front-stage boundary.

Read-only breakpoints in the existing synthetic no-lens capture fixture. No new
guest patches, completion events, pixel algorithms, or firmware edits are used.
"""
from pathlib import Path
import argparse, hashlib, json, shutil, struct, sys, traceback

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--repo', type=Path, required=True)
p.add_argument('--firmware', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--transport-cases', action='store_true', help='Artificial calibration in private guest RAM, restored after bounded original-code calls.')
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
source = Path(__file__).read_bytes()
(a.output/'probe-source.py').write_bytes(source)
sys.path.insert(0, str(a.repo/'tools'))
import interactive as ui
import probe as controller
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
    0x10179dd8:'after_temporary_gate',
    0x10179e58:'front_stage_return',
    0x1011b7bc:'front_command_selector',
    0x101228c2:'front_command_batch',
    0x1017e524:'front_command_packet',
    0x1017e57c:'front_spi_submission',
    0x1011c750:'front_stage_operation',
}
phase, events, last_object, window = 'synthetic-boot', [], 0, 0
repeated={0x1011dce0,0x1011dcb2,0x1011df8c,0x1011e112,0x1011d548,
          0x1010b330,0x1010b37e,0x1010b2f0,0x1011b7bc,0x101228c2,0x1017e524,0x1017e57c,0x1011c750}
original = ui.call_fixture
report = dict(ok=False, scope=__doc__, firmware_sha256=digest,
    probe_sha256=hashlib.sha256(source).hexdigest(), calls=[],
    points={hex(k):v for k,v in points.items()}, limitations=[
        'Pinned synthetic boot keeps the pre-existing 0x29e and sensor/input/device/time fixtures.',
        'CaptureWithoutCard and sleep are diagnostic guest calls, not a physical exposure.',
        'Selected points repeat during capture diagnostics using the existing single-step/rearm support.',
        'Rearming is capped at 256 total trace events per outer call; event counts and saturation are recorded.',
        'Other points remain one hit per outer call. No entry/return pairing is assumed.',
        'No MMIO status reads or full RAW payload scans; configuration bytes are not output pixels.',
        'Neither calibration payloads nor source context are from a physical camera.'])
for name in ('nikon-z6.c','nikon-z6-profile.h','nikon-functional-isp.h','nikon-isp-pixels.h'):
    report.setdefault('model_sources', {})[name] = hashlib.sha256((a.repo/'qemu'/name).read_bytes()).hexdigest()
report['controller_sha256']=hashlib.sha256((a.repo/'tools/probe.py').read_bytes()).hexdigest()
(a.output/'controller-source.py').write_bytes((a.repo/'tools/probe.py').read_bytes())
report['repeat_points']=[hex(x) for x in sorted(repeated)]

def capture(remote, address, size):
    if not address: return dict(address='0x0', skipped='null')
    assert 0x40000000 <= address < address+size <= 0xd0000000 and size <= 0x10000, (hex(address),size)
    data = remote.memory(address,size)
    return dict(address=hex(address),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())

def word(remote,address): return struct.unpack('<I',remote.memory(address,4))[0]

def shared(remote, areas):
    areas['calibration_state'] = capture(remote,0xc18fa954,0x20)
    areas['directory_38'] = capture(remote,0xc1881298,28)
    areas['storage_18'] = capture(remote,0xc1880c4c,44)
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
    global window
    window+=1
    start=len(events)
    def observe(remote,regs):
        global last_object
        ri = lambda n:int(regs[f'r{n}'],16)
        pc,areas = ri(15),{}
        events.append(dict(sequence=len(events),window=window,phase=phase,event=points[pc],outer_call=hex(args[2]),registers=regs,memory=areas))
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
        elif pc==0x101228c2:
            areas['command_lengths']=capture(remote,ri(1),64)
        elif pc==0x1017e524:
            assert 0<ri(1)<=0x10000
            areas['command_payload']=capture(remote,ri(0),ri(1))
        elif pc==0x1017e57c:
            areas['serial_context']=capture(remote,0xc18fa9bc,0x28)
            areas['serial_descriptor']=capture(remote,ri(1),0x18)
            count=word(remote,ri(1)+8)
            assert 0<count<=192
            areas['serial_words']=capture(remote,word(remote,ri(1)),count*2)
        if last_object: object_areas(remote,areas,last_object)
    observers=dict(kwargs.get('observers') or {})
    observers.update({pc:observe for pc in points})
    kwargs['observers']=observers
    saved=set(controller.TRACE_REPEAT)
    if phase!='synthetic-boot':controller.TRACE_REPEAT=saved|repeated
    try:
        result=original(*args,**kwargs)
        report.setdefault('windows',[]).append(dict(window=window,phase=phase,function=hex(args[2]),
            events_start=start,events_end=len(events),trace_count=len(result['trace']),
            repeat_enabled=phase!='synthetic-boot',saturated=len(result['trace'])>=256))
        return result
    finally:controller.TRACE_REPEAT=saved

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
    phase='native-storage-descriptor'
    report['directory_query']=invoke(0x101f620e,bytes(20),[0x38,('scratch',0)])
    assert int(report['directory_query']['return_r0'],16)==1
    if a.transport_cases:
        phase='synthetic-calibration-transport'
        remote=camera.remote
        base=word(remote,0xc18fa954+0x14)
        assert base==0xc9700000
        # Only captured/model calibration addresses are touched, in this guest.
        areas=((base+0xbe0d0,8),(base+0xbe0e0,8),(0xc18fa954+6,1),
               (base+0xbf970,9),(base+0xc1b70,6),(base+0xc22d0,9),(base+0xc24d0,6))
        originals={addr:remote.memory(addr,size) for addr,size in areas}
        table_before=remote.memory(0xc29a38a0,0x340)
        context_before=remote.memory(0xc18fa844,0xe4)
        report['transport_fixture']=dict(scope='Artificial private guest calibration; original SPI sink and OS; no physical camera connection.',
            before=[capture(remote,addr,size) for addr,size in areas],restored=False)
        report['transport_cases']=[]
        def write(addr,data):assert remote.command(f'M{addr:x},{len(data):x}:'+data.hex())=='OK'
        patterns=(bytes.fromhex('1122334455667788'),bytes.fromhex('91a2b3c4d5e6f708'))
        artificial_packets=(bytes.fromhex('817a0111'),bytes.fromhex('817a022233'))
        try:
            write(base+0xbe0d0,patterns[0]);write(base+0xbe0e0,patterns[1])
            for state,mode in ((0,0),(1,0),(0,1),(1,1)):
                write(0xc18fa954+6,bytes([state]));start=len(events)
                result=invoke(0x1011ba4e,bytes(8),[mode])
                emitted=[bytes.fromhex(e['memory']['command_payload']['bytes']) for e in events[start:] if e['event']=='front_command_packet']
                expected=[] if mode else [bytes.fromhex('8100db')+patterns[1-state]]
                after=remote.memory(0xc18fa954+6,1)[0]
                assert after==1-state and emitted==expected and int(result['return_r0'],16)==0
                report['transport_cases'].append(dict(name=f'toggle-{state}-argument-{mode}',initial_state=state,
                    argument=mode,final_state=after,expected_packets=[b.hex() for b in expected],
                    events_start=start,events_end=len(events)))
            for kind,data_off,length_off in ((2,0xbf970,0xc1b70),(5,0xc22d0,0xc24d0)):
                write(base+data_off,b''.join(artificial_packets))
                for enabled in (False,True):
                    write(base+length_off,struct.pack('<3H',4,5,0) if enabled else bytes(6))
                    start=len(events)
                    result=invoke(0x1011b7bc,context_before,[kind,('scratch',0)])
                    emitted=[bytes.fromhex(e['memory']['command_payload']['bytes']) for e in events[start:] if e['event']=='front_command_packet']
                    expected=list(artificial_packets) if enabled else []
                    assert emitted==expected and int(result['return_r0'],16)==0
                    report['transport_cases'].append(dict(name=f'command-{kind}-lengths-{int(enabled)}',kind=kind,
                        data_address=hex(base+data_off),length_address=hex(base+length_off),
                        expected_packets=[b.hex() for b in expected],events_start=start,events_end=len(events)))
            assert remote.memory(0xc29a38a0,0x340)==table_before
            assert remote.memory(0xc18fa844,0xe4)==context_before
            report['transport_fixture']['front_tables_and_context_unchanged']=True
        finally:
            for addr,data in originals.items():write(addr,data)
            for addr,data in originals.items():assert remote.memory(addr,len(data))==data
            report['transport_fixture']['restored']=True
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

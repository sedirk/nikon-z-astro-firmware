"""Observe original front-field writers and consumers in the existing QEMU fixture.

No new guest instructions, pixel algorithms or completion events. Diagnostic
calls and synthetic boot settings are inherited from the pinned research setup.
"""
from pathlib import Path
import argparse, hashlib, json, shutil, struct, sys, traceback

p=argparse.ArgumentParser(description=__doc__)
for name in ('repo','firmware','output'):p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--replay',type=Path,help='Cross-check one saved artificial calibration case in private guest RAM.')
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
source=Path(__file__).read_bytes();(a.output/'probe-source.py').write_bytes(source)
sys.path.insert(0,str(a.repo/'tools'))
import interactive as ui
import probe as controller
ui.FIRMWARE=a.firmware.resolve(strict=True);ui.BUILD_MANIFEST=a.repo/'.local/build-manifest.json'
digest=ui.checked_firmware(ui.FIRMWARE)
assert digest=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
camera=ui.Camera(8787,profile='shooting',capture_control_test=True,raw_source=ui.active_manifest('native0'),
    exmcu_no_lens=True,tg_periodic_test=True,tg_paired_test=True,raw_ingress_test=ui.active_ingress(),
    isp_boundary_test=True,orientation_fixture=0,keep_awake=True,photo_liveview=True,firmware_sha256=digest)
camera.exposure_probe=True;camera.isp_disable_cache=False;camera.tg_period_ms=None
points={0x10179962:'still_source_entry',0x1017a136:'still_builder_callsite',
    0x10121ede:'field_builder_entry',0x10121f1e:'first_pair_built',
    0x10121fdc:'four_coefficients_built',0x10122086:'control_fields_begin',
    0x10122250:'field_builder_return',0x1011b7bc:'command_selector',
    0x1011ba4e:'alternating_record_entry',0x1017e524:'command_packet',
    0x1017e57c:'spi_submission',0x10076a08:'still_front_submit',
    0x100bd8ec:'front_raw_address_ready',0x10107262:'four_offsets_and_720_upload',
    0x100ae33e:'still_raw_processing',0x10106980:'replacement_raw_address_upload',
    0x100af648:'still_raw_encoding',0x1010b2f0:'positive_scalar_upload',
    0x10179dd8:'after_temporary_stage',0x1011e940:'coefficient_publisher',
    0x10122ca2:'coefficient_packet_builder',0x1010b298:'front_coefficients_upload'}
phase,window,last_object='synthetic-boot',0,0
events=[];original=ui.call_fixture
report=dict(ok=False,scope=__doc__,firmware_sha256=digest,probe_sha256=hashlib.sha256(source).hexdigest(),
    points={hex(k):v for k,v in points.items()},calls=[],windows=[],limitations=[
        'Existing synthetic boot, sensor/input/device/time and 0x29e settings are retained.',
        'No physical calibration, sensor response, completed NEF or valid static pixel input is supplied.',
        'Boot points are first-hit per diagnostic call; selected capture points repeat up to 256 total trace events per outer call.',
        'Snapshots are taken before the instruction at each PC. No entry/return pairing is assumed.'])
for name in ('nikon-z6.c','nikon-z6-profile.h','nikon-functional-isp.h','nikon-isp-pixels.h'):
    report.setdefault('model_sources',{})[name]=hashlib.sha256((a.repo/'qemu'/name).read_bytes()).hexdigest()
controller_source=(a.repo/'tools/probe.py').read_bytes()
report['controller_sha256']=hashlib.sha256(controller_source).hexdigest()
(a.output/'controller-source.py').write_bytes(controller_source)

def capture(remote,address,size):
    if not address:return dict(address='0x0',skipped='null')
    assert 0x40000000<=address<address+size<=0xd0000000 and size<=0x10000
    data=remote.memory(address,size)
    return dict(address=hex(address),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())
def word(remote,address):return struct.unpack('<I',remote.memory(address,4))[0]
def shared(remote,areas):
    areas['context']=capture(remote,0xc18fa844,0xe4)
    areas['calibration_state']=capture(remote,0xc18fa954,0x20)
    base=word(remote,0xc18fa954+0x14)
    if base:areas['calibration_front_fields']=capture(remote,base+0xbe000,0xb20)
    if last_object:
        areas['still_object']=capture(remote,last_object,0x3c0)
        for offset in (0x1f8,0x1fc,0x330):areas[f'handle_{offset:x}']=capture(remote,word(remote,last_object+offset),0x90)
def observed(*args,**kwargs):
    global window
    window+=1;start=len(events)
    def observe(remote,regs):
        global last_object
        ri=lambda n:int(regs[f'r{n}'],16)
        pc=ri(15);areas={}
        if pc==0x10076a08:last_object=word(remote,ri(0))
        if pc in (0x100ae33e,0x100af648):last_object=word(remote,ri(0)+0xc)
        shared(remote,areas)
        if pc==0x10179962:areas['still_source_input']=capture(remote,ri(0),0x50)
        elif pc==0x100bd8ec:areas['front_parameters']=capture(remote,0xc25ee224,0x44)
        elif pc==0x1017e524:areas['payload']=capture(remote,ri(0),ri(1))
        elif pc==0x1017e57c:
            areas['descriptor']=capture(remote,ri(1),0x18)
            n=word(remote,ri(1)+8);assert 0<n<=192
            areas['words']=capture(remote,word(remote,ri(1)),n*2)
        elif pc==0x10107262:areas['offset_input']=capture(remote,ri(1),0x20)
        elif pc in (0x10121ede,0x1011e940):areas['argument_context']=capture(remote,ri(0),0xe4)
        elif pc==0x10122ca2:
            areas['coefficient_record']=capture(remote,ri(0),12)
            areas['coefficient_values']=capture(remote,ri(1),16)
        elif pc==0x1010b298:areas['coefficient_packet']=capture(remote,ri(1),32)
        events.append(dict(sequence=len(events),phase=phase,window=window,event=points[pc],registers=regs,memory=areas))
    observers=dict(kwargs.get('observers') or {});observers.update({pc:observe for pc in points})
    kwargs['observers']=observers;saved=set(controller.TRACE_REPEAT)
    if phase!='synthetic-boot':controller.TRACE_REPEAT=saved|set(points)
    try:
        result=original(*args,**kwargs)
        report['windows'].append(dict(window=window,phase=phase,events_start=start,events_end=len(events),
            trace_count=len(result['trace']),repeat_enabled=phase!='synthetic-boot',saturated=len(result['trace'])>=256))
        return result
    finally:controller.TRACE_REPEAT=saved
ui.call_fixture=observed
def invoke(fn,payload,arguments):
    global packet
    result=ui.call_fixture(camera.remote,packet,fn,payload,arguments)
    packet='T05thread:'+result['return_cpu']+';'
    report['calls'].append(dict(phase=phase,function=hex(fn),result=result));return result
try:
    print('BOOT',flush=True)
    camera.boot_shooting();camera.pause();packet=camera.run_to(0x100531bc)
    camera.remote.sock.settimeout(90);phase='native-without-card'
    invoke(0x101efaa8,bytes(8),[1]);request=bytearray(32);request[2]=1
    struct.pack_into('<I',request,0x10,1)
    assert int(invoke(0x101eedb4,request,[('scratch',0),0x10524b7f])['return_r0'],16)==0
    invoke(0x10170cca,bytes(8),[100]);phase='native-settle'
    invoke(0x10170cca,bytes(8),[5000]);report['final']={};shared(camera.remote,report['final'])
    if a.replay:
        phase='synthetic-field-replay';remote=camera.remote
        source_result=json.loads(a.replay.read_text());case=next(c for c in source_result['cases'] if c['name']=='baseline')
        base=word(remote,0xc18fa954+0x14);assert base==0xc9700000
        patches={base+0xbe000:bytes.fromhex(case['calibration_front']['bytes']),
                 base+0xbbd70+22*12:bytes.fromhex(case['calibration_coefficient_record']['bytes'])}
        originals={address:remote.memory(address,len(value)) for address,value in patches.items()}
        for address,size in ((0xc29a3868,32),(0xc29a34c0,96),(0xc29a3f28,64)):
            originals[address]=remote.memory(address,size)
        context_before=remote.memory(0xc18fa844,0xe4)
        def write(address,data):assert remote.command(f'M{address:x},{len(data):x}:'+data.hex())=='OK'
        report['replay']=dict(source_sha256=hashlib.sha256(a.replay.read_bytes()).hexdigest(),case='baseline',restored=False,
            scope='Artificial baseline in private guest RAM; original builder/publisher/packet functions and existing disconnected SPI sink.',
            before=[capture(remote,address,len(value)) for address,value in originals.items()])
        try:
            for address,data in patches.items():write(address,data)
            start=len(events)
            built=invoke(0x10121ede,bytes.fromhex(case['input_context']['bytes']),[('scratch',0)])
            assert int(built['return_r0'],16)==0 and built['output']==case['context_after_builder']['bytes']
            published=invoke(0x1011e940,bytes.fromhex(built['output']),[('scratch',0),1])
            assert int(published['return_r0'],16)==0
            packet_bytes=remote.memory(0xc29a3868,32)
            assert packet_bytes.hex()==case['coefficient_packet']['bytes']
            sent=invoke(0x1011b7bc,bytes.fromhex(built['output']),[4,('scratch',0)])
            assert int(sent['return_r0'],16)==0
            report['replay'].update(events_start=start,events_end=len(events),context=built['output'],
                coefficient_packet=packet_bytes.hex(),global_context_unchanged=remote.memory(0xc18fa844,0xe4)==context_before)
            assert report['replay']['global_context_unchanged']
        finally:
            for address,data in originals.items():write(address,data)
            for address,data in originals.items():assert remote.memory(address,len(data))==data
            report['replay']['restored']=True
    report['ok']=True
except Exception:
    report['error']=traceback.format_exc();print(report['error'],flush=True)
finally:
    camera.close_guest();report['firmware_unchanged']=hashlib.sha256(ui.FIRMWARE.read_bytes()).hexdigest()==digest
    report['event_count']=len(events)
    (a.output/'events.json').write_text(json.dumps(events,indent=2),encoding='utf-8')
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    shutil.copytree(camera.directory,a.output/'session');print('SAVED',report['ok'],len(events),flush=True)
sys.exit(0 if report['ok'] else 1)

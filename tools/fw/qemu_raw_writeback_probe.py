"""Observe the initial still RAW destination, under the existing synthetic boot.

Read original descriptors and full declared buffer extents before/after the
bounded capture attempt. No new firmware/RAM patches or completion injections.
These are emulator RAM bytes, not sensor samples or a saved NEF.
"""
from pathlib import Path
import argparse, gzip, hashlib, json, shutil, struct, sys, traceback

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--repo',type=Path,required=True)
p.add_argument('--firmware',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--settle-ticks',type=int,default=5000)
a=p.parse_args();assert 1<=a.settle_ticks<=10000
a.output.mkdir(parents=True,exist_ok=False)
source=Path(__file__).read_bytes();(a.output/'probe-source.py').write_bytes(source)
sys.path.insert(0,str(a.repo/'tools'));import interactive as ui
ui.FIRMWARE=a.firmware.resolve(strict=True)
ui.BUILD_MANIFEST=a.repo/'.local/build-manifest.json'
digest=ui.checked_firmware(ui.FIRMWARE)
assert digest=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
camera=ui.Camera(8787,profile='shooting',capture_control_test=True,
    raw_source=ui.active_manifest('native0'),exmcu_no_lens=True,
    tg_periodic_test=True,tg_paired_test=True,raw_ingress_test=ui.active_ingress(),
    isp_boundary_test=True,orientation_fixture=0,keep_awake=True,photo_liveview=True,
    firmware_sha256=digest)
camera.exposure_probe=True;camera.isp_disable_cache=False;camera.tg_period_ms=None
points={
    0x10076a08:'still_lower_submit',
    0x100bd820:'front_full_geometry_entry',
    0x100bd870:'front_full_geometry_built',
    0x100bd8dc:'front_primary_address_assignment',
    0x100bd8ec:'front_primary_descriptor_ready',
    0x100ae33e:'still_raw_processing_entry',
    0x10106980:'replacement_raw_address_configuration',
    0x100af648:'still_raw_encoding_entry',
    0x100a323e:'raw_encoder_descriptor_entry',
}
events=[];phase='synthetic-boot';last_object=0;original=ui.call_fixture
report=dict(ok=False,scope=__doc__,firmware_sha256=digest,
    probe_sha256=hashlib.sha256(source).hexdigest(),calls=[],payloads=[],
    points={hex(k):v for k,v in points.items()},
    arguments={k:str(v) for k,v in vars(a).items()},
    limitations=[
        'Pinned synthetic boot retains 0x29e=1, sensor-pointer fallback, synthetic input and device/time fixtures.',
        'CaptureWithoutCard is a diagnostic guest call, not passive physical-camera observation.',
        'One hit per breakpoint per call_fixture; not a complete call or bus-write trace.',
        'Before/after equal bytes cannot rule out intervening writes or writes of identical values.',
        'Full extent is descriptor stride times height including padding; packing is not validated.',
        'No ISP correction algorithm, new IRQ, forced wait success, encoding or NEF is supplied.'])
for name in ('nikon-z6.c','nikon-z6-profile.h','nikon-functional-isp.h','nikon-isp-pixels.h'):
    file=a.repo/'qemu'/name
    report.setdefault('model_sources',{})[name]=hashlib.sha256(file.read_bytes()).hexdigest()

def capture(remote,address,size):
    if not address:return dict(address='0x0',skipped='null')
    if not (0x40000000<=address<0xd0000000 and address+size<=0xd0000000 and size<=0x10000):
        return dict(address=hex(address),skipped='outside_snapshot_policy')
    data=remote.memory(address,size)
    return dict(address=hex(address),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())

def word(remote,address):return struct.unpack('<I',remote.memory(address,4))[0]

def object_areas(remote,areas,obj):
    areas['still_object']=capture(remote,obj,0x3c0)
    if not obj:return
    for off in (0x1f8,0x1fc,0x318,0x330):
        areas[f'still_handle_{off:x}']=capture(remote,word(remote,obj+off),0x90)
    owner=word(remote,obj+0x3a4)
    areas['owner']=capture(remote,owner,0x400)

def payload(remote,areas,label):
    row=areas.get('still_handle_1f8',{})
    if 'bytes' not in row:return
    raw=bytes.fromhex(row['bytes'])
    fmt=raw[0x24];stride,w,h=struct.unpack_from('<3H',raw,0x26)
    address=struct.unpack_from('<I',raw,0x34)[0];size=stride*h
    assert fmt in (2,3,4) and 0<size<=64*1024*1024
    assert 0xa0000000<=address<address+size<=0xc0000000
    print('READ_RAW',label,hex(address),size,flush=True)
    data=remote.memory(address,size)
    file=f'{label}-raw.bin.gz';packed=gzip.compress(data,compresslevel=6,mtime=0)
    (a.output/file).write_bytes(packed)
    result=dict(label=label,object=hex(last_object),handle=row['address'],format_id=fmt,
        width=w,height=h,stride=stride,address=hex(address),size=size,
        sha256=hashlib.sha256(data).hexdigest(),nonzero_bytes=size-data.count(0),
        file=file,gzip_sha256=hashlib.sha256(packed).hexdigest(),gzip_size=len(packed))
    report['payloads'].append(result);print('READ_RAW_DONE',json.dumps(result),flush=True)

def observed(*args,**kwargs):
    def observe(remote,regs):
        global last_object
        ri=lambda n:int(regs[f'r{n}'],16)
        pc=ri(15);areas={}
        row=dict(phase=phase,event=points[pc],outer_call=hex(args[2]),registers=regs,memory=areas)
        events.append(row)
        if pc==0x10076a08:
            last_object=word(remote,ri(0));object_areas(remote,areas,last_object)
            if not report['payloads']:payload(remote,areas,'before-front-submit')
        elif pc==0x100bd820:
            areas['front_request']=capture(remote,ri(0),0x10)
            areas['front_handle']=capture(remote,word(remote,ri(0)+4),0x90)
        elif pc==0x100bd870:
            areas['geometry']=capture(remote,ri(0),0x14)
            areas['front_request']=capture(remote,ri(5),0x10)
            areas['front_handle']=capture(remote,word(remote,ri(5)+4),0x90)
        elif pc==0x100bd8dc:
            row['assignment']=dict(address=hex(ri(1)+0x24),value=hex(ri(0)))
            areas['front_request']=capture(remote,ri(5),0x10)
        elif pc==0x100bd8ec:
            areas['front_parameters']=capture(remote,0xc25ee224,0x44)
        elif pc in (0x100ae33e,0x100af648):
            object_areas(remote,areas,word(remote,ri(0)+0xc))
        elif pc==0x10106980:
            areas['driver']=capture(remote,ri(0),0x20)
            areas['replacement_address']=capture(remote,ri(1),8)
        elif pc==0x100a323e:
            areas['encoder_input']=capture(remote,ri(0),0x20)
            areas['encoder_output']=capture(remote,ri(1),0x20)
        if last_object and 'still_object' not in areas:object_areas(remote,areas,last_object)
    observers=dict(kwargs.get('observers') or {});observers.update({pc:observe for pc in points})
    kwargs['observers']=observers;return original(*args,**kwargs)

ui.call_fixture=observed
def invoke(function,payload_bytes,arguments):
    global packet
    result=ui.call_fixture(camera.remote,packet,function,payload_bytes,arguments)
    packet='T05thread:'+result['return_cpu']+';'
    report['calls'].append(dict(phase=phase,function=hex(function),result=result));return result

try:
    print('BOOT',flush=True);camera.boot_shooting();camera.pause();packet=camera.run_to(0x100531bc)
    camera.remote.sock.settimeout(90);print('BASELINE',len(events),flush=True)
    phase='native-without-card';invoke(0x101efaa8,bytes(8),[1])
    request=bytearray(32);request[2]=1;struct.pack_into('<I',request,0x10,1)
    call=invoke(0x101eedb4,request,[('scratch',0),0x10524b7f]);assert int(call['return_r0'],16)==0
    invoke(0x10170cca,bytes(8),[100]);phase='native-settle'
    invoke(0x10170cca,bytes(8),[a.settle_ticks])
    report['final']={};object_areas(camera.remote,report['final'],last_object)
    report['final']['sequence']=capture(camera.remote,0xc2376050,0x100)
    payload(camera.remote,report['final'],'after-bounded-wait')
    report['ok']=True
except Exception:
    report['error']=traceback.format_exc();print(report['error'],flush=True)
finally:
    camera.close_guest()
    report['firmware_unchanged']=hashlib.sha256(ui.FIRMWARE.read_bytes()).hexdigest()==digest
    report['event_count']=len(events)
    (a.output/'events.json').write_text(json.dumps(events,indent=2),encoding='utf-8')
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    shutil.copytree(camera.directory,a.output/'session');print('SAVED',report['ok'],len(events),flush=True)
sys.exit(0 if report['ok'] else 1)

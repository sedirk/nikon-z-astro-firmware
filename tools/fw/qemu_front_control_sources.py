"""Trace modified3 original front-control sources in the pinned no-lens fixture.

Read-only observers. No added sensor values, completion events or image model.
"""
from pathlib import Path
import argparse, hashlib, json, shutil, struct, sys, traceback

ap=argparse.ArgumentParser(description=__doc__)
for name in ('repo','firmware','output'):ap.add_argument('--'+name,type=Path,required=True)
ap.add_argument('--variant',choices=('modified3','front-bit11-lab'),default='modified3')
a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
source=Path(__file__).read_bytes();(a.output/'probe-source.py').write_bytes(source)
sys.path.insert(0,str(a.repo/'tools'))
import interactive as ui
import probe as controller
ui.FIRMWARE=a.firmware.resolve(strict=True);ui.BUILD_MANIFEST=a.repo/'.local/build-manifest.json'
digest=hashlib.sha256(ui.FIRMWARE.read_bytes()).hexdigest()
assert digest=={'modified3':'a8ec90a9b55b2eefcd46e13b0f6acd0b7aa1bc4d9d127d701dee89154b8b04bd',
    'front-bit11-lab':'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b'}[a.variant]
camera=ui.Camera(8787,profile='shooting',capture_control_test=True,
    raw_source=ui.active_manifest('native0'),exmcu_no_lens=True,tg_periodic_test=True,
    tg_paired_test=True,raw_ingress_test=ui.active_ingress(),isp_boundary_test=True,
    orientation_fixture=0,keep_awake=True,photo_liveview=True,allow_modified_firmware=True,firmware_sha256=digest)
camera.exposure_probe=True;camera.isp_disable_cache=False;camera.tg_period_ms=None
points={0x1013f8e8:'owner_control_source',0x1013fa20:'owner_control_copy',
    0x1017c020:'liveview_context_input',
    0x1013fa50:'owner_control_copied',0x100f64b4:'source_control_read',
    0x10179962:'static_input',0x10179b4c:'static_context_ready',
    0x1017d7b6:'static_front_builder',0x1011d7a4:'policy_record',
    0x1010adf6:'master_word_upload',0x1011df8c:'table144_record',
    0x1011e6ba:'group03_selector',0x1011e616:'group03_record',
    0x10179d7c:'temporary_stage_builder',0x10179dd4:'temporary_stage_exit',
    0x100bd8ec:'raw_destination_ready'}
events=[];phase='synthetic-boot';original=ui.call_fixture
report=dict(ok=False,scope=__doc__,variant=a.variant,firmware_sha256=digest,calls=[],windows=[],
    probe_sha256=hashlib.sha256(source).hexdigest(),points={hex(k):v for k,v in points.items()},
    limitations=['Existing synthetic boot settings and zero calibration fixture are unchanged.',
        'Control-flow/memory evidence only; no physical sensor pixels or saved NEF.',
        'Repeated hits capped at 256 per diagnostic call; breakpoint snapshots precede the instruction.'])
for name in ('nikon-z6.c','nikon-z6-profile.h','nikon-functional-isp.h','nikon-isp-pixels.h'):
    report.setdefault('model_sha256',{})[name]=hashlib.sha256((a.repo/'qemu'/name).read_bytes()).hexdigest()

def capture(remote,address,size):
    if not address:return dict(address='0x0',skipped='null')
    assert 0x40000000<=address<address+size<=0xd0000000 and size<=0x10000,(hex(address),size)
    data=remote.memory(address,size)
    return dict(address=hex(address),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())

def word(remote,address):return struct.unpack('<I',remote.memory(address,4))[0]

def observed(*args,**kwargs):
    start=len(events)
    def observe(remote,regs):
        ri=lambda n:int(regs[f'r{n}'],16)
        pc=ri(15);mem={}
        for name,address,n in [('context',0xc18fa844,0xe4),('calibration_state',0xc18fa954,0x20),
            ('source_state',0xc18b7dc0,0x40),('controls',0xc29a3520,0xe0)]:
            mem[name]=capture(remote,address,n)
        if pc==0x1013f8e8:
            mem['source_record']=capture(remote,ri(2),0xb0)
            mem['owner']=capture(remote,word(remote,ri(3)+0x3a4),0x280)
        elif pc in (0x1013fa20,0x1013fa50):
            mem['source_record']=capture(remote,ri(6),0xb0)
            mem['owner']=capture(remote,word(remote,ri(4)+0x3a4),0x280)
        elif pc==0x100f64b4:mem['owner']=capture(remote,ri(0),0x280)
        elif pc==0x10179962:mem['input']=capture(remote,ri(0),0x50)
        elif pc==0x1017c020:mem['input']=capture(remote,ri(0),0x50)
        elif pc==0x1011d7a4:mem['policy_record']=capture(remote,ri(0),128)
        elif pc==0x1010adf6:mem['upload_controls']=capture(remote,ri(1),56)
        elif pc==0x1011df8c:mem['table144_record']=capture(remote,ri(0),588)
        elif pc==0x1011e616:mem['group03_record']=capture(remote,ri(0),52)
        elif pc==0x100bd8ec:mem['front_parameters']=capture(remote,0xc25ee224,0x44)
        events.append(dict(sequence=len(events),phase=phase,event=points[pc],registers=regs,memory=mem))
    obs=dict(kwargs.get('observers') or {});obs.update({pc:observe for pc in points});kwargs['observers']=obs
    saved=set(controller.TRACE_REPEAT)
    if phase!='synthetic-boot':controller.TRACE_REPEAT=saved|set(points)
    try:
        result=original(*args,**kwargs)
        report['windows'].append(dict(phase=phase,start=start,end=len(events),trace_count=len(result['trace']),saturated=len(result['trace'])>=256))
        return result
    finally:controller.TRACE_REPEAT=saved

ui.call_fixture=observed
def invoke(fn,payload,args):
    global packet
    result=ui.call_fixture(camera.remote,packet,fn,payload,args)
    packet='T05thread:'+result['return_cpu']+';'
    report['calls'].append(dict(phase=phase,function=hex(fn),result=result));return result

try:
    print('BOOT',flush=True);camera.boot_shooting();camera.pause();packet=camera.run_to(0x100531bc)
    camera.remote.sock.settimeout(90);phase='native-without-card'
    invoke(0x101efaa8,bytes(8),[1]);request=bytearray(32);request[2]=1;struct.pack_into('<I',request,0x10,1)
    assert int(invoke(0x101eedb4,request,[('scratch',0),0x10524b7f])['return_r0'],16)==0
    invoke(0x10170cca,bytes(8),[100]);phase='native-settle'
    invoke(0x10170cca,bytes(8),[5000]);report['ok']=True
except Exception:
    report['error']=traceback.format_exc();print(report['error'],flush=True)
finally:
    camera.close_guest();report['firmware_unchanged']=hashlib.sha256(ui.FIRMWARE.read_bytes()).hexdigest()==digest
    report['event_count']=len(events)
    (a.output/'events.json').write_text(json.dumps(events,indent=2),encoding='utf8')
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    shutil.copytree(camera.directory,a.output/'session')
    print('SAVED',report['ok'],len(events),flush=True)
sys.exit(0 if report['ok'] else 1)

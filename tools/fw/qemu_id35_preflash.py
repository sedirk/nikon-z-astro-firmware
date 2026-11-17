"""Exact modified4/5 startup, input and static-frontend compatibility review.

Existing synthetic QEMU sensor/calibration/RTOS fixtures remain. No real NEF.
"""
from pathlib import Path
import argparse,hashlib,io,json,shutil,struct,sys,time,traceback
from PIL import Image

def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for n in ('repo','firmware','output'):ap.add_argument('--'+n,type=Path,required=True)
    ap.add_argument('--variant',choices=('modified4','modified5'),required=True)
    ap.add_argument('--profile',choices=('menu','shooting'),required=True);a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=False);(a.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())
    sys.path.insert(0,str(a.repo/'tools'));import interactive as ui;import probe
    digest={'modified4':'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b',
            'modified5':'76474a8977a3bf4b456fe68f9594110714a04c09b4ec575f019ba27fadd0d2d7'}[a.variant]
    ui.FIRMWARE=a.firmware.resolve(strict=True);ui.BUILD_MANIFEST=a.repo/'.local/build-manifest.json'
    assert sha(ui.FIRMWARE.read_bytes())==digest;shooting=a.profile=='shooting'
    report=dict(ok=False,scope=__doc__,variant=a.variant,profile=a.profile,firmware_sha256=digest,
                events=[],windows=[],calls=[],phase='boot',real_pixels=False,physical_flash=False)
    camera=ui.Camera(8787,profile=a.profile,capture_control_test=shooting,
        raw_source=ui.active_manifest('native0') if shooting else None,exmcu_no_lens=shooting,
        tg_periodic_test=shooting,tg_paired_test=shooting,raw_ingress_test=ui.active_ingress() if shooting else None,
        isp_boundary_test=shooting,orientation_fixture=0 if shooting else None,keep_awake=shooting,
        photo_liveview=shooting,allow_modified_firmware=True,firmware_sha256=digest)
    camera.exposure_probe=shooting;camera.isp_disable_cache=False;camera.tg_period_ms=None
    points={0x10179962:'static_input',0x1017d7b6:'static_builder',0x1017c020:'live_input',0x100bd8ec:'raw_destination',0x1011c750:'id35_dispatch',0x10179d5a:'id35_return',0x10179dd4:'temporary_exit'}
    original=ui.call_fixture
    def observe(remote,regs):
        pc=int(regs['r15'],16);r0=int(regs['r0'],16)
        row=dict(phase=report['phase'],event=points[pc],registers=regs,context=remote.memory(0xc18fa844,0xe4).hex())
        if pc in (0x1011c750,0x10179d5a,0x10179dd4):row['global_packet']=remote.memory(0xc29a3230,0x84).hex()
        if pc in (0x10179962,0x1017c020):row['input']=remote.memory(r0,0x50).hex()
        if pc==0x100bd8ec:row['front_parameters']=remote.memory(0xc25ee224,0x44).hex()
        report['events'].append(row)
    def observed(*args,**kwargs):
        obs=dict(kwargs.get('observers') or {});obs.update({pc:observe for pc in points});kwargs['observers']=obs
        saved=set(probe.TRACE_REPEAT)
        if report['phase']!='boot':probe.TRACE_REPEAT=saved|set(points)
        try:
            r=original(*args,**kwargs);report['windows'].append(dict(phase=report['phase'],trace_count=len(r['trace']),saturated=len(r['trace'])>=256));return r
        finally:probe.TRACE_REPEAT=saved
    ui.call_fixture=observed
    def frame(name):
        image=Image.open(io.BytesIO(camera.png)).convert('RGB')
        assert any(lo!=hi for lo,hi in image.getextrema()),'Blank '+name
        (a.output/name).write_bytes(camera.png)
        report.setdefault('image_pixels',{})[name]=sha(image.tobytes())
    try:
        print('BOOT',a.variant,a.profile,flush=True)
        if shooting:camera.boot_shooting()
        else:
            camera.boot()
            for _ in range(3):time.sleep(1);camera.refresh()
        camera.pause();packet=camera.run_to(0x100531bc);camera.remote.sock.settimeout(90)
        report['boot_reached_dispatch']=True;report['boot_state']=camera.snapshot();frame('boot.png')
        if shooting:
            report['phase']='dial';packet,before=camera.exposure_observation(packet);turns=[]
            for key in ('main_ccw','main_cw'):
                packet=camera.dial_or_mode(packet,key);packet,state=camera.exposure_observation(packet);turns.append(dict(action=key,exposure=state))
            assert turns[-1]['exposure']['tv']==before['tv'];report['dial']=dict(before=before,turns=turns,returned_to_baseline=True)
            def invoke(fn,payload,args):
                nonlocal packet
                r=ui.call_fixture(camera.remote,packet,fn,payload,args);packet='T05thread:'+r['return_cpu']+';'
                report['calls'].append(r);return r
            report['phase']='static_request'
            invoke(0x101efaa8,bytes(8),[1]);request=bytearray(32);request[2]=1;struct.pack_into('<I',request,0x10,1)
            assert int(invoke(0x101eedb4,request,[('scratch',0),0x10524b7f])['return_r0'],16)==0
            invoke(0x10170cca,bytes(8),[100]);report['phase']='static_settle';invoke(0x10170cca,bytes(8),[5000])
            inputs=[e for e in report['events'] if e['event']=='static_input'];builders=[e for e in report['events'] if e['event']=='static_builder']
            assert inputs and builders
            expected=2  # Both inherit modified4's earlier static override.
            assert all(bytes.fromhex(e['input'])[0x45]==expected for e in inputs)
            assert all(bytes.fromhex(e['context'])[0x5d]==expected for e in builders)
            dest=[e for e in report['events'] if e['event']=='raw_destination'];assert dest
            report['static_control']=dict(expected=expected,input_count=len(inputs),builder_count=len(builders),raw_destination_count=len(dest))
            kinds=[int(e['registers']['r0'],16) for e in report['events'] if e['phase']=='static_settle' and e['event']=='id35_dispatch']
            assert kinds==([4,1,2] if a.variant=='modified5' else [0,1,2]),kinds
            returns=[e for e in report['events'] if e['phase']=='static_settle' and e['event']=='id35_return']
            assert len(returns)==1 and int(returns[0]['registers']['r0'],16)==0
            assert any(e['event']=='temporary_exit' and e['phase']=='static_settle' for e in report['events'])
            report['id35_dispatch_kinds']=kinds
        else:
            report['phase']='menu_down';camera.key(packet,'down');report['menu_key_submitted']=True
        report['phase']='resume';camera.continue_guest();time.sleep(1);camera.refresh();camera.pause();frame('after.png')
        report['final_state']=camera.snapshot();assert report['final_state']['error'] is None
        assert not any(x['saturated'] for x in report['windows']);report['ok']=True
    except Exception:
        report['error']=traceback.format_exc();print(report['error'],flush=True)
        # Capture a failed synthetic call before shutting down; no retry or
        # fabricated completion, and no guest code/memory modifications.
        report['active_fixture_on_error']=probe.ACTIVE_FIXTURE
        try:
            camera.remote.sock.settimeout(5)
            camera.remote.sock.sendall(b'\x03')
            report['error_stop_packet']=camera.remote.receive()
            report['error_registers']=camera.remote.registers()
            report['error_threads']=camera.remote.command('qfThreadInfo')
            report['error_context']=camera.remote.memory(0xc18fa844,0xe4).hex()
        except Exception:
            report['error_capture_failed']=traceback.format_exc()
    finally:
        ui.call_fixture=original;camera.close_guest()
        report['firmware_unchanged']=sha(a.firmware.read_bytes())==digest
        report['controller_sources']={n:sha((a.repo/'tools'/n).read_bytes()) for n in ('interactive.py','probe.py')}
        report['model_sources']={n:sha((a.repo/'qemu'/n).read_bytes()) for n in ('nikon-z6.c','nikon-z6-profile.h','nikon-functional-isp.h','nikon-isp-pixels.h')}
        shutil.copytree(camera.directory,a.output/'session');(a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print('SAVED',report['ok'],len(report['events']),flush=True)
    return 0 if report['ok'] else 1
if __name__=='__main__':raise SystemExit(main())

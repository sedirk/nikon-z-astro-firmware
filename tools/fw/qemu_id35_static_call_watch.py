"""Observe the ID35 static call tag in the pinned zero-calibration QEMU fixture.

Only read observers are added. This checks dispatch and return on QEMU, not
physical pixel processing or a saved NEF. Existing sensor/RTOS/model fixtures
are explicitly retained and have no status as a recovered Nikon ISP formula.
"""
from pathlib import Path
import argparse,hashlib,json,shutil,struct,sys,traceback

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for k in ('repo','firmware','output'):ap.add_argument('--'+k,type=Path,required=True)
    ap.add_argument('--variant',choices=('modified4','lab'),required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())
    sys.path.insert(0,str(a.repo/'tools'));import interactive as ui;import probe as control
    sha=lambda b:hashlib.sha256(b).hexdigest()
    digest={'modified4':'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b',
            'lab':'76474a8977a3bf4b456fe68f9594110714a04c09b4ec575f019ba27fadd0d2d7'}[a.variant]
    ui.FIRMWARE=a.firmware.resolve(strict=True);ui.BUILD_MANIFEST=a.repo/'.local/build-manifest.json'
    assert sha(ui.FIRMWARE.read_bytes())==digest
    camera=ui.Camera(8787,profile='shooting',capture_control_test=True,
        raw_source=ui.active_manifest('native0'),exmcu_no_lens=True,tg_periodic_test=True,
        tg_paired_test=True,raw_ingress_test=ui.active_ingress(),isp_boundary_test=True,
        orientation_fixture=0,keep_awake=True,photo_liveview=True,
        allow_modified_firmware=True,firmware_sha256=digest)
    camera.exposure_probe=True;camera.isp_disable_cache=False;camera.tg_period_ms=None
    control.TRACE_WATCH=[]
    points={0x1011c750:'secondary_dispatch',0x1011c760:'native_index_call',
        0x10110c08:'global_parameter_upload',0x100cd6b0:'id35_gate_written',
        0x1011c3f4:'id35_selector',0x10179d5a:'static_kind0_return',
        0x1017d7b6:'static_front_builder',0x10179dd4:'temporary_exit',
        0x100bd8ec:'raw_destination_ready',0x1011e23e:'table33_record'}
    events=[];phase='synthetic-boot';original=ui.call_fixture
    report=dict(ok=False,scope=__doc__,variant=a.variant,firmware_sha256=digest,events=events,
                windows=[],calls=[],hardware_pixels_verified=False,physical_flash=False,calibration='existing zero fixture')
    report['model_sha256']={n:sha((a.repo/'qemu'/n).read_bytes()) for n in ('nikon-z6.c','nikon-z6-profile.h','nikon-functional-isp.h','nikon-isp-pixels.h')}
    def observed(*args,**kwargs):
        def observe(remote,regs):
            pc=int(regs['r15'],16)
            mem={n:dict(address=hex(addr),bytes=remote.memory(addr,size).hex()) for n,addr,size in
                [('context',0xc18fa844,0xe4),('global_packet',0xc29a3230,0x84),('state',0xc18fa954,0x20)]}
            if pc==0x1011e23e:
                addr=int(regs['r0'],16);mem['table33']=dict(address=hex(addr),bytes=remote.memory(addr,300).hex())
            if pc==0x100bd8ec:mem['raw_destination']=dict(address='0xc25ee224',bytes=remote.memory(0xc25ee224,0x44).hex())
            events.append(dict(sequence=len(events),phase=phase,event=points[pc],registers=regs,memory=mem))
        obs=dict(kwargs.get('observers') or {});obs.update({pc:observe for pc in points});kwargs['observers']=obs
        saved=set(control.TRACE_REPEAT)
        if phase!='synthetic-boot':control.TRACE_REPEAT=saved|set(points)
        try:
            r=original(*args,**kwargs);report['windows'].append(dict(phase=phase,trace_count=len(r['trace']),saturated=len(r['trace'])>=256));return r
        finally:control.TRACE_REPEAT=saved
    ui.call_fixture=observed;packet=None
    def invoke(fn,payload,args):
        nonlocal packet
        r=ui.call_fixture(camera.remote,packet,fn,payload,args);packet='T05thread:'+r['return_cpu']+';'
        report['calls'].append(dict(phase=phase,function=hex(fn),result=r));return r
    try:
        print('BOOT',a.variant,flush=True);camera.boot_shooting();camera.pause();packet=camera.run_to(0x100531bc)
        camera.remote.sock.settimeout(60);phase='native-without-card'
        invoke(0x101efaa8,bytes(8),[1]);req=bytearray(32);req[2]=1;struct.pack_into('<I',req,0x10,1)
        assert int(invoke(0x101eedb4,req,[('scratch',0),0x10524b7f])['return_r0'],16)==0
        invoke(0x10170cca,bytes(8),[100]);phase='native-settle';invoke(0x10170cca,bytes(8),[5000])
        active=[e for e in events if e['phase']=='native-settle']
        ds=[int(e['registers']['r0'],16) for e in active if e['event']=='secondary_dispatch']
        assert ds==([4,1,2] if a.variant=='lab' else [0,1,2]),ds
        returns=[e for e in active if e['event']=='static_kind0_return'];assert len(returns)==1
        assert int(returns[0]['registers']['r0'],16)==0
        assert any(e['event']=='static_front_builder' for e in active)
        assert any(e['event']=='raw_destination_ready' for e in active)
        assert all(not w['saturated'] for w in report['windows'])
        report.update(ok=True,native_dispatch_kinds=ds)
    except Exception:
        report['error']=traceback.format_exc();print(report['error'],flush=True)
    finally:
        camera.close_guest();report['firmware_unchanged']=sha(ui.FIRMWARE.read_bytes())==digest
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        shutil.copytree(camera.directory,a.output/'session');print('SAVED',report['ok'],len(events),flush=True)
    return 0 if report['ok'] else 1

if __name__=='__main__':sys.exit(main())

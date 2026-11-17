"""Read-only CAL and additional frontend-table observations of modified4.

Uses the pinned existing zero-calibration/no-lens fixture without adding pixel
algorithms, camera completions, or calibration values. Breakpoints precede code.
"""
from pathlib import Path
import argparse, hashlib, json, shutil, struct, sys, traceback

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for k in ('repo','firmware','output'): ap.add_argument('--'+k,type=Path,required=True)
    ap.add_argument('--secondary',action='store_true',help='Observe the earlier ID35 / ID0b frontend stage instead.')
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    source=Path(__file__).read_bytes();(a.output/'probe-source.py').write_bytes(source)
    sys.path.insert(0,str(a.repo/'tools'))
    import interactive as ui
    import probe as controller
    ui.FIRMWARE=a.firmware.resolve(strict=True);ui.BUILD_MANIFEST=a.repo/'.local/build-manifest.json'
    sha=lambda b:hashlib.sha256(b).hexdigest()
    digest=sha(ui.FIRMWARE.read_bytes())
    assert digest=='bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b'
    camera=ui.Camera(8787,profile='shooting',capture_control_test=True,
        raw_source=ui.active_manifest('native0'),exmcu_no_lens=True,tg_periodic_test=True,
        tg_paired_test=True,raw_ingress_test=ui.active_ingress(),isp_boundary_test=True,
        orientation_fixture=0,keep_awake=True,photo_liveview=True,
        allow_modified_firmware=True,firmware_sha256=digest)
    camera.exposure_probe=True;camera.isp_disable_cache=False;camera.tg_period_ms=None
    controller.TRACE_WATCH=[(0xc18812a0,4),(0xc18fa968,4),(0xc18fa970,4)]
    points={0x1011b6f4:'install_cal_base',0x1011d55e:'auxiliary_record_selector',
        0x1011e150:'table48_selector',0x1011e20c:'table48_record',
        0x1011e23e:'table33_record',0x1011e2ce:'table33_selector',
        0x1010b166:'table48_upload',0x1010b3a8:'table33_upload',
        0x1011dddc:'record76_copy',0x1010b058:'record76_upload',
        0x1017d7b6:'static_front_builder',0x10179d7c:'temporary_stage_builder',
        0x10179dd4:'temporary_stage_exit',0x100bd8ec:'raw_destination_ready'}
    if a.secondary:
        controller.TRACE_WATCH=[(0xc18fa96c,4),(0xc18fa970,4)]
        points={0x1011c750:'secondary_dispatch',0x1011c79c:'cal_gate_store',
            0x1011c3f4:'id35_table_selector',0x1011c2a0:'id0b_table_selector',
            0x101229b8:'secondary_descriptor_submit',0x100cd64a:'secondary_global_upload',
            0x100cd6b0:'gate_6103c_written',0x100cda0a:'secondary_processing_upload',
            0x1017d7b6:'static_front_builder',0x10179dd4:'temporary_stage_exit',
            0x100bd8ec:'raw_destination_ready'}
    report=dict(ok=False,scope=__doc__,firmware_sha256=digest,probe_sha256=sha(source),
        points={hex(k):v for k,v in points.items()},calls=[],windows=[],watched_writes=[],
        watch_addresses=[hex(x[0]) for x in controller.TRACE_WATCH],secondary=a.secondary,
        limitations=['Existing synthetic initialization and zero calibration retained.',
            'Watchpoints observe guest instruction writes, not host-side fixture writes.',
            'No physical sensor or saved NEF; no hardware correction algorithm supplied.',
            'Repeated breakpoint hits capped at 256 per diagnostic call.'])
    for name in ('nikon-z6.c','nikon-z6-profile.h','nikon-functional-isp.h','nikon-isp-pixels.h'):
        report.setdefault('model_sha256',{})[name]=sha((a.repo/'qemu'/name).read_bytes())
    events=[];phase='synthetic-boot';original=ui.call_fixture
    def capture(remote,address,size):
        if not address:return dict(address='0x0',skipped='null')
        assert 0x40000000<=address<address+size<=0xd0000000 and size<=0x10000,(hex(address),size)
        b=remote.memory(address,size)
        return dict(address=hex(address),size=size,bytes=b.hex(),sha256=sha(b))
    def observed(*args,**kwargs):
        start=len(events)
        def observe(remote,regs):
            ri=lambda n:int(regs[f'r{n}'],16)
            pc=ri(15);mem={}
            for name,address,n in [('context',0xc18fa844,0xe4),('calibration_state',0xc18fa954,0x20),
                ('resource38',0xc1881298,28),('packet',0xc29a34c0,0x60),
                ('table48',0xc29a3664,0xc8)]:mem[name]=capture(remote,address,n)
            if a.secondary:
                for name,address,n in [('secondary_global',0xc29a3230,0x84),
                    ('secondary_processing',0xc29a32b4,0x60)]:
                    mem[name]=capture(remote,address,n)
            records={0x1011e20c:(0,16),0x1011e23e:(0,300),0x1011dddc:(0,76),
                0x1010b166:(1,200),0x1010b3a8:(1,264),0x1010b058:(1,80)}
            if pc in records:
                reg,n=records[pc];mem['record']=capture(remote,ri(reg),n)
            events.append(dict(sequence=len(events),phase=phase,event=points[pc],registers=regs,memory=mem))
        obs=dict(kwargs.get('observers') or {});obs.update({pc:observe for pc in points});kwargs['observers']=obs
        saved=set(controller.TRACE_REPEAT)
        if phase!='synthetic-boot':controller.TRACE_REPEAT=saved|set(points)
        try:
            r=original(*args,**kwargs)
            for e in r['trace']:
                if 'watch' in e:report['watched_writes'].append(dict(phase=phase,call_function=r['function'],**e))
            report['windows'].append(dict(phase=phase,start=start,end=len(events),trace_count=len(r['trace']),saturated=len(r['trace'])>=256))
            return r
        finally:controller.TRACE_REPEAT=saved
    ui.call_fixture=observed
    packet=None
    def invoke(fn,payload,args):
        nonlocal packet
        r=ui.call_fixture(camera.remote,packet,fn,payload,args)
        packet='T05thread:'+r['return_cpu']+';'
        report['calls'].append(dict(phase=phase,function=hex(fn),result=r));return r
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
        camera.close_guest();report['firmware_unchanged']=sha(ui.FIRMWARE.read_bytes())==digest
        report['event_count']=len(events)
        (a.output/'events.json').write_text(json.dumps(events,indent=2),encoding='utf8')
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        shutil.copytree(camera.directory,a.output/'session')
        print('SAVED',report['ok'],len(events),flush=True)
    return 0 if report['ok'] else 1

if __name__=='__main__':sys.exit(main())

"""Boot each actual candidate module and cross-check its narrow code changes.

Uses the existing synthetic QEMU profile. Original code runs to function return
or a named pre-submission breakpoint. No ISP completion, pixel arithmetic or
NEF output is supplied. The submission call is never allowed to execute in the
bounded RAW-request experiment; all saved CPU/scratch/request state is restored.
"""
from pathlib import Path
import argparse, hashlib, json, shutil, struct, sys, traceback

p=argparse.ArgumentParser(description=__doc__)
for key in ('repo','modules','output'): p.add_argument('--'+key,type=Path,required=True)
p.add_argument('--original',type=Path,required=True)
p.add_argument('--variant',action='append',help='Run only selected candidate IDs (or original); preserves earlier run directories.')
a=p.parse_args(); a.output.mkdir(parents=True,exist_ok=False)
(a.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())
sys.path.insert(0,str(a.repo/'tools'))
import interactive as ui
import probe as controller
ui.BUILD_MANIFEST=a.repo/'.local/build-manifest.json'
build=json.loads((a.modules/'build.json').read_text())
variants=[('original',a.original,build['source_sha256'])]+[(c['id'],a.modules/c['file'],c['output_sha256']) for c in build['candidates']]
if a.variant:
    assert set(a.variant)<={v[0] for v in variants}
    variants=[v for v in variants if v[0] in a.variant]
report=dict(ok=False,scope=__doc__,probe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),runs=[],
    limitations=['Existing boot assumptions, synthetic sensor/clock/input and zero physical calibration persist.',
      'Native capture request supplies an object for cloning; completed capture is not assumed.',
      'Property and parameter checks use artificial black scalar 300 in isolated guest scratch.',
      'RAW routing is stopped before 0x100b4c78; no processing submission or completion is fabricated.',
      'Cold boot here is emulator compatibility, not camera installation or recovery verification.'])
original_call=ui.call_fixture


def memory(remote,address,size):
    data=remote.memory(address,size)
    return dict(address=hex(address),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())


def word(remote,address): return struct.unpack('<I',remote.memory(address,4))[0]
def write(remote,address,data): assert remote.command(f'M{address:x},{len(data):x}:'+data.hex())=='OK'
def scratch_address(remote,packet,n):
    remote.command('Hg'+packet.split('thread:')[1].split(';')[0])
    return (int(remote.registers()['r13'],16)-n-7)&~7


def bounded_request(remote,packet,payload,args):
    """Execute to submission entry, then restore context without executing it."""
    thread=packet.split('thread:')[1].split(';')[0]
    assert remote.command('Hg'+thread)=='OK'
    saved=remote.command('g'); regs=bytearray.fromhex(saved); assert len(regs)==68
    scratch=(struct.unpack_from('<I',regs,52)[0]-len(payload)-7)&~7
    old_scratch=remote.memory(scratch,len(payload))
    old_request=remote.memory(0xc233525c,0x390)
    write(remote,scratch,payload)
    for i,val in enumerate(args): struct.pack_into('<I',regs,i*4,val)
    struct.pack_into('<I',regs,52,scratch); struct.pack_into('<I',regs,56,0x100202b4)
    struct.pack_into('<I',regs,60,0x100ae33e)
    cpsr=struct.unpack_from('<I',regs,64)[0]; struct.pack_into('<I',regs,64,cpsr|32)
    points={0x100ae3b0,0x100b4c78,0x100202b4}; active=set(points); traces=[]
    result=dict(entry='0x100ae33e',stop='0x100b4c78',submitted=False,restored=False,scratch=hex(scratch),input=payload.hex())
    try:
        for pc in points: assert remote.command(f'Z1,{pc:x},2')=='OK'
        assert remote.command('G'+regs.hex())=='OK'
        while True:
            remote.send('c'); stopped=remote.receive()
            cpu=stopped.split('thread:')[1].split(';')[0]; assert remote.command('Hg'+cpu)=='OK'
            values=remote.registers(); pc=int(values['r15'],16)
            assert pc in (0x100ae3b0,0x100b4c78),values
            traces.append(dict(pc=hex(pc),registers=values,instructions=memory(remote,pc,4)))
            if pc==0x100b4c78:
                result.update(request=memory(remote,0xc233525c,0x390),traces=traces,return_cpu=cpu)
                break
            assert remote.command(f'z1,{pc:x},2')=='OK'; active.remove(pc)
    finally:
        for pc in active: remote.command(f'z1,{pc:x},2')
        write(remote,0xc233525c,old_request); write(remote,scratch,old_scratch)
        assert remote.command('G'+saved)=='OK'
        assert remote.memory(scratch,len(payload))==old_scratch
        assert remote.memory(0xc233525c,0x390)==old_request
        result['restored']=True
    return result,'T05thread:'+result['return_cpu']+';'


try:
    for name,firmware,digest in variants:
        destination=a.output/name; destination.mkdir()
        ui.FIRMWARE=firmware.resolve(strict=True)
        assert ui.checked_firmware(ui.FIRMWARE,allow_modified=name!='original',expected_sha256=digest)==digest
        camera=ui.Camera(8787,profile='shooting',capture_control_test=True,raw_source=ui.active_manifest('native0'),
            exmcu_no_lens=True,tg_periodic_test=True,tg_paired_test=True,raw_ingress_test=ui.active_ingress(),
            isp_boundary_test=True,orientation_fixture=0,keep_awake=True,photo_liveview=True,
            allow_modified_firmware=name!='original',firmware_sha256=digest)
        camera.exposure_probe=True; camera.isp_disable_cache=False; camera.tg_period_ms=None
        run=dict(id=name,firmware_sha256=digest,ok=False,events=[],calls=[],phase='boot')
        report['runs'].append(run); last_frame=[0]
        points={0x10076a08:'still_front',0x100c2790:'static_scalar_patch_site',0x1019f448:'negative_patch_site',
                0x100ae33e:'raw_request_entry',0x100ae3b0:'raw_request_patch_site'}
        def observed(*args,**kwargs):
            def observer(remote,regs):
                pc=int(regs['r15'],16)
                if pc==0x10076a08: last_frame[0]=word(remote,int(regs['r0'],16))
                run['events'].append(dict(phase=run['phase'],pc=hex(pc),label=points[pc],registers=regs,
                    instructions=memory(remote,pc,4 if pc!=0x1019f448 else 2)))
            observers=dict(kwargs.get('observers') or {}); observers.update({pc:observer for pc in points})
            kwargs['observers']=observers
            return original_call(*args,**kwargs)
        ui.call_fixture=observed
        try:
            print('BOOT',name,flush=True)
            camera.boot_shooting(); camera.pause(); packet=camera.run_to(0x100531bc)
            camera.remote.sock.settimeout(55); remote=camera.remote
            def invoke(fn,payload,args):
                global packet
                result=ui.call_fixture(remote,packet,fn,payload,args)
                packet='T05thread:'+result['return_cpu']+';'
                run['calls'].append(dict(phase=run['phase'],result=result)); return result
            run['boot_reached_dispatch']=True; run['phase']='native-object-acquisition'
            invoke(0x101efaa8,bytes(8),[1])
            request=bytearray(32); request[2]=1; struct.pack_into('<I',request,16,1)
            assert int(invoke(0x101eedb4,request,[('scratch',0),0x10524b7f])['return_r0'],16)==0
            invoke(0x10170cca,bytes(8),[100]); invoke(0x10170cca,bytes(8),[5000])
            frame=last_frame[0]; assert frame
            frame_data=remote.memory(frame,0x3c0); owner=word(remote,frame+0x3a4)
            owner_data=remote.memory(owner,0x3000)
            run['source_object']=dict(frame=memory(remote,frame,0x3c0),owner=memory(remote,owner,0x3000))
            run['phase']='synthetic-scalar-builder'
            payload=bytearray(0x3540); scratch=scratch_address(remote,packet,len(payload))
            payload[:0x3c0]=frame_data; payload[0x400:0x3400]=owner_data
            struct.pack_into('<I',payload,0x3a4,scratch+0x400)
            struct.pack_into('<4H',payload,0x400+0x198,300,300,300,300)
            struct.pack_into('<I',payload,0x3400,scratch)
            struct.pack_into('<2H',payload,0x341c,6104,4222)
            old_properties=remote.memory(0xc2763120,0xa0)
            try:
                generated=invoke(0x100c24f2,payload,[('scratch',0x3400),('scratch',0x3500)])
                props=remote.memory(0xc2763120,0xa0)
                expected=0 if name=='still-offset-source-zero' else 300
                assert struct.unpack_from('<H',props,0x86)[0]==expected
                assert bytes.fromhex(generated['output'])[0x400+0x198:0x400+0x1a0]==struct.pack('<4H',300,300,300,300)
                run['scalar_builder']=dict(properties=memory(remote,0xc2763120,0xa0),expected_scalar=expected,clone_owner_unchanged=True)
            finally:
                write(remote,0xc2763120,old_properties)
                assert remote.memory(0xc2763120,0xa0)==old_properties
            run['phase']='synthetic-negative-builder'
            payload=bytearray(0x800); scratch=scratch_address(remote,packet,len(payload))
            struct.pack_into('<I',payload,0,scratch+0x100); struct.pack_into('<I',payload,0xd0,scratch+0x200)
            struct.pack_into('<H',payload,0x26,512); struct.pack_into('<2H',payload,0x2e,512,512)
            struct.pack_into('<H',payload,0x186,300)
            generated=invoke(0x1019f3d0,payload,[('scratch',0)])
            result=bytes.fromhex(generated['output'])
            negatives=[struct.unpack_from('<H',result,0x200+x)[0] for x in (0x186,0x18c,0x192,0x198)]
            assert negatives==([0]*4 if name=='negative-only' else [65236]*4)
            run['negative_builder']=dict(negative_halfwords=negatives,parameter_bytes=result[0x200:0x700].hex())
            run['phase']='bounded-raw-request'
            payload=bytearray(0x8000); scratch=scratch_address(remote,packet,len(payload))
            payload[0x4800:0x4bc0]=frame_data; payload[0x4c00:0x7c00]=owner_data
            struct.pack_into('<I',payload,0xc,scratch+0x4800)
            for off,val in ((0x3a4,scratch+0x4c00),(0x1f8,scratch+0x7c00),(0x1fc,scratch+0x7d00),
                            (0x330,scratch+0x7e00),(0x314,0),(0x318,scratch+0x7f00)):
                struct.pack_into('<I',payload,0x4800+off,val)
            payload[0x4c00]=0; payload[0x4d90]=0
            for off in (0x7c00,0x7d00):
                payload[off+0x24]=2; struct.pack_into('<3H',payload,off+0x26,9168,6104,4222)
                struct.pack_into('<I',payload,off+0x34,0xa448e000)
            bounded,packet=bounded_request(remote,packet,payload,[scratch])
            request=bytes.fromhex(bounded['request']['bytes'])
            expected=0 if name=='still-preserve-front-raw' else scratch+0x7d00
            assert struct.unpack_from('<I',request,0x1a8)[0]==expected
            assert struct.unpack_from('<I',request,8)[0]==scratch+0x7c00
            bounded['expected_replacement']=hex(expected); run['raw_request']=bounded
            run['ok']=True; print('PASS',name,run['scalar_builder']['expected_scalar'],negatives,hex(expected),flush=True)
        except Exception:
            run['error']=traceback.format_exc(); raise
        finally:
            ui.call_fixture=original_call; camera.close_guest()
            run['firmware_unchanged']=hashlib.sha256(firmware.read_bytes()).hexdigest()==digest
            run['model_sources']={name:hashlib.sha256((a.repo/'qemu'/name).read_bytes()).hexdigest()
                for name in ('nikon-z6.c','nikon-z6-profile.h','nikon-functional-isp.h','nikon-isp-pixels.h')}
            (destination/'result.json').write_text(json.dumps(run,indent=2),encoding='utf-8')
            shutil.copytree(camera.directory,destination/'session')
    report['ok']=True
except Exception:
    report['error']=traceback.format_exc(); print(report['error'],flush=True)
finally:
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('SAVED',report['ok'],len(report['runs']),flush=True)
sys.exit(0 if report['ok'] else 1)

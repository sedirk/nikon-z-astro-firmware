"""Boot exact modified2/modified3 copies and cross-check the native spatial code.

Existing synthetic QEMU hardware, upstream startup fixtures and no-lens profile.
Observed call windows are not exhaustive; synthetic preview is not a real NEF.
"""
from pathlib import Path
import argparse, hashlib, io, json, shutil, struct, sys, time, traceback
from PIL import Image

def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for key in ('repo','firmware','reference','output'):ap.add_argument('--'+key,type=Path,required=True)
    ap.add_argument('--variant',choices=('modified2','spatial-neutral-lab'),required=True)
    ap.add_argument('--profile',choices=('menu','shooting'),default='shooting');a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())
    sys.path.insert(0,str(a.repo/'tools'));import interactive as ui
    ui.BUILD_MANIFEST=a.repo/'.local/build-manifest.json';ui.FIRMWARE=a.firmware.resolve(strict=True)
    digests={'modified2':'6790186e7e088ae7c504677be052aecdbf3868616207bfda5606b36d37149038',
             'spatial-neutral-lab':'a8ec90a9b55b2eefcd46e13b0f6acd0b7aa1bc4d9d127d701dee89154b8b04bd'}
    digest=digests[a.variant];assert sha(ui.FIRMWARE.read_bytes())==digest
    reference=json.loads(a.reference.read_text())
    expected=[r for r in reference['abi'] if r['variant']==a.variant and r['initial_NZCV']==0]
    assert len(expected)==8
    report=dict(ok=False,scope=__doc__,variant=a.variant,profile=a.profile,firmware_sha256=digest,
        reference_sha256=sha(a.reference.read_bytes()),observations=[],cross_checks=[],phase='boot',
        limitations=['Upstream synthetic startup/sensor/clock/calibration/input assumptions remain.',
                    'No-lens liveview and menu are emulator compatibility checks, not real camera boot.',
                    'Nonzero grids/cache are reconstructed fixtures; no ISP or real NEF pixel result.',
                    'Breakpoint observations are limited to call_fixture windows, not all execution.'])
    original_call=ui.call_fixture
    points={0x100c1a48:'shared_precompute_wrapper',0x100c1d9a:'shared_main_wrapper',
            0x10197500:'spatial_generator',0x101722c2:'precompute_after_generator',0x1017208c:'main_after_generator'}
    def observe(remote,regs):
        pc=int(regs['r15'],16);r0=int(regs['r0'],16)
        row=dict(phase=report['phase'],pc=hex(pc),label=points[pc],registers=regs)
        try:
            if pc in (0x100c1a48,0x100c1d9a):
                row['request']=dict(address=hex(r0),bytes=remote.memory(r0,0x34).hex())
            if pc==0x10197500:
                e=remote.memory(r0,32);state=struct.unpack_from('<I',e,28)[0]
                row.update(input= e.hex(),state_address=hex(state),state_before=remote.memory(state,0x6c).hex())
            if pc==0x101722c2:
                context=int(regs['r4'],16);state=struct.unpack('<I',remote.memory(context+0x1c,4))[0]
                row.update(state_address=hex(state),state_after=remote.memory(state,0x6c).hex())
            if pc==0x1017208c:
                state=int(regs['r4'],16)+0x58
                row.update(state_address=hex(state),state_after=remote.memory(state,0x6c).hex())
        except Exception as exc:row['read_error']=str(exc)
        report['observations'].append(row)
    def observed(*args,**kwargs):
        observers=dict(kwargs.get('observers') or {});observers.update({pc:observe for pc in points})
        kwargs['observers']=observers;return original_call(*args,**kwargs)
    ui.call_fixture=observed;shooting=a.profile=='shooting'
    camera=ui.Camera(8787,profile=a.profile,capture_control_test=shooting,
        raw_source=ui.active_manifest('native0') if shooting else None,exmcu_no_lens=shooting,
        tg_periodic_test=shooting,tg_paired_test=shooting,raw_ingress_test=ui.active_ingress() if shooting else None,
        isp_boundary_test=shooting,orientation_fixture=0 if shooting else None,keep_awake=shooting,
        photo_liveview=shooting,allow_modified_firmware=True,firmware_sha256=digest)
    camera.exposure_probe=False;camera.isp_disable_cache=False;camera.tg_period_ms=None
    try:
        print('BOOT',a.variant,a.profile,flush=True)
        if shooting:camera.boot_shooting()
        else:camera.boot()
        if not shooting:
            # The controller returns before its first menu scanout completes.
            # Match the established baseline's settling interval.
            for _ in range(3):time.sleep(1);camera.refresh()
        camera.pause();packet=camera.run_to(0x100531bc);camera.remote.sock.settimeout(45)
        report['boot_reached_dispatch']=True;report['boot_state']=camera.snapshot()
        (a.output/'boot.png').write_bytes(camera.png)
        boot_extrema=Image.open(io.BytesIO(camera.png)).convert('RGB').getextrema()
        assert any(lo!=hi for lo,hi in boot_extrema),'Blank boot image'
        report['boot_image_nonuniform']=True
        if shooting:
            packet,before=camera.exposure_observation(packet);turns=[]
            for key in ('main_ccw','main_cw'):
                packet=camera.dial_or_mode(packet,key);packet,state=camera.exposure_observation(packet)
                turns.append(dict(action=key,exposure=state))
            assert turns[-1]['exposure']['tv']==before['tv']
            report['dial']=dict(before=before,turns=turns,returned_to_baseline=True)
            report['phase']='isolated_nonzero_spatial'
            for ref in expected:
                cfg=ref['fixture'];remote=camera.remote
                remote.command('Hg'+packet.split('thread:')[1].split(';')[0])
                # E+24 onward is the native interpolation workspace; keep
                # source/cache/output/grid well beyond that mutable area.
                src,cache,state,grid=0x1000,0x1100,0x1200,0x1400
                n=0x2200;scratch=(int(remote.registers()['r13'],16)-n-7)&~7
                payload=bytearray(n)
                for off,val in ((0,scratch+src),(4,6064*256),(8,4040*256),(16,scratch+cache),(28,scratch+state)):
                    struct.pack_into('<I',payload,off,val)
                payload[0xd]=cfg['cached'];payload[0x14]=cfg['mode'];struct.pack_into('<2h',payload,0x16,*cfg['xy'])
                payload[src]=cfg['source'];payload[src+0x19]=cfg['bit2'];payload[src+9:src+17]=bytes(range(1,9))
                struct.pack_into('<I',payload,src+0x14,scratch+grid);struct.pack_into('<H',payload,src+0x1a,16)
                payload[cache:cache+2]=bytes(cfg['cache_flags'])
                coeffs=[142,-79,0,-74,-6,61];struct.pack_into('<6i',payload,cache+4,*coeffs)
                payload[state-16:state]=b'\xa3'*16;payload[state:state+0x6c]=b'\x7b'*0x6c;payload[state+0x6c:state+0x7c]=b'\x3a'*16
                for knot in range(8):
                    for c,v in enumerate(coeffs):struct.pack_into('<i',payload,grid+4*(knot*108+c*18),v)
                result=ui.call_fixture(remote,packet,0x10197500,payload,[('scratch',0)])
                packet='T05thread:'+result['return_cpu']+';';out=bytes.fromhex(result['output'])
                checked=dict(fixture=cfg,expected_state=ref['state_hex'],actual_state=out[state:state+0x6c].hex(),
                             exact_unicorn_state_match=False,inputs_canaries_preserved=False,result=result)
                report['cross_checks'].append(checked)
                assert out[state:state+0x6c].hex()==ref['state_hex'],cfg
                for off,length in ((0,32),(src,32),(cache,28),(grid,3456),(state-16,16),(state+0x6c,16)):
                    assert out[off:off+length]==payload[off:off+length],(cfg,hex(off))
                checked.update(exact_unicorn_state_match=True,inputs_canaries_preserved=True)
                print('CROSS_CHECK',cfg,flush=True)
        else:
            report['phase']='menu_input';camera.key(packet,'down');report['menu_key_submitted']=True
        report['phase']='resume';camera.continue_guest();time.sleep(1);camera.refresh();camera.pause()
        extrema=Image.open(io.BytesIO(camera.png)).convert('RGB').getextrema()
        assert any(lo!=hi for lo,hi in extrema),'Blank final image'
        report['final_image_nonuniform']=True
        (a.output/'after.png').write_bytes(camera.png);report['final_state']=camera.snapshot();report['ok']=True
    except Exception:
        report['error']=traceback.format_exc();print(report['error'],flush=True)
    finally:
        ui.call_fixture=original_call;camera.close_guest()
        report['firmware_unchanged']=sha(a.firmware.read_bytes())==digest
        report['controller_sources']={name:sha((a.repo/'tools'/name).read_bytes()) for name in ('interactive.py','probe.py')}
        report['model_sources']={name:sha((a.repo/'qemu'/name).read_bytes()) for name in ('nikon-z6.c','nikon-z6-profile.h','nikon-functional-isp.h','nikon-isp-pixels.h')}
        shutil.copytree(camera.directory,a.output/'session')
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],observations=len(report['observations']),cross_checks=len(report['cross_checks']))),flush=True)
    return 0 if report['ok'] else 1
if __name__=='__main__':raise SystemExit(main())

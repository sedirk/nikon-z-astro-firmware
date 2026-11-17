"""Boot the full-size candidate and cross-check its native size guard in QEMU.

Bounded calls use copied owner data and artificial handles. Stop before image
submission and restore CPU, scratch and request bytes. No exposure or pixels.
"""
from pathlib import Path
import argparse, hashlib, json, shutil, struct, sys, traceback

SHA='7ff43669a82d9def1407056d889db041338dbe12a0bb2867eccfc98527f0875c'
def sha(b): return hashlib.sha256(b).hexdigest()
def memory(r,addr,n):
    b=r.memory(addr,n); return dict(address=hex(addr),size=n,bytes=b.hex(),sha256=sha(b))
def write(r,addr,b): assert r.command(f'M{addr:x},{len(b):x}:'+b.hex())=='OK'


def bounded(r,packet,frame,owner,cfg):
    thread=packet.split('thread:')[1].split(';')[0]
    assert r.command('Hg'+thread)=='OK'
    saved=r.command('g'); regs=bytearray.fromhex(saved); assert len(regs)==68
    payload=bytearray(0x8000)
    scratch=(struct.unpack_from('<I',regs,52)[0]-len(payload)-7)&~7
    payload[0x4800:0x4bc0]=frame; payload[0x4c00:0x7c00]=owner
    struct.pack_into('<I',payload,0xc,scratch+0x4800)
    for off,val in ((0x3a4,scratch+0x4c00),(0x1f8,scratch+0x7c00),
                    (0x1fc,scratch+0x7d00),(0x330,scratch+0x7e00),
                    (0x314,0),(0x318,scratch+0x7f00)):
        struct.pack_into('<I',payload,0x4800+off,val)
    payload[0x4c00]=cfg['kind']; payload[0x4d90]=cfg['mode']; payload[0x4d92]=cfg['size']
    for off in (0x7c00,0x7d00):
        payload[off+0x24]=2; struct.pack_into('<3H',payload,off+0x26,9168,6104,4222)
        struct.pack_into('<I',payload,off+0x34,0x60000000 if off==0x7c00 else 0x64000000)
    old_scratch=r.memory(scratch,len(payload)); old_request=r.memory(0xc233525c,0x390)
    for index,val in ((0,scratch),(13,scratch),(14,0x100202b4),(15,0x100ae33e)):
        struct.pack_into('<I',regs,index*4,val)
    struct.pack_into('<I',regs,64,struct.unpack_from('<I',regs,64)[0]|32)
    points={0x100ae3a4,0x101ba4b6,0x100ae3b0,0x100b4c78,0x100202b4}
    active=set(); events=[]
    row=dict(configuration=cfg,scratch=hex(scratch),payload_sha256=sha(payload),
             entry='0x100ae33e',submitted=False,restored=False)
    try:
        write(r,scratch,payload); write(r,0xc2335404,struct.pack('<I',0x5a5a5a5a))
        for pc in points:
            assert r.command(f'Z1,{pc:x},2')=='OK'; active.add(pc)
        assert r.command('G'+regs.hex())=='OK'
        while True:
            r.send('c'); stopped=r.receive()
            cpu=stopped.split('thread:')[1].split(';')[0]
            assert r.command('Hg'+cpu)=='OK'
            values=r.registers(); pc=int(values['r15'],16)
            assert pc in points-{0x100202b4},values
            events.append(dict(pc=hex(pc),registers=values,instructions=memory(r,pc,4)))
            if pc==0x100b4c78:
                row.update(request=memory(r,0xc233525c,0x390),events=events)
                break
            assert r.command(f'z1,{pc:x},2')=='OK'; active.remove(pc)
        packet='T05thread:'+thread+';'
        req=bytes.fromhex(row['request']['bytes'])
        replace=cfg['kind'] not in (3,4,5,6) and cfg['mode'] in (0,1) and cfg['size']!=0
        expected=scratch+0x7d00 if replace else 0
        assert struct.unpack_from('<I',req,0x1a8)[0]==expected
        assert struct.unpack_from('<I',req,8)[0]==scratch+0x7c00
        assert ('0x100ae3b0' in [e['pc'] for e in events])==replace
        if cfg['kind'] not in (3,4,5,6):
            assert [e['pc'] for e in events][:2]==['0x100ae3a4','0x101ba4b6']
            assert events[0]['instructions']['bytes']=='0cf187f8'
        row['expected_replacement']=hex(expected); row['ok']=True
    finally:
        for pc in active: r.command(f'z1,{pc:x},2')
        write(r,0xc233525c,old_request); write(r,scratch,old_scratch)
        assert r.command('Hg'+thread)=='OK'; assert r.command('G'+saved)=='OK'
        assert r.memory(scratch,len(payload))==old_scratch
        assert r.memory(0xc233525c,0x390)==old_request
        row['restored']=True
    return row,packet


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('repo','firmware','observed','output'): p.add_argument('--'+key,type=Path,required=True)
    args=p.parse_args(); assert __debug__
    args.output.mkdir(parents=True,exist_ok=False)
    (args.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())
    sys.path.insert(0,str(args.repo/'tools'))
    import interactive as ui
    ui.BUILD_MANIFEST=args.repo/'.local/build-manifest.json'
    ui.FIRMWARE=args.firmware.resolve(strict=True)
    assert sha(ui.FIRMWARE.read_bytes())==SHA
    observed=json.loads(args.observed.read_text())['final']
    frame=bytes.fromhex(observed['still_object']['bytes']); owner=bytes.fromhex(observed['owner']['bytes'])
    report=dict(ok=False,scope=__doc__,firmware_sha256=SHA,probe_sha256=sha(Path(__file__).read_bytes()),
                observed_sha256=sha(args.observed.read_bytes()),cases=[],
                limitations=['Existing QEMU synthetic hardware/boot assumptions persist.',
                    'Only local predicate and request construction execute; no actual processing or NEF.',
                    'Camera updater, physical recovery and continuous-shooting timing are outside this test.'])
    camera=ui.Camera(8787,profile='shooting',capture_control_test=True,raw_source=ui.active_manifest('native0'),
        exmcu_no_lens=True,tg_periodic_test=True,tg_paired_test=True,raw_ingress_test=ui.active_ingress(),
        isp_boundary_test=True,orientation_fixture=0,keep_awake=True,photo_liveview=True,
        allow_modified_firmware=True,firmware_sha256=SHA)
    camera.exposure_probe=True; camera.isp_disable_cache=False; camera.tg_period_ms=None
    try:
        print('BOOT fullsize candidate',flush=True)
        camera.boot_shooting(); camera.pause(); packet=camera.run_to(0x100531bc)
        report['boot_reached_dispatch']=True; camera.remote.sock.settimeout(45)
        configs=[dict(kind=0,mode=mode,size=size) for mode in (0,1) for size in (0,1,2)]
        configs += [dict(kind=0,mode=2,size=1),dict(kind=3,mode=0,size=1)]
        for cfg in configs:
            report['current_case']=cfg
            result,packet=bounded(camera.remote,packet,frame,owner,cfg)
            report['cases'].append(result)
            print('PASS',cfg,result['expected_replacement'],flush=True)
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc(); print(report['error'],flush=True)
    finally:
        camera.close_guest()
        report['firmware_unchanged']=sha(args.firmware.read_bytes())==SHA
        report['model_sources']={name:sha((args.repo/'qemu'/name).read_bytes())
            for name in ('nikon-z6.c','nikon-z6-profile.h','nikon-functional-isp.h','nikon-isp-pixels.h')}
        shutil.copytree(camera.directory,args.output/'session')
        (args.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return 0 if report['ok'] else 1


if __name__=='__main__': sys.exit(main())

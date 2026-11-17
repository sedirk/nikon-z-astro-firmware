"""Exact-module QEMU control-flow check with disclosed real-record RAM overlays.

Existing diagnostic boot/sensor/IRQ/ISP fixtures remain. Only the specified real
CAL records and ID35 mode1 block are overlaid after boot; all other resources
remain the old fixture. No correction formula, extra completion, or real NEF.
"""
from pathlib import Path
import argparse,hashlib,io,json,shutil,struct,sys,time,traceback
from PIL import Image
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('repo','firmware','output','project'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--variant',choices=('modified4','lab'),required=True);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False);(a.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())
    sys.path.insert(0,str(a.repo/'tools'));import interactive as ui;import probe
    digest={'modified4':'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b',
        'lab':'5c1cdfcd11ccfef301317118c43954bf6b55a50e6574ea66ba941e2f9a716003'}[a.variant]
    ui.FIRMWARE=a.firmware.resolve(strict=True);ui.BUILD_MANIFEST=a.repo/'.local/build-manifest.json'
    assert sha(ui.FIRMWARE.read_bytes())==digest
    source=a.project/'analysis/raw-calibration-access-2026-11-10/camera-calibration-backup-v3'
    cal=(source/'CAL38.bin').read_bytes();fixed=(source/'ID35.bin').read_bytes()
    assert sha(cal)=='914884aa8f0db4d407fd15eb6731ca6f7f388c62c109407e733d09d5ec760372'
    assert sha(fixed)=='d52210383ec47bb473f2faebf3e1b7dd60bcf77f3b018dcba89fdec2bef48baf'
    report=dict(ok=False,scope=__doc__,variant=a.variant,firmware_sha256=digest,events=[],windows=[],calls=[],overlays=[],
        phase='boot',physical_camera=False,real_nef=False,hardware_formula_added=False,extra_completion_added=False)
    camera=ui.Camera(8787,profile='shooting',capture_control_test=True,raw_source=ui.active_manifest('native0'),
        exmcu_no_lens=True,tg_periodic_test=True,tg_paired_test=True,raw_ingress_test=ui.active_ingress(),
        isp_boundary_test=True,orientation_fixture=0,keep_awake=True,photo_liveview=True,
        allow_modified_firmware=True,firmware_sha256=digest)
    camera.exposure_probe=True;camera.isp_disable_cache=False;camera.tg_period_ms=None
    points={0x1017d7b6:'static_builder',0x1011e23e:'table33_source',0x1010b1e8:'table33_control_upload',
        0x10179d5a:'id35_config_return',0x101229b8:'id35_descriptor',0x10179dd4:'temporary_exit',0x100bd8ec:'raw_destination'}
    original=ui.call_fixture
    def observe(remote,regs):
        pc=int(regs['r15'],16)
        row=dict(phase=report['phase'],event=points[pc],registers=regs,context=remote.memory(0xc18fa844,0xe4).hex(),
            cached_controls=remote.memory(0xc29a3744,16).hex(),id35_parameters=remote.memory(0xc29a3230,0x84).hex())
        if pc==0x1011e23e:row['source_record']=remote.memory(int(regs['r0'],16),300).hex()
        if pc==0x1010b1e8:row['uploaded_control']=remote.memory(int(regs['r1'],16),16).hex()
        if pc==0x100bd8ec:row['front_parameters']=remote.memory(0xc25ee224,0x44).hex()
        report['events'].append(row)
    def observed(*args,**kwargs):
        obs=dict(kwargs.get('observers') or {});obs.update({pc:observe for pc in points});kwargs['observers']=obs
        saved=set(probe.TRACE_REPEAT)
        if report['phase']!='boot':probe.TRACE_REPEAT=saved|set(points)
        try:
            r=original(*args,**kwargs);report['windows'].append(dict(phase=report['phase'],count=len(r['trace']),saturated=len(r['trace'])>=256));return r
        finally:probe.TRACE_REPEAT=saved
    ui.call_fixture=observed;packet=None
    def invoke(fn,payload,args):
        nonlocal packet
        r=ui.call_fixture(camera.remote,packet,fn,payload,args);packet='T05thread:'+r['return_cpu']+';'
        report['calls'].append(dict(phase=report['phase'],function=hex(fn),result=r));return r
    def overlay(resource,base,offset,data):
        assert 0xc0000000<=base<base+offset+len(data)<0xd0000000
        before=camera.remote.memory(base+offset,len(data))
        for i in range(0,len(data),512):
            chunk=data[i:i+512];assert camera.remote.command(f'M{base+offset+i:x},{len(chunk):x}:'+chunk.hex())=='OK'
        after=camera.remote.memory(base+offset,len(data));assert after==data
        report['overlays'].append(dict(resource=resource,base=hex(base),offset=hex(offset),bytes=len(data),
            before_sha256=sha(before),after_sha256=sha(data),readback_matches=True))
    def frame(name):
        data=camera.png;im=Image.open(io.BytesIO(data)).convert('RGB');assert any(lo!=hi for lo,hi in im.getextrema())
        (a.output/name).write_bytes(data)
    try:
        print('BOOT',a.variant,flush=True);camera.boot_shooting();camera.pause();packet=camera.run_to(0x100531bc)
        camera.remote.sock.settimeout(60);report['boot_reached_dispatch']=True;frame('boot.png')
        calptr=int.from_bytes(camera.remote.memory(0xc18fa968,4),'little')
        fixedptr=int.from_bytes(camera.remote.memory(0xc18fa96c,4),'little')
        assert calptr and fixedptr
        report['phase']='real_record_overlay'
        overlay('CAL38',calptr,0x540,cal[0x540:0x540+28*80])
        overlay('CAL38',calptr,0x47180,cal[0x47180:0x47180+6600])
        overlay('ID35',fixedptr,0xacdf0,fixed[0xacdf0:0xb2d50])
        print('OVERLAY VERIFIED',a.variant,flush=True)
        report['phase']='static_request';invoke(0x101efaa8,bytes(8),[1])
        request=bytearray(32);request[2]=1;struct.pack_into('<I',request,0x10,1)
        assert int(invoke(0x101eedb4,request,[('scratch',0),0x10524b7f])['return_r0'],16)==0
        invoke(0x10170cca,bytes(8),[100]);report['phase']='static_settle';invoke(0x10170cca,bytes(8),[5000])
        active=[e for e in report['events'] if e['phase'].startswith('static')]
        builders=[e for e in active if e['event']=='static_builder'];assert len(builders)==1
        assert bytes.fromhex(builders[0]['context'])[0]==1
        gates=[e for e in active if e['event']=='id35_config_return'];assert len(gates)==1
        assert struct.unpack_from('<I',bytes.fromhex(gates[0]['id35_parameters']),0x1c)[0]==1
        descriptors=[e for e in active if e['event']=='id35_descriptor']
        assert any(int(e['registers']['r0'],16)==fixedptr+0xacdf0 and int(e['registers']['r1'],16)==0x5f60 for e in descriptors)
        uploads=[e for e in active if e['event']=='table33_control_upload' and struct.unpack_from('<I',bytes.fromhex(e['context']),0x84)[0]==1]
        assert uploads and all(bytes.fromhex(e['uploaded_control'])[4]==(0 if a.variant=='lab' else 1) for e in uploads)
        assert any(e['event']=='temporary_exit' for e in active)
        assert any(e['event']=='raw_destination' for e in active)
        assert not any(w['saturated'] for w in report['windows'])
        report['phase']='resume';camera.continue_guest();time.sleep(1);camera.refresh();camera.pause();frame('after.png')
        report['final_state']=camera.snapshot();assert report['final_state']['error'] is None
        report.update(ok=True,target_upload_count=len(uploads),original_id35_transfer_preserved=True)
    except Exception:
        report['error']=traceback.format_exc();print(report['error'],flush=True)
        report['active_fixture_on_error']=probe.ACTIVE_FIXTURE
        try:
            camera.remote.sock.settimeout(5);camera.remote.sock.sendall(b'\x03');report['error_stop_packet']=camera.remote.receive()
            report['error_registers']=camera.remote.registers();report['error_context']=camera.remote.memory(0xc18fa844,0xe4).hex()
        except Exception:report['error_capture_failed']=traceback.format_exc()
    finally:
        ui.call_fixture=original;camera.close_guest();report['firmware_unchanged']=sha(ui.FIRMWARE.read_bytes())==digest
        report['model_sources']={n:sha((a.repo/'qemu'/n).read_bytes()) for n in ('nikon-z6.c','nikon-z6-profile.h','nikon-functional-isp.h','nikon-isp-pixels.h')}
        report['controller_sources']={n:sha((a.repo/'tools'/n).read_bytes()) for n in ('interactive.py','probe.py')}
        shutil.copytree(camera.directory,a.output/'session');(a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print('SAVED',report['ok'],len(report['events']),flush=True)
    return 0 if report['ok'] else 1
if __name__=='__main__':raise SystemExit(main())

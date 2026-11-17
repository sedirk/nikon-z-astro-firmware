"""Cross-check synthetic list generation in QEMU using native heap allocation.

Disposable menu session, original firmware functions, artificial heap inputs.
This actively calls guest functions; it is not passive camera observation.
"""
from pathlib import Path
import argparse,hashlib,json,shutil,struct,sys,time,traceback

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--repo',type=Path,required=True)
p.add_argument('--firmware',type=Path,required=True)
p.add_argument('--expected-root',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
sys.path.insert(0,str(a.repo/'tools'))
import interactive as ui
import probe
ui.FIRMWARE=a.firmware.resolve(strict=True)
ui.BUILD_MANIFEST=a.repo/'.local/build-manifest.json'
digest=ui.checked_firmware(ui.FIRMWARE)
camera=ui.Camera(8787,profile='menu',firmware_sha256=digest)
camera.isp_disable_cache=False;camera.tg_period_ms=None
report=dict(ok=False,firmware_sha256=digest,scope='Synthetic diagnostic calls in a disposable QEMU menu session; native code unchanged; no real calibration or pixel computation.',cases=[])
allocation=None
def write_memory(address,blob):
    for off in range(0,len(blob),4096):
        part=blob[off:off+4096]
        assert camera.remote.command(f'M{address+off:x},{len(part):x}:'+part.hex())=='OK'
def call(function,arguments):
    global packet
    result=probe.call_fixture(camera.remote,packet,function,bytes(32),arguments)
    packet='T05thread:'+result['return_cpu']+';'
    return result
try:
    print('BOOT_MENU',flush=True);camera.boot();camera.pause()
    packet=camera.run_to(0x100531bc)
    result=call(0x1012934a,[0,0x47,0x300000])
    allocation=int(result['return_r0'],16)
    assert allocation
    pointer=int.from_bytes(camera.remote.memory(allocation+4,4),'little')
    bus=int.from_bytes(camera.remote.memory(pointer,4),'little')
    translation=call(0x101e5be2,[bus]);base=int(translation['return_r0'],16)
    report['allocation']=dict(descriptor=hex(allocation),bus=hex(bus),cpu=hex(base),bytes=0x300000,
                              native_allocator_call=result,address_translation=translation)
    print('ALLOCATED',hex(base),flush=True)
    inputs=[base+0x10000,base+0x30000,base+0x60000]
    geom=base+0x80000;work=base+0x100000;out=base+0x1c0000
    write_memory(base,bytes(0x300000))
    write_memory(base,struct.pack('<7I',*inputs,out,geom,work,2))
    write_memory(geom,struct.pack('<4I',0,0,0,6064)*7)
    for name in ('empty','one-point','pair','weighted'):
        expected=json.loads((a.expected_root/name/'result.json').read_text())
        assert expected['ok'] and expected['firmware_sha256']==digest
        for ptr,n in zip(inputs,(0x14000,0x28000,0x8000)):write_memory(ptr,bytes(n))
        write_memory(inputs[0],struct.pack('<I',len(expected['points'])))
        for i,(x,y) in enumerate(expected['points']):write_memory(inputs[0]+4+4*i,struct.pack('<I',y*6064+x))
        write_memory(inputs[1],struct.pack('<I',len(expected['weighted_points'])))
        for i,(x,y,value) in enumerate(expected['weighted_points']):write_memory(inputs[1]+4+8*i,struct.pack('<IHH',y*6064+x,value,0))
        write_memory(out,b'Z'*(0xdfff8+64));write_memory(work+0xbf400,b'W'*64)
        started=time.perf_counter();result=call(0x10250e28,[base])
        assert int(result['return_r0'],16)==1
        blob=camera.remote.memory(out,0xdfff8)
        sha=hashlib.sha256(blob).hexdigest()
        guards=camera.remote.memory(out+0xdfff8,64)==b'Z'*64 and camera.remote.memory(work+0xbf400,64)==b'W'*64
        row=dict(name=name,call=result,output_sha256=sha,expected_sha256=expected['output_sha256'],
                 matches_unicorn=sha==expected['output_sha256'],guards=guards,seconds=time.perf_counter()-started)
        report['cases'].append(row)
        assert row['matches_unicorn'] and guards,row
        print('MATCH',name,sha,flush=True)
    report['native_free_call']=call(0x10129380,[allocation,0x47])
    assert int(report['native_free_call']['return_r0'],16)==1
    allocation=None
    report['ok']=True
except Exception as exc:
    report.update(error=str(exc),traceback=traceback.format_exc())
    print(report['traceback'],flush=True)
finally:
    report['allocation_freed']=allocation is None
    report['remaining_allocation_discarded_with_guest']=allocation is not None
    camera.close_guest()
    report['firmware_unchanged']=hashlib.sha256(ui.FIRMWARE.read_bytes()).hexdigest()==digest
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    shutil.copytree(camera.directory,a.output/'session')
sys.exit(0 if report['ok'] else 1)

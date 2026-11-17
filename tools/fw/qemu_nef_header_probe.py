"""Native Z6 NEF construction in a booted disposable QEMU guest.

Uses the native heap allocator and metadata/OS services. Descriptor lengths
are fixtures: this is a serialization test, not a completed exposure or codec.
"""
from pathlib import Path
import argparse,hashlib,json,shutil,struct,sys,traceback

ROOT=Path(__file__).resolve().parents[2]
FULLSIZE_SHA='7ff43669a82d9def1407056d889db041338dbe12a0bb2867eccfc98527f0875c'
ORIGINAL_SHA='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
def sha(b): return hashlib.sha256(b).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('repo','firmware','output'): p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--payload',choices=['zeros','markers'],default='markers')
    p.add_argument('--black-level',type=int,choices=[0,300],default=300)
    p.add_argument('--readout',type=int,choices=[0,1],default=1)
    p.add_argument('--depth',type=int,choices=[12,14],default=12)
    a=p.parse_args(); assert __debug__
    a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())
    sys.path.insert(0,str(a.repo/'tools'))
    import interactive as ui
    import probe
    ui.FIRMWARE=a.firmware.resolve(strict=True);ui.BUILD_MANIFEST=a.repo/'.local/build-manifest.json'
    SHA=sha(ui.FIRMWARE.read_bytes());assert SHA in (ORIGINAL_SHA,FULLSIZE_SHA)
    camera=ui.Camera(8787,profile='menu',allow_modified_firmware=SHA!=ORIGINAL_SHA,firmware_sha256=SHA)
    camera.isp_disable_cache=False;camera.tg_period_ms=None
    obs=ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json'
    snap=json.loads(obs.read_text())['final']
    report=dict(ok=False,scope=__doc__,firmware_sha256=SHA,probe_sha256=sha(Path(__file__).read_bytes()),
        observed_sha256=sha(obs.read_bytes()),calls=[],events=[],phase='boot',
        assumptions=['Cloned owner, explicit RAW mode/size/depth fields and artificial raw length.',
            'Native OS/metadata services execute without service-return interception.',
            'No sensor data, encoder completion, storage card or physical NEF sample is supplied.',
            '103fabac is a real host-file-write adapter; it does not model a camera card controller.'],
        configuration=dict(payload=a.payload,black_level=a.black_level,readout=a.readout,depth=a.depth))
    allocation=None;packet=None
    def write(addr,data):
        for off in range(0,len(data),4096):
            part=data[off:off+4096]
            assert camera.remote.command(f'M{addr+off:x},{len(part):x}:'+part.hex())=='OK'
    def word(addr):return struct.unpack('<I',camera.remote.memory(addr,4))[0]
    def put(addr,v,fmt='I'):write(addr,struct.pack('<'+fmt,v))
    def mem(addr,n):
        b=camera.remote.memory(addr,n)
        return dict(address=hex(addr),size=n,bytes=b.hex(),sha256=sha(b))
    def call(fn,args=(),stack=(),observers=None,services=None):
        nonlocal packet
        payload=bytearray(32)
        for i,val in enumerate(stack):struct.pack_into('<I',payload,4*i,val)
        result=probe.call_fixture(camera.remote,packet,fn,payload,list(args),observers=observers,services=services)
        packet='T05thread:'+result['return_cpu']+';'
        report['calls'].append(dict(phase=report['phase'],result=result))
        return int(result['return_r0'],16)
    try:
        print('BOOT native NEF metadata test',flush=True)
        camera.boot();camera.pause();packet=camera.run_to(0x100531bc)
        camera.remote.sock.settimeout(45);report['boot_reached_dispatch']=True
        report['phase']='allocate'
        allocation_size=0x3400000
        allocation=call(0x1012934a,[0,0x47,allocation_size]);assert allocation
        desc=word(allocation+4);bus=word(desc)
        base=call(0x101e5be2,[bus]);assert base
        report['allocation']=dict(handle=hex(allocation),bus=hex(bus),cpu=hex(base),size=allocation_size)
        owner=base;encoded=base+0x10000;preview=base+0x11200
        hh=base+0x12000;ad=base+0x12100;package=base+0x13000;header=base+0x40000
        write(base,bytes(allocation_size));write(owner,bytes.fromhex(snap['owner']['bytes']))
        for off,val in ((0,0),(0x170,0),(0x190,1),(0x192,0),(0x194,0),(0x195,int(a.depth==14)),(0x2811,a.readout)):
            put(owner+off,val,'B')
        put(owner+0x1af0,0)
        for off in (0x198,0x19a,0x19c,0x19e):put(owner+off,a.black_level,'H')
        put(encoded+4,ad+0x20);put(ad+0x20,base+0x200000)
        report['phase']='native-output-descriptor'
        call(0x101254bc,[encoded,owner])
        # Explicit post-encoder payload fixture. This is not a sensor/ISP/codec model.
        width=struct.unpack('<H',camera.remote.memory(encoded+0x52,2))[0]
        height=struct.unpack('<H',camera.remote.memory(encoded+0x54,2))[0]
        stride=((width*a.depth+7)//8+15)&~15
        raw_length=stride*height
        assert raw_length<=word(encoded+0x4c)
        put(encoded+0x5c,raw_length)
        values=[0,1,299,300,301,1023,1024,2047,2048,4095,17,4094,273,274,2049,2]
        if a.depth==14:values=[0,1,299,300,301,4095,4096,8191,8192,16383,17,16382,273,274,8193,2]
        raw=bytearray(raw_length)
        if a.payload=='markers':
            rows=[]
            for phase in range(len(values)):
                row=bytearray();acc=bits=0
                for x in range(width):
                    acc|=values[(x+phase)%len(values)]<<bits;bits+=a.depth
                    while bits>=8:
                        row.append(acc&255);acc>>=8;bits-=8
                if bits:row.append(acc&255)
                rows.append(row)
            for y in range(height):
                row=rows[y%len(values)]
                raw[y*stride:y*stride+len(row)]=row
            write(word(encoded+0x58),raw)
        report['raw_payload']=dict(kind=a.payload,width=width,height=height,stride=stride,depth=a.depth,
            size=raw_length,sha256=sha(raw),address=hex(word(encoded+0x58)),
            marker_values=values if a.payload=='markers' else None,
            packing='Explicit LSB-first test packing with native-descriptor row stride; checked independently by LibRaw. Earlier MSB-first trial is retained in qemu-nef-markers.')
        # Group 13 callbacks require a descriptor even when its payload is empty.
        # This is an explicitly empty preview fixture, not a completed preview.
        put(preview+8,1);put(preview+0x1c,base+0x100000)
        put(hh+4,ad);put(ad,header)
        report['encoded_descriptor']=mem(encoded,0x120)
        report['phase']='native-package'
        assert call(0x100b1634,[1,owner,encoded,preview],stack=[hh,package])==1
        report['package_before']=mem(package,0x90)
        report['phase']='native-nef-header'
        points={0x1026db48,0x1026d8a4,0x1029eb9a,0x10170df0,0x1026ddc4,0x10184414}
        probe.TRACE_REPEAT={0x10184414}
        def observer(remote,regs):
            pc=int(regs['r15'],16)
            event=dict(pc=hex(pc),registers=regs,instructions=mem(pc,4))
            if pc==0x10184414:
                event['tag_descriptor']=mem(int(regs['r0'],16),12)
                event['callback']=regs['r3']
            report['events'].append(event)
        report['header_return']=call(0x103269ac,[0,1,package+0x30],observers={pc:observer for pc in points})
        report['package_after']=mem(package,0x90)
        n=word(package+0x70)
        assert 0<n<=0x6d000,(n,report['header_return'])
        data=camera.remote.memory(header,n)
        (a.output/'native-nef-header.bin').write_bytes(data)
        report['header']=dict(address=hex(header),size=n,sha256=sha(data),prefix=data[:32].hex())
        print('HEADER',n,sha(data),data[:16].hex(),flush=True)
        report['phase']='native-chunks-with-host-file-adapter'
        probe.TRACE_REPEAT=set()
        report['file_writes']=[]
        target=a.output/'serialization-fixture.NEF'
        with target.open('xb') as sink:
            def host_write(remote,regs):
                h,addr,count,out=(int(regs['r'+str(i)],16) for i in range(4))
                assert h==0x5a6
                assert ((base<=addr and addr+count<=base+allocation_size) or
                        (0xc27ea960<=addr and addr+count<=0xc27eab60)),(hex(addr),count)
                payload=remote.memory(addr,count)
                start=sink.tell();written=sink.write(payload);sink.flush()
                assert written==count
                put(out,written)
                report['file_writes'].append(dict(source=hex(addr),offset=start,size=written,sha256=sha(payload)))
                state=bytearray.fromhex(remote.command('g'))
                struct.pack_into('<I',state,0,0x04390080)
                lr=int(regs['r14'],16)
                struct.pack_into('<I',state,60,lr&~1)
                cpsr=struct.unpack_from('<I',state,64)[0]
                struct.pack_into('<I',state,64,(cpsr|0x20) if lr&1 else (cpsr&~0x20))
                assert remote.command('G'+state.hex())=='OK'
            total=word(package+0x40)|(word(package+0x44)<<32)
            report['writer_return']=call(0x1027176a,[0x5a6,1,package+0x30,0],
                stack=[total&0xffffffff,total>>32],services={0x103fabac:host_write})
            assert report['writer_return']==0
            assert sink.tell()==total,(sink.tell(),total)
        report['file']=dict(name=target.name,size=target.stat().st_size,sha256=sha(target.read_bytes()),
            scope='Native NEF header and chunk iterator; explicit host filesystem adapter at 103fabac; synthetic post-encoder payload. Not a sensor capture or physical-card output.')
        print('FILE',report['file'],flush=True)
        report['phase']='free'
        report['free_return']=call(0x10129380,[allocation,0x47]);assert report['free_return']==1
        allocation=None;report['ok']=True
    except Exception:
        report['error']=traceback.format_exc();print(report['error'],flush=True)
        report['active_fixture']=probe.ACTIVE_FIXTURE
        try:
            camera.remote.sock.settimeout(5)
            camera.remote.sock.sendall(b'\x03')
            report['failure_stop']=camera.remote.receive()
            report['failure_cpus']={}
            for cpu in ('p01.01','p01.02'):
                camera.remote.command('Hg'+cpu)
                report['failure_cpus'][cpu]=camera.remote.registers()
            if 'package' in locals():report['package_failure']=mem(package,0x90)
            if 'header' in locals():
                (a.output/'partial-header.bin').write_bytes(camera.remote.memory(header,0x6d000))
        except Exception:
            report['failure_snapshot_error']=traceback.format_exc()
    finally:
        report['allocation_freed']=allocation is None
        report['remaining_allocation_discarded_with_guest']=allocation is not None
        camera.close_guest()
        report['firmware_unchanged']=sha(ui.FIRMWARE.read_bytes())==SHA
        report['model_sources']={name:sha((a.repo/'qemu'/name).read_bytes()) for name in (
            'nikon-z6.c','nikon-z6-profile.h','nikon-functional-isp.h','nikon-isp-pixels.h')}
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        shutil.copytree(camera.directory,a.output/'session')
    return 0 if report['ok'] else 1


if __name__=='__main__':sys.exit(main())

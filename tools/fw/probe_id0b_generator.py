"""Execute the unmodified ID0b generator on explicitly artificial body data.

No sensor pixels, hardware arithmetic, RTOS stubs or memory-write hooks.
The geometry is a disclosed fixture, not a dump from the user's camera.
"""
from pathlib import Path
import argparse, hashlib, json, struct, time
import unicorn as un
from unicorn.arm_const import *

ROOT=Path(__file__).resolve().parents[2];BASE=0x10020000
EXPECTED='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
CTX=0x50000000;ID35=0x50010000;ID34=0x50100000
WORK=0x50400000;OUTPUT=0x51000000;CAL=0x51400000
STACK=0x51ff0000;STOP=0x53000000;OUTSIZE=0x25fff8;WORKSIZE=0x7970cc
OFFSETS=[0x60,0x1ed40,0x4eb90,0xa0cc0,0x14ac30,0x155210,0x1674f0,
         0x16b700,0x172fc0,0x178c90,0x183dc0,0x189a60,0x194b60,0x19dab0,
         0x1afe70,0x1d5ab0,0x1e1eb0]

def sha(b):return hashlib.sha256(b).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--point',action='append',default=[],help='x,y in ID35 first position list')
    ap.add_argument('--list-offset',type=lambda s:int(s,0),default=0x10,
                    choices=(0x10,0x7d18),help='ID35 u32 count offset for the artificial points')
    ap.add_argument('--fixed-word',type=lambda s:int(s,0),help='Change ID35+0xacdf0 only, for separation from its position lists')
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())
    data=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes();assert sha(data)==EXPECTED
    u=un.Uc(un.UC_ARCH_ARM,un.UC_MODE_THUMB)
    n=(len(data)+4095)&~4095;u.mem_map(BASE,n);u.mem_write(BASE,data)
    u.mem_protect(BASE,n,un.UC_PROT_READ|un.UC_PROT_EXEC)
    u.mem_map(0xc1800000,0x1200000);u.mem_map(CTX,0x2000000);u.mem_map(STOP,4096)
    for off in range(0x14000,0x14120,16):
        src,dst,n,handler=struct.unpack_from('<4I',data,off)
        if handler==0x1002006c and 0xc1800000<=dst<dst+n<=0xc2a00000:
            u.mem_write(dst,data[src-BASE:src-BASE+n])
    def put(addr,fmt,*v):u.mem_write(addr,struct.pack('<'+fmt,*v))
    def get(addr,fmt):return struct.unpack('<'+fmt,bytes(u.mem_read(addr,struct.calcsize('<'+fmt))))
    put(0xc18fa954+0x14,'I',CAL)
    geom=CAL+0xcdfc0
    for g in range(7):
        put(geom+0x360+g*4,'2H',0,0)
        put(geom+0x312+g*8,'H',6104);put(geom+0x316+g*8,'H',4222)
    put(CTX,'5I',ID35,ID34,OUTPUT,WORK,0)
    points=[tuple(int(v,0) for v in p.split(',')) for p in a.point]
    assert len(points)<=4000 and all(len(p)==2 and 0<=p[0]<6104 and 0<=p[1]<4222 for p in points)
    put(ID35+a.list_offset,'I',len(points))
    for i,(x,y) in enumerate(points):put(ID35+a.list_offset+4+i*4,'I',6104*y+x)
    if a.fixed_word is not None:put(ID35+0xacdf0,'I',a.fixed_word)
    source_hashes=[sha(bytes(u.mem_read(p,0xd8000 if p==ID35 else 0x100000))) for p in (ID35,ID34)]
    u.mem_write(OUTPUT,bytes([0x5a])*(OUTSIZE+64));u.mem_write(WORK+WORKSIZE,b'W'*64)
    report=dict(ok=False,scope=__doc__,firmware_sha256=EXPECTED,points=points,
                input_resource=dict(resource='ID35',count_offset=hex(a.list_offset),
                    positions_offset=hex(a.list_offset+4),fixed_word=a.fixed_word),
                geometry_fixture=dict(address=hex(geom),origin=[0,0],size=[6104,4222],groups=7,
                    other_fields=0),code_patches=False,service_stubs=False,memory_write_hooks=False,
                unicorn_version=un.__version__)
    blocks=set();pending={};observations=[];source_reads=[]
    def read_source(machine,kind,addr,size,value,user):
        source_reads.append(dict(pc=hex(machine.reg_read(UC_ARM_REG_PC)),offset=hex(addr-ID35),size=size,
                                 bytes=bytes(machine.mem_read(addr,size)).hex()))
    def observe(machine,pc,size,user):
        blocks.add(pc)
        if pc in pending:
            row=pending.pop(pc);head=get(row.pop('_out'),'3I');row['count']=head[1]
            row['records_u16']=[list(get(head[2]+i*12,'6H')) for i in range(min(head[1],32))]
            row['return']=machine.reg_read(UC_ARM_REG_R0);observations.append(row)
        if pc==0x1024d51a:
            desc=machine.reg_read(UC_ARM_REG_R0);out=machine.reg_read(UC_ARM_REG_R2)
            pending[machine.reg_read(UC_ARM_REG_LR)&~1]=dict(
                descriptor=bytes(machine.mem_read(desc,16)).hex(),_out=out,
                mode=get(desc+1,'B')[0],group=get(desc+2,'B')[0])
    u.hook_add(un.UC_HOOK_BLOCK,observe)
    u.hook_add(un.UC_HOOK_MEM_READ,read_source,begin=ID35,end=ID35+0xd7fff)
    u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP|1);u.reg_write(UC_ARM_REG_R0,CTX)
    start=time.perf_counter()
    try:
        u.emu_start(0x1024efc1,STOP,count=40_000_000)
        assert u.reg_read(UC_ARM_REG_PC)==STOP,'instruction budget exceeded'
        assert u.reg_read(UC_ARM_REG_R0)==1
        assert bytes(u.mem_read(OUTPUT+OUTSIZE,64))==b'Z'*64
        assert bytes(u.mem_read(WORK+WORKSIZE,64))==b'W'*64
        assert source_hashes==[sha(bytes(u.mem_read(p,0xd8000 if p==ID35 else 0x100000))) for p in (ID35,ID34)]
        blob=bytes(u.mem_read(OUTPUT,OUTSIZE));(a.output/'generated.bin').write_bytes(blob)
        groups=[]
        for g,off in enumerate(OFFSETS):
            count=struct.unpack_from('<I',blob,g*4)[0]
            assert off+count*2<=OUTSIZE
            words=list(struct.unpack_from('<'+'H'*min(count,64),blob,off))
            groups.append(dict(mode=g,offset=hex(off),count=count,first_words=[hex(w) for w in words]))
        report.update(ok=True,groups=groups,output_sha256=sha(blob),source_hashes_unchanged=True,
                      output_guard=True,workspace_guard=True,tail_marker=blob[0x24fffc:0x250000].hex())
    except Exception as exc:
        report.update(error=str(exc),pc=hex(u.reg_read(UC_ARM_REG_PC)))
    report.update(elapsed_seconds=time.perf_counter()-start,coordinate_calls=observations,source_reads=source_reads,
                  blocks=[hex(x) for x in sorted(blocks)])
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('blocks','coordinate_calls','source_reads')},indent=2))
    if not report['ok']:raise SystemExit(1)

if __name__=='__main__':main()

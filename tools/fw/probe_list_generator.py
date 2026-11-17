"""Run the native C3.80 list generator on disclosed artificial position inputs.

No code edits, service stubs, peripheral model or memory-write hooks. RAM is
synthetic, with the original startup copy region and explicit scratch inputs.
"""
from pathlib import Path
import argparse, hashlib, json, struct, time
import unicorn
from unicorn.arm_const import *

ROOT=Path(__file__).resolve().parents[2]
BASE=0x10020000
EXPECTED='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
CONTEXT=0x50000000; INPUTS=[0x50010000,0x50030000,0x50060000]
GEOMETRY=0x50080000; WORK=0x50400000; OUTPUT=0x50600000
STACK=0x50f00000; STOP=0x53000000; OUTSIZE=0xdfff8

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--point',action='append',default=[],help='x,y encoded as y*6064+x in first simple input stream')
    p.add_argument('--weighted-point',action='append',default=[],help='x,y,value in first 8-byte-record stream')
    a=p.parse_args(); a.output.mkdir(parents=True,exist_ok=False)
    data=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    assert hashlib.sha256(data).hexdigest()==EXPECTED
    uc=unicorn.Uc(unicorn.UC_ARCH_ARM,unicorn.UC_MODE_THUMB)
    uc.mem_map(BASE,(len(data)+4095)&~4095);uc.mem_write(BASE,data)
    uc.mem_protect(BASE,(len(data)+4095)&~4095,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
    uc.mem_map(0xc1800000,0x1200000)
    uc.mem_write(0xc1800000,data[0x11e94dd4-BASE:0x11e94dd4-BASE+0x101400])
    uc.mem_map(CONTEXT,0x1000000)
    uc.mem_map(STOP,4096)
    uc.mem_write(CONTEXT,struct.pack('<7I',*INPUTS,OUTPUT,GEOMETRY,WORK,2))
    for i in range(7):uc.mem_write(GEOMETRY+i*16,struct.pack('<4I',0,0,0,6064))
    points=[tuple(int(x,0) for x in s.split(',')) for s in a.point]
    weighted=[tuple(int(x,0) for x in s.split(',')) for s in a.weighted_point]
    assert len(points)<=0x1a90 and len(weighted)<=0x1a90
    assert all(len(x)==2 and 0<=x[0]<6064 and 0<=x[1]<65536 for x in points)
    assert all(len(x)==3 and 0<=x[0]<6064 and 0<=x[1]<65536 and 0<=x[2]<=65535 for x in weighted)
    uc.mem_write(INPUTS[0],struct.pack('<I',len(points)))
    for i,(x,y) in enumerate(points):uc.mem_write(INPUTS[0]+4+4*i,struct.pack('<I',y*6064+x))
    uc.mem_write(INPUTS[1],struct.pack('<I',len(weighted)))
    for i,(x,y,value) in enumerate(weighted):uc.mem_write(INPUTS[1]+4+8*i,struct.pack('<IHH',y*6064+x,value,0))
    uc.mem_write(OUTPUT,b'Z'*(OUTSIZE+64))
    uc.mem_write(WORK+0xbf400,b'W'*64)
    observed=[]; blocks=set()
    def observe(machine,pc,size,user):
        blocks.add(pc)
        if pc==0x10250394:
            head=struct.unpack('<3I',bytes(machine.mem_read(0xc28593f4,12)))
            mode=bytes(machine.mem_read(0xc28553b0+0x3000+0xf39,1))[0]
            records=bytes(machine.mem_read(head[2],min(head[1],12)*12))
            observed.append(dict(mode=mode,count=head[1],records=records.hex()))
    uc.hook_add(unicorn.UC_HOOK_BLOCK,observe)
    uc.reg_write(UC_ARM_REG_SP,STACK+0xf000)
    uc.reg_write(UC_ARM_REG_LR,STOP|1);uc.reg_write(UC_ARM_REG_R0,CONTEXT)
    start=time.perf_counter()
    report=dict(firmware_sha256=EXPECTED,points=points,weighted_points=weighted,
                scope='Isolated native generator with copied startup data and synthetic RAM. No RTOS, real calibration or pixels.',
                geometry_fixture=[0,0,0,6064],input_type_fixture=2,code_patches=False,service_stubs=False,
                memory_write_hooks=False,unicorn_version=unicorn.__version__,ok=False)
    try:
        uc.emu_start(0x10250e29,STOP,count=20_000_000)
        assert uc.reg_read(UC_ARM_REG_PC)==STOP,'Instruction budget reached'
        assert uc.reg_read(UC_ARM_REG_R0)==1
        assert bytes(uc.mem_read(OUTPUT+OUTSIZE,64))==b'Z'*64
        assert bytes(uc.mem_read(WORK+0xbf400,64))==b'W'*64
        blob=bytes(uc.mem_read(OUTPUT,OUTSIZE));(a.output/'generated.bin').write_bytes(blob)
        descriptors=data[0x11f66eb0-BASE:0x11f66eb0-BASE+84]
        groups=[]
        for g in range(7):
            kind,n,_,_,length,offset=struct.unpack_from('<4B2I',descriptors,12*g)
            streams=[]
            for s in range(3):
                startword=offset+s*length
                words=struct.unpack_from('<'+'I'*length,blob,startword*4)
                nonempty=[];row=0
                for index,w in enumerate(words):
                    if w==0xffffffff:row+=1
                    elif w and w!=0x5a5a5a5a:nonempty.append(dict(word_index=index,row=row,word=hex(w)))
                streams.append(dict(stream=s,sentinels=row,nonempty=nonempty[:100],nonempty_count=len(nonempty),
                                    untouched_5a_words=words.count(0x5a5a5a5a)))
            groups.append(dict(group=g,streams=streams))
        report.update(ok=True,output_sha256=hashlib.sha256(blob).hexdigest(),groups=groups,
                      tail_marker=blob[0xd767c:0xd7680].decode('ascii'),output_guard=True,workspace_guard=True)
    except Exception as exc:
        report.update(error=str(exc),pc=hex(uc.reg_read(UC_ARM_REG_PC)))
    report.update(elapsed_seconds=time.perf_counter()-start,prepack_observations=observed,
                  executed_blocks=[hex(x) for x in sorted(blocks)])
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('groups','executed_blocks','prepack_observations')},indent=2))
    if not report['ok']:raise SystemExit(1)

if __name__=='__main__':main()

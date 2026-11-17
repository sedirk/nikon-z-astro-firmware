"""Original receive-descriptor/publication code in private memory, not a DMA or pixel model.

Packets are deliberately synthetic. The harness invokes bounded segments separately;
it never asserts that a physical transfer, exposure or NEF write completed.
"""
from pathlib import Path
import argparse, hashlib, json, struct, traceback
import unicorn as un
from unicorn.arm_const import *

ROOT=Path(__file__).resolve().parents[2]
BASE,RAM,STACK,STOP=0x10020000,0x50000000,0x52000000,0x53000000
S,P,Q,T,C=0xc18d4090,0xc18faa00,0xc29a42f0,0xc29a42c8,0xc18d4434
RD,WR,DESC=0xc2813140,0xc28132a0,0xc18db630
SOURCE,BUILT,PROPS,CTX,CACHE,A,TABLE,OWNER=[RAM+x for x in (0,0x1000,0x2000,0x3000,0x5000,0x6000,0x8000,0xa000)]
REQ,PROJECTED,REPLY,PORT,HANDLE,CHANNEL,REGTABLE,REGMEM=[RAM+x for x in (0x10000,0x10100,0x10200,0x10300,0x10400,0x10500,0x10600,0x10700)]
SHA='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,
      UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,
      UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert __debug__;a.output.mkdir(parents=True,exist_ok=False)
src=Path(__file__).read_bytes();(a.output/'probe-source.py').write_bytes(src)
fw=ROOT/'firmware/decoded/eg1620_038000.bi';blob=fw.read_bytes()
assert hashlib.sha256(blob).hexdigest()==SHA
uc=un.Uc(un.UC_ARCH_ARM,un.UC_MODE_THUMB)
romsize=(len(blob)+4095)&~4095
uc.mem_map(BASE,romsize);uc.mem_write(BASE,blob)
uc.mem_protect(BASE,romsize,un.UC_PROT_READ|un.UC_PROT_EXEC)
regions=((RAM,0x20000),(STACK,0x10000),(STOP,0x1000),(0xc1800000,0x2000000))
for addr,size in regions:uc.mem_map(addr,size)
initial=[]
for off in range(0x14000,0x14120,16):
    source,dst,size,handler=struct.unpack_from('<4I',blob,off)
    if handler==0x1002006c and 0xc1800000<=dst and dst+size<=0xc3800000:
        initial.append((source,dst,size))
blocks,reads,watched=[],[],[]
def block(_uc,pc,size,_):
    blocks.append(hex(pc))
    if len(blocks)>100000:raise RuntimeError('block cap')
def read_hook(_uc,kind,addr,size,value,_):
    if any(lo<=addr<hi for lo,hi in watched):
        reads.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,
                          bytes=bytes(uc.mem_read(addr,size)).hex()))
uc.hook_add(un.UC_HOOK_BLOCK,block)
# No RAM-write/code hooks: those perturb this installed Unicorn's IT/memset path.
uc.hook_add(un.UC_HOOK_MEM_READ,read_hook)
def put(addr,val,fmt='I'):uc.mem_write(addr,struct.pack('<'+fmt,val))
def get(addr,fmt='I'):return struct.unpack('<'+fmt,uc.mem_read(addr,struct.calcsize(fmt)))[0]
def memory(addr,size):
    data=bytes(uc.mem_read(addr,size))
    return dict(address=hex(addr),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())
report=dict(ok=False,scope=__doc__,firmware_sha256=SHA,probe_sha256=hashlib.sha256(src).hexdigest(),
    unicorn=un.__version__,cases=[],startup_copies=[dict(source=hex(x),destination=hex(y),size=z) for x,y,z in initial],
    limitations=['Private initialized RAM, synthetic packets and artificial peripheral/channel/register-pointer objects.',
        'The DMA register pointers point into ordinary private RAM; no DMA transfer is implemented or forced.',
        'Request prefix stops at 1007b168 before OS-backed config 294; unused tail fields remain synthetic zeros.',
        'Request, transfer setup, validation and completion are separately invoked segments, not one asynchronous transaction.',
        'Only successful callback value 1 publishes; the harness supplies completion status explicitly.',
        'No image payload, physical ISP, real calibration, exposure or saved NEF is exercised.'])
def execute(entry,args=(),until=STOP):
    blocks.clear();reads.clear()
    for reg in REGS:uc.reg_write(reg,0)
    for reg,val in zip(REGS,args):uc.reg_write(reg,val)
    uc.reg_write(UC_ARM_REG_SP,STACK+0xf000);uc.reg_write(UC_ARM_REG_LR,STOP|1)
    report['last_call']=dict(entry=hex(entry),args=[hex(x) for x in args],until=hex(until))
    uc.ctl_flush_tb();uc.emu_start(entry|1,until,count=2000000)
    pc=uc.reg_read(UC_ARM_REG_PC);assert pc==until,hex(pc)
    return dict(**report['last_call'],stopped_at=hex(pc),registers={f'r{i}':hex(uc.reg_read(reg)) for i,reg in enumerate(REGS)},
                sp=hex(uc.reg_read(UC_ARM_REG_SP)),blocks=list(blocks),reads=list(reads))
def reset():
    for addr,size in regions:uc.mem_write(addr,bytes(size))
    for source,dst,size in initial:uc.mem_write(dst,blob[source-BASE:source-BASE+size])
    watched[:]=[(S,S+0x100),(RD,RD+0x2c0),(RAM,RAM+0x11000),
                (0xc2802f7c,0xc2802f7c+5*0xda0),(0xc2813400,0xc281e000)]
def current(slot):return get(DESC+24*slot+12+4*(get(RD+4*slot)&1))
def pending(slot):return get(DESC+24*slot+12+4*(get(WR+4*slot)&1))
def packet(mult,valid=True):
    data=bytearray(0xd8c);data[0]=0x55;data[1]=1;data[2:10]=bytes(range(1,9))
    grid=[0.0]*864
    for knot in range(8):grid[knot*108]=16*mult/(1<<20);grid[knot*108+54]=32*mult/(1<<20)
    struct.pack_into('<864f',data,10,*grid)
    data[-1]=(-sum(data))&255
    if not valid:data[-1]^=1
    return bytes(data)
def pipeline():
    for offset,val in ((0,PROPS),(4,CACHE),(0xd0,A),(0xd8,TABLE),(0xe4,OWNER+0xff8)):put(CTX+offset,val)
    put(PROPS+0x58,6104*256);put(PROPS+0x5c,4222*256)
    steps=[]
    for entry,args in ((0x1015e0a0,()),(0x101c2660,[RAM+0xf000]),(0x10072714,[SOURCE,BUILT]),
                       (0x100c0eda,[BUILT,PROPS+0x2c]),(0x10196fe4,[CTX]),(0x10197500,[CTX+0x160]),
                       (0x101975be,[CTX]),(0x10197678,[CTX])):steps.append(execute(entry,args))
    return dict(calls=steps,coefficients=[get(CTX+0x5c+i*4,'i') for i in range(6)],table=memory(TABLE,68),
                selected_cache=memory(0xc2802f7c+get(S+0xe,'B')*0xda0,0xda0))

calls=[]
try:
    for slot in (15,17):
      for startindex in (0,1):
       for success in (False,True):
        name=f'slot{slot}-index{startindex}-'+('success' if success else 'bad-checksum')
        report['current_case']=name;reset();calls=[]
        calls.append(execute(0x100c3490,until=0x100c34aa))
        assert all(get(RD+i*4)==0 and get(WR+i*4)==1 for i in range(88))
        if startindex:calls.append(execute(0x100c34be,[slot]))
        calls.append(execute(0x10075128,until=0x1007513a))
        assert (get(S+0xb,'B'),get(S+0xc,'B'))==(12,20)
        calls.append(execute(0x1016110e,[1,1]));assert get(S+3,'B')==get(S+6,'B')==1
        calls.append(execute(0x10070366,[0x1c14,1,RAM+0xf008]))
        put(current(0)+0x19,int(slot==17),'H');put(current(7)+0xae,int(slot==17),'B')
        old,new=current(slot),pending(slot);assert old!=new
        uc.mem_write(old,packet(1));uc.mem_write(new,packet(3,success))
        old_memory,new_memory=memory(old,0xd8c),memory(new,0xd8c)
        before=pipeline();assert before['coefficients']==[16,0,0,32,0,0]
        calls.append(execute(0x1007b0bc,[slot,0,0,REQ],until=0x1007b168))
        assert bytes(uc.mem_read(REQ+4,2))==bytes((0x24,0x10 if slot==15 else 0x12))
        assert get(REQ+0xa,'H')==get(REQ+0xc,'H')==0xd8c
        assert get(REQ+0x10)==get(DESC+24*slot+8) and get(REQ+0x14)==new
        request=memory(REQ,64)
        calls.append(execute(0x100cb0a8,[REQ,PROJECTED]));projection=memory(PROJECTED,64)
        assert get(PROJECTED+0x14)==new
        calls.append(execute(0x1008c6a0,[PROJECTED,0],until=0x1008c6b2))
        assert bytes(uc.mem_read(Q,64))==bytes(uc.mem_read(PROJECTED,64))
        # Seed enclosing handler registers and stop before timer/hardware calls.
        calls.append(execute(0x1008c754,[0,0,0,0,P,T,Q,4,0,1000],until=0x1008c772))
        assert get(T+4)==new and get(T+8)==get(T+12)==0xd8c//2 and get(T+16,'B')==4
        transfer=memory(T,24)
        # The serial handle and DMA channel are fixtures. The original code fills
        # register cells in private RAM, with an artificial peripheral address.
        put(PORT+12,HANDLE);put(PORT+24,CHANNEL);put(HANDLE+28,RAM+0x10800)
        put(CHANNEL+4,REGTABLE)
        for i in range(4):put(REGTABLE+i*4,REGMEM+i*4)
        calls.append(execute(0x100d27be,[0,PORT,T],until=0x10068b06))
        dmadesc=int(calls[-1]['registers']['r1'],16);dma=memory(dmadesc,24)
        assert get(dmadesc+20)==new and get(dmadesc+4,'H')==0xd8c//2-1
        native_args=[int(calls[-1]['registers'][f'r{i}'],16) for i in range(3)]
        # Copy the native descriptor because independent entry resets the stack.
        uc.mem_write(RAM+0x10900,bytes(uc.mem_read(dmadesc,24)));native_args[1]=RAM+0x10900
        calls.append(execute(0x10068b06,native_args))
        assert get(REGMEM+12)==new and get(REGMEM+8)==RAM+0x10804
        assert get(REGMEM)&0xffff==0xd8c//2-1
        dma_regs=memory(REGMEM,16)
        calls.append(execute(0x1008bd92,[0xd8c,new]))
        assert int(calls[-1]['registers']['r0'],16)==int(success)
        assert get(P+6,'B')==(0 if success else 8)
        assert current(slot)==old
        put(C,0);put(C+4,slot);put(C+0x28,0x12345678);put(S+0x58,0)
        put(REPLY,int(success),'B');put(REPLY+1,get(P+6,'B'),'B')
        calls.append(execute(0x10131d64,[0,REPLY]))
        assert get(C+0x28)==0 and current(slot)==(new if success else old)
        assert get(RD+4*slot)==startindex+int(success)
        assert get(WR+4*slot)==1+startindex+int(success)
        after=pipeline();mult=3 if success else 1
        assert after['coefficients']==[16*mult,0,0,32*mult,0,0]
        assert list(struct.unpack('<34h',bytes.fromhex(after['table']['bytes'])))==[mult]*17+[2*mult]*17
        assert old_memory==memory(old,0xd8c) and new_memory==memory(new,0xd8c)
        report['cases'].append(dict(name=name,slot=slot,initial_index=startindex,success=success,
            old_pointer=hex(old),receive_pointer=hex(new),published_pointer=hex(current(slot)),
            old_packet=old_memory,received_packet=new_memory,request=request,projection=projection,
            transfer=transfer,dma_descriptor=dma,dma_register_cells=dma_regs,
            scales=memory(S+0xb,2),read_counter=get(RD+slot*4),write_counter=get(WR+slot*4),
            calls=calls,before=before,after=after))
    report['ok']=True
except Exception:
    report['error']=traceback.format_exc();report['failure_pc']=hex(uc.reg_read(UC_ARM_REG_PC))
    report['failure_blocks']=list(blocks);report['failure_reads']=list(reads)
    report['completed_segments_in_failed_case']=calls
    raise
finally:
    report['firmware_unchanged']=hashlib.sha256(fw.read_bytes()).hexdigest()==SHA
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']),pc=hex(uc.reg_read(UC_ARM_REG_PC)))))

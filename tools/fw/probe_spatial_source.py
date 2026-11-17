"""Run original spatial-coefficient source, cache and generator code in private RAM.

Synthetic input packets and IEEE-754 coefficient data are explicitly seeded.
No pixel model, hardware completion, complete exposure, NEF or firmware patch.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import traceback
import unicorn as un
from unicorn.arm_const import *

ROOT=Path(__file__).resolve().parents[2]
BASE,RAM,STACK,STOP=0x10020000,0x50000000,0x52000000,0x53000000
SOURCE,BUILT,PROPS,CTX,CACHE,A,TABLE,OWNER= [RAM+x for x in (0,0x1000,0x2000,0x3000,0x5000,0x6000,0x8000,0xa000)]
STATE=0xc18d4090
COEFF_BASE=0xc2802f7c
SHA='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,
      UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,
      UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
assert __debug__
a.output.mkdir(parents=True,exist_ok=False)
source=Path(__file__).read_bytes()
(a.output/'probe-source.py').write_bytes(source)
fw=ROOT/'firmware/decoded/eg1620_038000.bi'
blob=fw.read_bytes()
assert hashlib.sha256(blob).hexdigest()==SHA
uc=un.Uc(un.UC_ARCH_ARM,un.UC_MODE_THUMB)
size=(len(blob)+4095)&~4095
uc.mem_map(BASE,size);uc.mem_write(BASE,blob)
uc.mem_protect(BASE,size,un.UC_PROT_READ|un.UC_PROT_EXEC)
for addr,size in ((RAM,0x20000),(STACK,0x10000),(STOP,0x1000),(0xc1800000,0x2000000)):
    uc.mem_map(addr,size)
initial=[]
for off in range(0x14000,0x14120,16):
    src,dst,size,handler=struct.unpack_from('<4I',blob,off)
    if handler==0x1002006c and 0xc1800000<=dst and dst+size<=0xc3800000:
        initial.append((src,dst,size))
blocks,reads,writes,property_accesses,source_registers=[],[],[],[],[]
watched=[]

def block(_uc,pc,size,_):
    blocks.append(hex(pc))
    if pc==0x1015d308:
        ptr=uc.reg_read(UC_ARM_REG_R5)
        property_accesses.append(dict(pc=hex(pc),array_pointer=hex(ptr),id=hex(get(ptr)),
                                      sp=hex(uc.reg_read(UC_ARM_REG_SP))))
    if len(blocks)>100000:raise RuntimeError('block cap')

def access(_uc,kind,addr,size,value,_):
    if not any(lo<=addr<hi for lo,hi in watched):return
    row=dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size)
    if kind==un.UC_MEM_WRITE:
        row['value']=hex(value);writes.append(row)
    else:
        row['bytes']=bytes(uc.mem_read(addr,size)).hex();reads.append(row)
uc.hook_add(un.UC_HOOK_BLOCK,block)
# This installed Unicorn build has an already reproduced IT/memset discrepancy
# with RAM-write/code hooks (tools/fw/check_unicorn_memhook.py). Observe reads
# and basic blocks; verify writes through post-call memory snapshots instead.
uc.hook_add(un.UC_HOOK_MEM_READ,access)

def put(addr,val,fmt='I'):uc.mem_write(addr,struct.pack('<'+fmt,val))
def get(addr,fmt='I'):return struct.unpack('<'+fmt,uc.mem_read(addr,struct.calcsize(fmt)))[0]
def memory(addr,size):
    data=bytes(uc.mem_read(addr,size))
    return dict(address=hex(addr),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())
report=dict(ok=False,scope=__doc__,firmware_sha256=SHA,probe_sha256=hashlib.sha256(source).hexdigest(),
            unicorn=un.__version__,startup_copies=[dict(source=hex(s),destination=hex(d),size=n) for s,d,n in initial],cases=[],
            limitations=['Original code is immutable; globals and packets are synthetic.',
                         'No RAM-write or instruction hook in the accepted run; those observers perturb local IT/memset execution.',
                         'State numeric values are not assigned camera/lens meanings by this harness.',
                         'Source packets are not captured lens communication or real calibration.',
                         'No MMIO or image payload is mapped; no saved NEF pixel effect is tested.'])

def execute(entry,args=(),until=STOP):
    blocks.clear();reads.clear();writes.clear();property_accesses.clear();source_registers.clear()
    for reg in REGS:uc.reg_write(reg,0)
    for reg,val in zip(REGS,args):uc.reg_write(reg,val)
    uc.reg_write(UC_ARM_REG_SP,STACK+0xf000);uc.reg_write(UC_ARM_REG_LR,STOP|1)
    report['last_call']=dict(entry=hex(entry),args=[hex(x) for x in args],until=hex(until))
    uc.ctl_flush_tb();uc.emu_start(entry|1,until,count=2000000)
    pc=uc.reg_read(UC_ARM_REG_PC)
    assert pc==until,hex(pc)
    return dict(**report['last_call'],stopped_at=hex(pc),r0=hex(uc.reg_read(UC_ARM_REG_R0)),
                r1=hex(uc.reg_read(UC_ARM_REG_R1)),r2=hex(uc.reg_read(UC_ARM_REG_R2)),
                blocks=list(blocks),reads=list(reads),writes=list(writes),property_accesses=list(property_accesses),
                source_registers=list(source_registers))

def buffer(slot):
    selector=get(0xc2813140+slot*4,'B')&1
    return get(0xc18db630+slot*24+12+selector*4)

def reset(state=1,alternate=False,index=0):
    for addr,size in ((RAM,0x20000),(STACK,0x10000),(0xc1800000,0x2000000)):
        uc.mem_write(addr,bytes(size))
    for src,dst,size in initial:uc.mem_write(dst,blob[src-BASE:src-BASE+size])
    # Original descriptor initialization, with zero-filled packet payloads.
    for slot in (0,7,8,14,15,16,17):
        ptr=buffer(slot)
        assert 0xc1800000<=ptr<0xc3800000,(slot,hex(ptr))
        uc.mem_write(ptr,bytes(get(0xc18db630+slot*24+4,'H')))
    put(STATE+3,1,'B');put(STATE+6,state,'B');put(STATE+0xe,index,'B')
    put(STATE+0xb,20,'B');put(STATE+0xc,20,'B')
    put(0xc24cd198,1) # property 1c14, a RAM property value, not an opcode patch.
    put(buffer(0)+0x19,int(alternate),'H')
    put(buffer(7)+0xae,int(alternate),'B')
    for slot,mult in ((15,1),(17,3)):
        ptr=buffer(slot)
        put(ptr+1,1,'B')
        uc.mem_write(ptr+2,bytes(range(1,9)))
        grid=[0.0]*864
        # 8 knot blocks, 6 output coefficients, 18 basis terms per coefficient.
        # Only the constant basis of C0/C3 is nonzero; ordinary generator runs.
        for knot in range(8):
            grid[knot*108]=mult*16/(1<<20)
            grid[knot*108+3*18]=mult*32/(1<<20)
        uc.mem_write(ptr+10,struct.pack('<864f',*grid))
    put(SOURCE,0,'B')
    for off,val in ((0,PROPS),(4,CACHE),(0xd0,A),(0xd8,TABLE),(0xe4,OWNER+0xff8)):
        put(CTX+off,val)
    put(PROPS+0x58,6104*256);put(PROPS+0x5c,4222*256)
    watched[:]=[(STATE,STATE+0x20),(0xc24cd198,0xc24cd19c),(COEFF_BASE,COEFF_BASE+5*0xda0),
                (BUILT,BUILT+0x80),(PROPS,PROPS+0xa0),(CTX+0x58,CTX+0xc2)]
    watched.append((STACK+0xef00,STACK+0xf000))
    watched.extend((buffer(s),buffer(s)+get(0xc18db630+s*24+4,'H')) for s in (0,7,15,17))

calls=[]
try:
    # Complete original producer, provider and ordinary coefficient generator.
    for name,state,alternate,index in (('ordinary',1,False,0),('alternate',1,True,0),
                                       ('wrap',1,False,4),('source-inactive',0,False,0)):
        report['current_case']=dict(name=name,state=state,alternate=alternate,index=index)
        reset(state,alternate,index)
        calls=[]
        source_before=memory(buffer(17 if alternate else 15),0xd8c)
        calls.append(execute(0x1015e0a0))
        selected=get(STATE+0xe,'B')
        expected_index=(index+1)%5
        assert selected==expected_index
        cache_addr=COEFF_BASE+selected*0xda0
        cache=memory(cache_addr,0xda0)
        report['last_cache']=cache
        expected=[0]*864
        mult=3 if alternate else 1
        if state==1:
            for knot in range(8):expected[knot*108]=16*mult;expected[knot*108+54]=32*mult
        actual=list(struct.unpack('<864i',uc.mem_read(cache_addr+16,3456)))
        assert actual==expected,[(i,x,y) for i,(x,y) in enumerate(zip(actual,expected)) if x!=y][:20]
        assert get(cache_addr,'B')==int(state==1)
        calls.append(execute(0x101c2660,[RAM+0xf000]))
        assert get(RAM+0xf00c)==cache_addr
        calls.append(execute(0x10072714,[SOURCE,BUILT]))
        assert get(BUILT+0x54)==cache_addr+16
        calls.append(execute(0x100c0eda,[BUILT,PROPS+0x2c]))
        assert get(PROPS+0x40)==cache_addr+16
        calls.append(execute(0x10196fe4,[CTX]))
        calls.append(execute(0x10197500,[CTX+0x160]))
        calls.append(execute(0x101975be,[CTX]))
        calls.append(execute(0x10197678,[CTX]))
        coefficients=[get(CTX+0x5c+4*i,'i') for i in range(6)]
        table=list(struct.unpack('<34h',uc.mem_read(TABLE,68)))
        if state==1:
            assert coefficients==[16*mult,0,0,32*mult,0,0],coefficients
            assert table==[mult]*17+[2*mult]*17,table
        else:
            assert coefficients==[0]*6 and table==[0]*34
        assert source_before==memory(buffer(17 if alternate else 15),0xd8c)
        report['cases'].append(dict(name=name,state=state,alternate=alternate,old_index=index,
            selected_index=selected,calls=calls,source_packet=source_before,cache=cache,
            provider=memory(RAM+0xf000,16),built=memory(BUILT,0x80),properties=memory(PROPS,0xa0),
            coefficients=coefficients,table=memory(TABLE,68),exported_coefficients=memory(OWNER+0xff8,28)))
    # Provider type 2 suppresses all four pointers. Do not force this inconsistent
    # state through a type-1 builder that expects a live pointer.
    reset();put(STATE+3,2,'B')
    uc.mem_write(RAM+0xf000,bytes([0xa5])*16)
    call=execute(0x101c2660,[RAM+0xf000])
    assert call['r0']=='0x0' and bytes(uc.mem_read(RAM+0xf000,16))==bytes(16)
    report['cases'].append(dict(name='provider-type2',calls=[call],provider=memory(RAM+0xf000,16)))
    # The publisher prefix maps source state to property 1c14. Stop before
    # its OS-lock/notification wrapper; independently execute its native
    # value-store consumer. This is NOT a continuous publisher transaction.
    for state in range(5):
        report['current_case']=dict(name=f'publish-state-{state}')
        reset(state=state);put(STATE+0x18,0xff,'B');put(0xc24cd198,0x55)
        put(RAM+0xf000,0xa5a5a5a5)
        calls=[execute(0x1015e970,[RAM+0xf000],until=0x10164b5c)]
        mapped=state if state in (1,2,3) else 0
        assert calls[0]['r0']=='0x1c14' and int(calls[0]['r1'],16)==mapped
        assert get(STATE+0x18,'B')==state and get(0xc24cd198)==0x55
        assert get(RAM+0xf000)==0xa5a5a5a5
        calls.append(execute(0x10070366,[0x1c14,mapped,RAM+0xf008]))
        assert calls[-1]['r0']=='0x1' and get(RAM+0xf008)==1
        assert get(0xc24cd198)==mapped
        calls.append(execute(0x1017039e,[0x1c14,0x10163d5c,0]))
        assert int(calls[-1]['r0'],16)==mapped
        report['cases'].append(dict(name=f'publish-state-{state}',state=state,mapped=mapped,
            calls=calls,publication='prefix plus independently entered native value store and getter; OS wrapper not run',
            property_value=memory(0xc24cd198,4),state_memory=memory(STATE,32)))
    reset();put(STATE+0x18,1,'B');put(RAM+0xf000,0xa5a5a5a5)
    call=execute(0x1015e970,[RAM+0xf000])
    assert call['r0']=='0x0' and get(RAM+0xf000)==0xa5a5a5a5
    assert '0x10164b5c' not in call['blocks']
    report['cases'].append(dict(name='publisher-unchanged',calls=[call]))
    # Match property 1c14 to source state for the three non-type-1 branches.
    # Numeric states still have no proven physical lens/camera labels.
    for state in (0,2,3):
        report['current_case']=dict(name=f'builder-state-{state}')
        reset(state=state)
        calls=[execute(0x10070366,[0x1c14,state,RAM+0xf008])]
        calls.append(execute(0x1015e0a0))
        calls.append(execute(0x10072714,[SOURCE,BUILT]))
        calls.append(execute(0x100c0eda,[BUILT,PROPS+0x2c]))
        assert get(BUILT,'B')==(3 if state==3 else 0)
        assert get(PROPS+0x2c,'B')==0 and get(PROPS+0x40)==0
        assert get(PROPS+0x48,'B')==int(state==3)
        for entry,args in ((0x10196fe4,[CTX]),(0x10197500,[CTX+0x160]),
                           (0x101975be,[CTX]),(0x10197678,[CTX])):
            calls.append(execute(entry,args))
        coefficients=[get(CTX+0x5c+4*i,'i') for i in range(6)]
        assert coefficients==[0]*6
        assert bytes(uc.mem_read(TABLE,68))==bytes(68)
        report['cases'].append(dict(name=f'builder-state-{state}',state=state,calls=calls,
            built=memory(BUILT,0x80),properties=memory(PROPS,0xa0),
            coefficients=coefficients,table=memory(TABLE,68)))
    report['ok']=True
except Exception:
    report['error']=traceback.format_exc();report['failure_pc']=hex(uc.reg_read(UC_ARM_REG_PC))
    report['failure_blocks']=list(blocks);report['failure_reads']=list(reads);report['failure_writes']=list(writes)
    report['failure_property_accesses']=list(property_accesses)
    report['failure_source_registers']=list(source_registers)
    report['completed_segments_in_failed_case']=calls
    raise
finally:
    report['firmware_unchanged']=hashlib.sha256(fw.read_bytes()).hexdigest()==SHA
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']),pc=hex(uc.reg_read(UC_ARM_REG_PC)))))

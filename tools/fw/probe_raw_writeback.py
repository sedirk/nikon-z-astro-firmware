"""Replay observed front-end descriptors and native replacement-route predicates.

Original ROM is read-only. MMIO is private ordinary RAM; image payloads are
unmapped. No DMA, sensor, correction math, encoder, OS wait or event is emulated.
"""
from pathlib import Path
import argparse, hashlib, json, struct, traceback
import unicorn as un
from unicorn.arm_const import *

ROOT=Path(__file__).resolve().parents[2]
BASE,RAM,STACK,STOP,MMIO=0x10020000,0x50000000,0x52000000,0x53000000,0x20068000
STAGE,INHANDLE,OUTHANDLE,ENCODED,OBJ,OWNER=[RAM+x for x in (0,0x5000,0x6000,0x7000,0x8000,0x9000)]
REQ=0xc233525c
SHA='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,
      UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,
      UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
p.add_argument('--observed',type=Path,required=True);a=p.parse_args();assert __debug__
a.output.mkdir(parents=True,exist_ok=False)
src=Path(__file__).read_bytes();(a.output/'probe-source.py').write_bytes(src)
native=json.loads((a.observed/'result.json').read_text(encoding='utf-8'))
events=json.loads((a.observed/'events.json').read_text(encoding='utf-8'))
assert native['ok'] and native['firmware_sha256']==SHA
fw=ROOT/'firmware/decoded/eg1620_038000.bi';blob=fw.read_bytes();assert hashlib.sha256(blob).hexdigest()==SHA
uc=un.Uc(un.UC_ARCH_ARM,un.UC_MODE_THUMB);romsize=(len(blob)+4095)&~4095
uc.mem_map(BASE,romsize);uc.mem_write(BASE,blob);uc.mem_protect(BASE,romsize,un.UC_PROT_READ|un.UC_PROT_EXEC)
regions=((RAM,0x10000),(STACK,0x10000),(STOP,0x1000),(0xc1800000,0x2000000),(MMIO,0x2000))
for addr,size in regions:uc.mem_map(addr,size)
blocks,reads=[],[]
def block(_uc,pc,size,_):
    blocks.append(hex(pc))
    if len(blocks)>10000:raise RuntimeError('block cap')
def read_hook(_uc,kind,addr,size,value,_):
    if RAM<=addr<RAM+0x10000 or 0xc1800000<=addr<0xc3800000 or MMIO<=addr<MMIO+0x2000:
        reads.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,
                          bytes=bytes(uc.mem_read(addr,size)).hex()))
uc.hook_add(un.UC_HOOK_BLOCK,block);uc.hook_add(un.UC_HOOK_MEM_READ,read_hook)
def put(addr,val,fmt='I'):uc.mem_write(addr,struct.pack('<'+fmt,val))
def get(addr,fmt='I'):return struct.unpack('<'+fmt,uc.mem_read(addr,struct.calcsize(fmt)))[0]
def memory(addr,size):
    data=bytes(uc.mem_read(addr,size))
    return dict(address=hex(addr),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())
def seed(row):uc.mem_write(int(row['address'],16),bytes.fromhex(row['bytes']))
report=dict(ok=False,scope=__doc__,firmware_sha256=SHA,probe_sha256=hashlib.sha256(src).hexdigest(),
    observed_files={str((a.observed/name).resolve()):hashlib.sha256((a.observed/name).read_bytes()).hexdigest()
                    for name in ('result.json','events.json')},
    unicorn=un.__version__,cases=[],limitations=[
        'Observed geometry prefix and observed ring submission are replayed as two separate segments.',
        'Route tests relocate observed owner bytes and use synthetic handles and an optional replacement.',
        'Owner numeric modes are not assigned menu or photographic meanings.',
        'Request construction stops before the later descriptor copy and processing call.',
        'Encoding tests stop before encoder or special-mode dump helper; no return is fabricated.',
        'Only control flow and configuration bytes are verified, not physical pixel effects.'])
def reset():
    for addr,size in regions:uc.mem_write(addr,bytes(size))
def execute(entry,args=(),until=STOP):
    blocks.clear();reads.clear()
    for reg in REGS:uc.reg_write(reg,0)
    for reg,val in zip(REGS,args):uc.reg_write(reg,val)
    uc.reg_write(UC_ARM_REG_SP,STACK+0xf000);uc.reg_write(UC_ARM_REG_LR,STOP|1)
    report['last_call']=dict(entry=hex(entry),args=[hex(x) for x in args],until=hex(until))
    uc.ctl_flush_tb();uc.emu_start(entry|1,until,count=200000)
    pc=uc.reg_read(UC_ARM_REG_PC);assert pc==until,hex(pc)
    return dict(**report['last_call'],stopped_at=hex(pc),registers={f'r{i}':hex(uc.reg_read(reg)) for i,reg in enumerate(REGS)},
                blocks=list(blocks),reads=list(reads))
calls=[]
try:
    for phase in ('synthetic-boot','native-settle'):
        report['current_case']='front-replay-'+phase;reset();calls=[]
        find=lambda name:next(e for e in events if e['phase']==phase and e['event']==name)
        entry=find('front_full_geometry_entry');ready=find('front_primary_descriptor_ready')
        req,handle=entry['memory']['front_request'],entry['memory']['front_handle']
        seed(req);seed(handle)
        calls.append(execute(0x100bd820,[int(req['address'],16)],until=0x100bd874))
        geometry=memory(MMIO+0x1500,0x14)
        expected_geometry=find('front_full_geometry_built')['memory']['geometry']
        stack=memory(STACK+0xefd8,0x14)
        # SP after PUSH {r4,r5,r6,lr}; SUB SP,18h is fixed by native prefix.
        assert stack['bytes']==expected_geometry['bytes']
        seed(ready['memory']['front_parameters'])
        calls.append(execute(0x100bd5cc,[0xc25ee224]))
        parameter=bytes.fromhex(ready['memory']['front_parameters']['bytes'])
        assert bytes(uc.mem_read(MMIO+0x1850,0x20))==parameter[0x24:0x44]
        assert get(MMIO+0x1808)==struct.unpack_from('<H',parameter,0x1a)[0]
        report['cases'].append(dict(name=report['current_case'],phase=phase,calls=calls,
            request=req,handle=handle,observed_geometry=expected_geometry,replayed_geometry=stack,
            observed_ring=ready['memory']['front_parameters'],geometry_registers=geometry,
            address_registers=memory(MMIO+0x1850,0x20),channel_registers=memory(MMIO+0x1800,0x50)))
    owner_bytes=bytes.fromhex(native['final']['owner']['bytes'])
    raw_handle=bytes.fromhex(native['final']['still_handle_1f8']['bytes'])
    assert owner_bytes[0]==0 and owner_bytes[0x190]==1
    cases=[('observed-mode0-file1',0,1,True),('file0',0,0,True),('file2',0,2,True),
           ('no-replacement',0,1,False)]+[(f'mode{mode}',mode,1,True) for mode in (3,4,5,6)]
    for name,mode,fileflag,has_output in cases:
        report['current_case']=name;reset();calls=[]
        uc.mem_write(OWNER,owner_bytes);put(OWNER,mode,'B');put(OWNER+0x190,fileflag,'B')
        uc.mem_write(INHANDLE,raw_handle);uc.mem_write(OUTHANDLE,raw_handle)
        put(OUTHANDLE+0x34,0x62000000)
        put(STAGE+0xc,OBJ);put(OBJ+0x3a4,OWNER);put(OBJ+0x1f8,INHANDLE)
        put(OBJ+0x1fc,OUTHANDLE if has_output else 0);put(OBJ+0x330,ENCODED)
        calls.append(execute(0x100ae33e,[STAGE],until=0x100ae3b4))
        selected=has_output and fileflag in (0,1) and mode not in (3,4,5,6)
        assert get(REQ+8)==INHANDLE and get(REQ+0x1a8)==(OUTHANDLE if selected else 0)
        if fileflag not in (0,1):until=STOP
        elif mode in (3,4,5,6):until=0x101af8e6
        else:until=0x100a323e
        calls.append(execute(0x100af648,[STAGE],until=until))
        if until==0x100a323e:
            assert int(calls[-1]['registers']['r0'],16)==INHANDLE+0x24
            assert int(calls[-1]['registers']['r1'],16)==ENCODED+0x50
        if until==0x101af8e6:
            assert int(calls[-1]['registers']['r0'],16)==0xa448e000
            assert int(calls[-1]['registers']['r1'],16)==9168*4222
        report['cases'].append(dict(name=name,owner_mode=mode,owner_fileflag=fileflag,has_replacement=has_output,
            replacement_selected=selected,calls=calls,request=memory(REQ,0x390),
            handles=memory(OBJ+0x1f8,8),encoded_descriptor=memory(ENCODED+0x50,0x20)))
    report['ok']=True
except Exception:
    report['error']=traceback.format_exc();report['failure_pc']=hex(uc.reg_read(UC_ARM_REG_PC))
    report['failure_blocks']=list(blocks);report['failure_reads']=list(reads);report['completed_calls']=calls
    raise
finally:
    report['firmware_unchanged']=hashlib.sha256(fw.read_bytes()).hexdigest()==SHA
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']),pc=hex(uc.reg_read(UC_ARM_REG_PC)))))

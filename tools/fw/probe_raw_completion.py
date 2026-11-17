"""Bounded native RAW completion and handoff, with explicit synthetic MMIO/status.

This checks software predicates and pointers only. It does not cause, emulate or
verify a hardware pixel transfer. Image payload addresses are deliberately unmapped.
"""
from pathlib import Path
import argparse, hashlib, json, struct, traceback
import unicorn as un
from unicorn.arm_const import *

ROOT=Path(__file__).resolve().parents[2]
BASE,RAM,STACK,STOP,MMIO=0x10020000,0x50000000,0x52000000,0x53000000,0x20380000
DRIVER,OBJ,REQ,INHANDLE,OUTHANDLE,OWNER=[RAM+x for x in (0,0x1000,0x2000,0x3000,0x4000,0x5000)]
GLOBAL=0xc180b698
SHA='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,
      UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,
      UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert __debug__;a.output.mkdir(parents=True,exist_ok=False)
src=Path(__file__).read_bytes();(a.output/'probe-source.py').write_bytes(src)
fw=ROOT/'firmware/decoded/eg1620_038000.bi';blob=fw.read_bytes()
assert hashlib.sha256(blob).hexdigest()==SHA
uc=un.Uc(un.UC_ARCH_ARM,un.UC_MODE_THUMB);romsize=(len(blob)+4095)&~4095
uc.mem_map(BASE,romsize);uc.mem_write(BASE,blob);uc.mem_protect(BASE,romsize,un.UC_PROT_READ|un.UC_PROT_EXEC)
regions=((RAM,0x10000),(STACK,0x10000),(STOP,0x1000),(0xc1800000,0x10000),(MMIO,0x80000))
for addr,size in regions:uc.mem_map(addr,size)
blocks,reads=[],[]
def block(_uc,pc,size,_):
    blocks.append(hex(pc))
    if len(blocks)>10000:raise RuntimeError('block cap')
def read_hook(_uc,kind,addr,size,value,_):
    if MMIO<=addr<MMIO+0x80000 or GLOBAL<=addr<GLOBAL+0x100 or OBJ<=addr<OWNER+0x2000:
        reads.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,
                          bytes=bytes(uc.mem_read(addr,size)).hex()))
uc.hook_add(un.UC_HOOK_BLOCK,block);uc.hook_add(un.UC_HOOK_MEM_READ,read_hook)
def put(addr,val,fmt='I'):uc.mem_write(addr,struct.pack('<'+fmt,val))
def get(addr,fmt='I'):return struct.unpack('<'+fmt,uc.mem_read(addr,struct.calcsize(fmt)))[0]
def memory(addr,size):
    data=bytes(uc.mem_read(addr,size))
    return dict(address=hex(addr),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())
report=dict(ok=False,scope=__doc__,firmware_sha256=SHA,probe_sha256=hashlib.sha256(src).hexdigest(),
    unicorn=un.__version__,cases=[],limitations=[
        'MMIO is ordinary private RAM, without IRQ, write-to-clear or hardware pixel semantics.',
        'Status register, callback input, return value and objects are supplied fixtures.',
        'All OS event-set calls stop before entry; no event wait is forced successful.',
        'Handoff is entered after the processing call, not executed as a continuous capture.',
        'Unmapped 60000000/62000000 image payloads; no complete exposure, encoding or NEF.'])
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
    for bank in (0,1):
      for name,status,cleanup,event in [('no-status',0,0,None),('status-bit1',2,0,1),
                                        ('error-bit7',0x80,0,0x100),('cleanup-bit1',2,1,0x80)]:
        report['current_case']=f'bank{bank}-{name}';reset();put(DRIVER+4,bank,'B');calls=[]
        # Mirror the single-bank worker's 100d620c/6210 sentinel; not an IRQ.
        put(GLOBAL+0x40,0xffffffff)
        callback=0x100d5685 if bank else 0x100d56d7
        calls.append(execute(0x1010615a,[DRIVER,callback]))
        assert get(0xc1801e68+bank*4)==callback
        calls.append(execute(0x10105eae,[DRIVER]))
        assert get(MMIO+bank*0x40000+8)==get(MMIO+bank*0x40000+16)==1
        put(0xc1801e64+bank,cleanup,'B');put(MMIO+bank*0x40000+0x24,status)
        calls.append(execute(0x10105870 if bank else 0x101058ac,until=STOP if event is None else 0x10105264))
        if event is not None:
            assert int(calls[-1]['registers']['r0'],16)==(0xc1d8833c if bank else 0xc1d881d0)
            assert int(calls[-1]['registers']['r1'],16)==event
        assert (hex(callback&~1) in calls[-1]['blocks'])
        report['cases'].append(dict(name=report['current_case'],bank=bank,synthetic_status=status,
            cleanup_state=cleanup,peer_accumulator_fixture='0xffffffff',event_before_OS=event,
            calls=calls,mmio=memory(MMIO+bank*0x40000,0x28)))
    for event,state in ((0x42170801,0),(0x4217080b,2),(0x42170806,1)):
        report['current_case']=f'completion-{event:08x}';reset()
        calls=[execute(0x100d67d8,[event],until=0x10105264)]
        assert get(GLOBAL+1,'B')==state
        assert calls[-1]['registers']['r0']=='0xc1d8833c' and calls[-1]['registers']['r1']=='0x8'
        report['cases'].append(dict(name=report['current_case'],supplied_message=hex(event),state=state,calls=calls))
    for return_value in (0,1):
      for has_output in (False,True):
        report['current_case']=f'handoff-return{return_value}-output{int(has_output)}';reset();calls=[]
        for bank in (0,1):
            put(DRIVER+4,bank,'B');put(MMIO+bank*0x40000+0x118,0xabc001+bank)
            calls.append(execute(0x10106402,[DRIVER,GLOBAL+0x4c+4*bank]))
            assert get(GLOBAL+0x4c+4*bank)==0xabc001+bank
        put(OBJ+0x1f8,INHANDLE);put(OBJ+0x1fc,OUTHANDLE);put(OBJ+0x3a4,OWNER)
        put(INHANDLE+0x18,6104);put(INHANDLE+0x1c,4222)
        put(INHANDLE+0x34,0x60000000);put(OUTHANDLE+0x34,0x62000000)
        put(REQ+0x1a8,OUTHANDLE if has_output else 0);put(REQ+0x374,0)
        before=memory(OBJ+0x1f8,8)
        calls.append(execute(0x100ae3d2,[return_value,0,0,0,OBJ,REQ],until=0x100ae438))
        assert get(OWNER+0x1ac8)==0xabc002
        assert get(OBJ+0x1f8)==(OUTHANDLE if has_output else INHANDLE)
        assert get(OBJ+0x1fc)==(INHANDLE if has_output else OUTHANDLE)
        if has_output:assert get(OUTHANDLE+0x18)==6104 and get(OUTHANDLE+0x1c)==4222
        report['cases'].append(dict(name=report['current_case'],injected_prior_return=return_value,has_output=has_output,
            calls=calls,before_handles=before,after_handles=memory(OBJ+0x1f8,8),
            output_handle=memory(OUTHANDLE,0x38),owner_field=memory(OWNER+0x1ac8,4)))
    report['ok']=True
except Exception:
    report['error']=traceback.format_exc();report['failure_pc']=hex(uc.reg_read(UC_ARM_REG_PC))
    report['failure_blocks']=list(blocks);report['failure_reads']=list(reads);report['completed_calls']=calls
    raise
finally:
    report['firmware_unchanged']=hashlib.sha256(fw.read_bytes()).hexdigest()==SHA
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']),pc=hex(uc.reg_read(UC_ARM_REG_PC)))))

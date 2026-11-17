"""Execute original field builders and front coefficient packing in private RAM.

Artificial calibration tests arithmetic and data propagation. ROM is read-only;
MMIO is ordinary RAM, and no sensor or image-pixel processing is implemented.
"""
from pathlib import Path
import argparse, hashlib, json, struct, traceback
import unicorn as un
from unicorn.arm_const import *

ROOT=Path(__file__).resolve().parents[2]
BASE,RAM,STACK,STOP,CAL=0x10020000,0x50000000,0x52000000,0x53000000,0x54000000
CTX,PACKET,CALCTX,COEFF=0xc18fa844,0xc29a34c0,0xc18fa954,0xc29a3868
SHA='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,
      UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--observed',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);assert __debug__
source=Path(__file__).read_bytes();(a.output/'probe-source.py').write_bytes(source)
events=json.loads((a.observed/'events.json').read_text())
observed=next(e for e in events if e['phase']=='native-settle' and e['event']=='field_builder_entry')
context=bytes.fromhex(observed['memory']['context']['bytes']);assert context[0]==1
firmware=ROOT/'firmware/decoded/eg1620_038000.bi';blob=firmware.read_bytes()
assert hashlib.sha256(blob).hexdigest()==SHA
uc=un.Uc(un.UC_ARCH_ARM,un.UC_MODE_THUMB)
romsize=(len(blob)+4095)&~4095;uc.mem_map(BASE,romsize);uc.mem_write(BASE,blob)
uc.mem_protect(BASE,romsize,un.UC_PROT_READ|un.UC_PROT_EXEC)
regions=((RAM,0x10000),(STACK,0x10000),(STOP,0x1000),(CAL,0x168000),
         (0xc1800000,0x2000000),(0x20068000,0x2000))
for address,size in regions:uc.mem_map(address,size)
blocks,reads,writes=[],[],[]
def block(_,pc,size,data):
    blocks.append(hex(pc))
    if len(blocks)>30000:raise RuntimeError('block cap')
def read(_,kind,address,size,value,data):
    if CAL<=address<CAL+0x168000:
        reads.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(address),size=size,bytes=bytes(uc.mem_read(address,size)).hex()))
def write(_,kind,address,size,value,data):
    writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(address),size=size,value=value))
uc.hook_add(un.UC_HOOK_BLOCK,block);uc.hook_add(un.UC_HOOK_MEM_READ,read)
uc.hook_add(un.UC_HOOK_MEM_WRITE,write,begin=0x20068000,end=0x20069fff)
def put(address,value,fmt='I'):uc.mem_write(address,struct.pack('<'+fmt,value))
def memory(address,size):
    data=bytes(uc.mem_read(address,size));return dict(address=hex(address),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())
report=dict(ok=False,scope=__doc__,firmware_sha256=SHA,probe_sha256=hashlib.sha256(source).hexdigest(),
    observed_sha256=hashlib.sha256((a.observed/'events.json').read_bytes()).hexdigest(),unicorn=un.__version__,cases=[],conversions=[])
def execute(entry,args=(),until=STOP):
    blocks.clear();reads.clear();writes.clear()
    for reg in REGS:uc.reg_write(reg,0)
    for reg,value in zip(REGS,args):uc.reg_write(reg,value)
    uc.reg_write(UC_ARM_REG_SP,STACK+0xf000);uc.reg_write(UC_ARM_REG_LR,STOP|1)
    report['last_call']=dict(entry=hex(entry),args=[hex(x) for x in args],until=hex(until))
    uc.ctl_flush_tb();uc.emu_start(entry|1,until,count=1000000)
    pc=uc.reg_read(UC_ARM_REG_PC);assert pc==until,hex(pc)
    return dict(**report['last_call'],stopped_at=hex(pc),r0=uc.reg_read(UC_ARM_REG_R0),r1=uc.reg_read(UC_ARM_REG_R1),
        blocks=list(blocks),calibration_reads=list(reads),writes=list(writes))
def code_to_scale(code):return 10**12//(10**6-(code*10**6//4095))
def scale_to_code(scale):return 0 if scale<=10**6 else ((10**6-10**12//scale)*4095)//10**6
cases=[dict(name='baseline'),dict(name='lower-rational-input',sv=7),dict(name='high-code',high=True),
       dict(name='one-channel-factor',factor=True),dict(name='one-control-byte',control=True),
       dict(name='offset-gate',gate=1),dict(name='temporary-stage',stage=1),
       dict(name='publication-reuses-old-values',publish=0)]
try:
    for code in (0,2048,3580,4094):
        call=execute(0x10121a1e,[code]);value=call['r0']+(call['r1']<<32)
        assert value==code_to_scale(code),(code,value)
        inverse=execute(0x10121a86,[value&0xffffffff,value>>32])
        assert inverse['r0']==scale_to_code(value)
        report['conversions'].append(dict(code=code,scale=value,inverse=inverse['r0'],calls=[call,inverse]))
    for case in cases:
        report['current_case']=case['name'];calls=[]
        for address,size in regions:uc.mem_write(address,bytes(size))
        uc.mem_write(CTX,context);put(CALCTX+0x14,CAL);put(0xc180b76c+0xc,RAM)
        sv=case.get('sv',8);put(CTX+4,192);put(CTX+8,sv*192)
        put(CTX+0x28,32768,'H');put(CTX+0x2a,32768,'H')
        put(CTX+0x5b,case.get('gate',0),'B');put(CTX+0x84,case.get('stage',0))
        # Exact ROM breakpoints use records 0..8. The adjustment table remains zero.
        records=[]
        for index in range(9):
            codes=[4000,4010] if case.get('high') else [1000+index*128,1200+index*128]
            factors=[4608 if case.get('factor') else 4096,4352,4608,4864]
            uc.mem_write(CAL+0xbe540+index*16,struct.pack('<2H',*codes)+bytes(12))
            uc.mem_write(CAL+0xbe830+index*8,struct.pack('<4H',*factors))
            records.append(dict(codes=codes,factors=factors))
        uc.mem_write(CAL+0xbe6a0,bytes([1,0,0,1,1,0,1,1,0,1,0,0,1,1]))
        uc.mem_write(CAL+0xbe6c0,bytes([0x11,0x21,0x12,0x22,1,2,3,4,1]))
        uc.mem_write(CAL+0xbe6e0,bytes([0x31,0x41,0x32,0x42,5,6,7,8,1]))
        uc.mem_write(CAL+0xbe700,bytes([1 if case.get('control') else 5,1,3,1]))
        put(CAL+0xbe810,9,'B');put(CAL+0xbe888,4096,'H');put(CAL+0xbe88a,4096,'H')
        # Signed adjustment +4*2 in the coefficient publisher, same for each mode.
        uc.mem_write(CAL+0xbe820,bytes([2])*15)
        uc.mem_write(CAL+0xbbd70,struct.pack('<6H',11,22,33,44,55,66)*(7*23))
        before=memory(CTX,0xe4)
        calls.append(execute(0x10121ede,[CTX]));assert calls[-1]['r0']==0
        built=memory(CTX,0xe4)
        record=records[sv-5];ca,cb=record['codes'];f=record['factors']
        scales=[code_to_scale(ca)*f[0]//4096,code_to_scale(cb)*f[1]//4096,
                code_to_scale(cb)*f[2]//4096,code_to_scale(ca)*f[3]//4096]
        expected_pair=[min(0xf7e,scale_to_code(min(scales[0],scales[3]))),
                       min(0xf7e,scale_to_code(min(scales[1],scales[2])))]
        expected_coeff=[scales[i]*4096//code_to_scale(expected_pair[0 if i in (0,3) else 1]) for i in range(4)]
        data=bytes.fromhex(built['bytes'])
        assert list(struct.unpack_from('<4H',data,0xb0))==expected_pair*2,(case,expected_pair,data[0xb0:0xb8].hex())
        assert list(struct.unpack_from('<4I',data,0xc4))==expected_coeff,(case,expected_coeff,struct.unpack_from('<4I',data,0xc4))
        upper=sv>=8;hi=min(expected_pair)>0xdfc
        expected_controls=[6 if upper else 5,
            ((0 if hi else 1)|((1 if hi else 0)<<1)|4) if upper else ((1 if hi else 0)|((0 if hi else 1)<<1)|4),
            0x21 if upper else 0x11,0x22 if upper else 0x12,
            ((4 if hi else 3) if upper else (2 if hi else 1))|64,
            0x41 if upper else 0x31,0x42 if upper else 0x32,
            ((8 if hi else 7) if upper else (6 if hi else 5))|64,
            0xb9 if case.get('control') else 0xbd]
        assert list(data[0xb8:0xc1])==expected_controls,(case,expected_controls,list(data[0xb8:0xc1]))
        old=[7001,7002,7003,7004];uc.mem_write(COEFF,struct.pack('<4I',*old));put(COEFF+0x18,77,'B')
        publish=case.get('publish',1)
        calls.append(execute(0x1011e940,[CTX,publish]));assert calls[-1]['r0']==0
        expected_published=[x+8 for x in expected_coeff] if publish else old
        assert list(struct.unpack('<4I',uc.mem_read(COEFF,16)))==expected_published
        assert uc.mem_read(COEFF+0x18,1)[0]==(9 if publish else 77)
        calls.append(execute(0x100bcd86,[PACKET],until=0x100d7de2))
        expected_regs=struct.pack('<8I',*expected_published,11|(22<<16),44|(33<<16),9 if publish else 77,55)
        assert bytes(uc.mem_read(0x200687d8,32))==expected_regs
        report['cases'].append(dict(case,sv=sv,
            input_context=before,context_after_builder=built,record=record,expected_pair=expected_pair,
            expected_coefficients=expected_coeff,expected_controls=expected_controls,expected_published=expected_published,
            calibration_front=memory(CAL+0xbe000,0xb20),coefficient_packet=memory(COEFF,32),
            calibration_coefficient_record=memory(CAL+0xbbd70+22*12,12),
            front_registers=memory(0x200687d8,32),calls=calls))
    report['ok']=True
except Exception:
    report['error']=traceback.format_exc();report['failure']=dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),
        blocks=list(blocks),calibration_reads=list(reads),writes=list(writes))
finally:
    report['firmware_unchanged']=hashlib.sha256(firmware.read_bytes()).hexdigest()==SHA
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']),error=report.get('error')),indent=2))
if not report['ok']:raise SystemExit(1)

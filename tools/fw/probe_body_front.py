"""Native front table builders and callback in private RAM, with explicit fixtures.

ROM is read-only. MMIO is ordinary RAM; no image storage is mapped. Artificial
nonzero calibration and prior tables test selection, reuse and packing only.
"""
from pathlib import Path
import argparse, hashlib, json, struct, traceback
import unicorn as un
from unicorn.arm_const import *

ROOT=Path(__file__).resolve().parents[2]
BASE,RAM,STACK,STOP,CAL=0x10020000,0x50000000,0x52000000,0x53000000,0x54000000
CTX,PACKET,CALCTX=0xc18fa844,0xc29a34c0,0xc18fa954
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,
      UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,
      UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]
SHA='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--observed',type=Path,required=True)
a=p.parse_args();assert __debug__
a.output.mkdir(parents=True,exist_ok=False)
src=Path(__file__).read_bytes();(a.output/'probe-source.py').write_bytes(src)
events=json.loads((a.observed/'events.json').read_text())
observed=next(e for e in events if e['phase']=='native-settle' and e['event']=='table32_selected')
context=bytes.fromhex(observed['memory']['source_context']['bytes'])
assert context[0]==1 and context[0x21]==0 and struct.unpack_from('<I',context,0x84)[0]==1
firmware=ROOT/'firmware/decoded/eg1620_038000.bi';blob=firmware.read_bytes()
assert hashlib.sha256(blob).hexdigest()==SHA
uc=un.Uc(un.UC_ARCH_ARM,un.UC_MODE_THUMB)
romsize=(len(blob)+4095)&~4095
uc.mem_map(BASE,romsize);uc.mem_write(BASE,blob)
uc.mem_protect(BASE,romsize,un.UC_PROT_READ|un.UC_PROT_EXEC)
regions=((RAM,0x10000),(STACK,0x10000),(STOP,0x1000),(CAL,0x168000),
         (0xc1800000,0x2000000),(0x20068000,0x2000))
for addr,size in regions:uc.mem_map(addr,size)
blocks,reads,writes=[],[],[]
def block(_uc,pc,size,_):
    blocks.append(hex(pc))
    if len(blocks)>20000:raise RuntimeError('block cap')
def read(_uc,kind,addr,size,value,_):
    if CAL<=addr<CAL+0x168000:
        reads.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,
                          bytes=bytes(uc.mem_read(addr,size)).hex()))
def write(_uc,kind,addr,size,value,_):
    writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,value=value))
uc.hook_add(un.UC_HOOK_BLOCK,block)
uc.hook_add(un.UC_HOOK_MEM_READ,read)
uc.hook_add(un.UC_HOOK_MEM_WRITE,write,begin=0x20068000,end=0x20069fff)
def put(addr,value,fmt='I'):uc.mem_write(addr,struct.pack('<'+fmt,value))
def get(addr,fmt='I'):return struct.unpack('<'+fmt,uc.mem_read(addr,struct.calcsize(fmt)))[0]
def memory(addr,size):
    data=bytes(uc.mem_read(addr,size))
    return dict(address=hex(addr),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())
report=dict(ok=False,scope=__doc__,firmware_sha256=SHA,probe_sha256=hashlib.sha256(src).hexdigest(),
    observed_sha256=hashlib.sha256((a.observed/'events.json').read_bytes()).hexdigest(),
    unicorn=un.__version__,cases=[],limitations=[
        'Snapshot context is the initial static front configuration, not a completed exposure.',
        'All nonzero calibration and prior-table values are artificial.',
        'The callback stops before its update-control call; no hardware completion is supplied.',
        'Config 0x3e1 is represented here by its previously verified static-input destination ctx+5b.',
        'The names table A/B and four channels specify storage layout, not physical correction meaning.'])
def execute(entry,args=(),until=STOP):
    blocks.clear();reads.clear();writes.clear()
    for reg in REGS:uc.reg_write(reg,0)
    for reg,value in zip(REGS,args):uc.reg_write(reg,value)
    uc.reg_write(UC_ARM_REG_SP,STACK+0xf000);uc.reg_write(UC_ARM_REG_LR,STOP|1)
    report['last_call']=dict(entry=hex(entry),args=[hex(x) for x in args],until=hex(until))
    uc.ctl_flush_tb();uc.emu_start(entry|1,until,count=500000)
    pc=uc.reg_read(UC_ARM_REG_PC);assert pc==until,hex(pc)
    return dict(**report['last_call'],stopped_at=hex(pc),r0=uc.reg_read(UC_ARM_REG_R0),
        r1=uc.reg_read(UC_ARM_REG_R1),blocks=list(blocks),calibration_reads=list(reads),writes=list(writes))

table32=[1000+g*4+c for g in range(32) for c in range(4)]
prior_a=[200+i for i in range(144)];prior_b=[40000+i for i in range(144)]
record_a=[32]*144;record_d=[64000]*144
record_address=CAL+0x2d984+2*588
variants=[('captured-selector-reuse',False,2496,0,0,62000,False),
          ('computed',True,2496,0,0,62000,False),
          ('offset-gate',True,2496,1,0,62000,False),
          ('threshold',True,1920,0,0,62000,False),
          ('one-second',True,0,0,0,62000,False),
          ('long-256-seconds',True,-1536,0,0,62000,False),
          ('independent-gate74',True,2496,0,1,62000,False),
          ('lower-cap',True,2496,0,0,35000,False),
          ('one-table32-value',True,2496,0,0,62000,True)]
calls=[]
try:
    for name,active,t,gate,gate74,cap,change32 in variants:
        report['current_case']=name;calls=[]
        for addr,size in regions:uc.mem_write(addr,bytes(size))
        uc.mem_write(CTX,context);put(CALCTX+0x14,CAL)
        put(0xc180b76c+0xc,RAM)
        put(CTX+0xc,192);put(CTX+0x10,t,'i')
        put(CTX+0x5b,gate,'B');put(CTX+0x74,gate74)
        if active:put(CTX+0x21,2,'B');put(CTX+0x78,1,'B')
        values=table32.copy()
        if change32:values[5*4+2]+=777
        uc.mem_write(CAL+0x293c0,struct.pack('<128H',*values))
        uc.mem_write(0xc29a39a0,struct.pack('<144H',*prior_a))
        uc.mem_write(0xc29a3ac0,struct.pack('<144H',*prior_b))
        uc.mem_write(record_address,struct.pack('<3HBBH',12,34,56,1,0,78)+
                     struct.pack('<144H',*record_a)+struct.pack('<144H',*record_d)+bytes(2))
        # Five 2020-word rows, indexed by cumulative table-A values and ctx+34.
        row=[i*20 for i in range(2020)]
        uc.mem_write(CAL+0x126900,struct.pack('<2020i',*row)*5)
        put(CAL+0x1306d0,cap,'H')
        uc.mem_write(CAL+0xbc7f0,struct.pack('<6H',101,202,303,300,405,606)*(7*33))
        calls.append(execute(0x1011c14a,[CTX+0xc]));exposure=calls[-1]['r0']+(calls[-1]['r1']<<32)
        # For the exact power-of-two inputs, native conversion should agree
        # with independent integer arithmetic; no helper return is replaced.
        power=t//192
        assert exposure==(10**9//(2**power) if power>=0 else 10**9*(2**(-power))),exposure
        calls.append(execute(0x1011dce0,[CTX]))
        assert bytes(uc.mem_read(0xc29a38a0,256))==struct.pack('<128H',*values)
        calls.append(execute(0x1011e118,[CTX]))
        if not active:expected_a,expected_b=prior_a,prior_b
        else:
            expected_a=record_a;expected_b=[];cumulative=0
            for width,d in zip(record_a,record_d):
                cumulative+=width
                extra=0 if cumulative<2020 else row[min(cumulative-2020,2019)]
                value=32768 if t<=1920 or gate74 else max(32768,min(cap,
                    (exposure*327680//(4000000000//d-122070+extra+exposure)+5)//10))
                expected_b.append(value)
        assert bytes(uc.mem_read(0xc29a39a0,288))==struct.pack('<144H',*expected_a)
        assert bytes(uc.mem_read(0xc29a3ac0,288))==struct.pack('<144H',*expected_b)
        calls.append(execute(0x1011ebb8,[CTX]))
        # Full original copy and pointer dispatch, through the selected drivers.
        calls.append(execute(0x100bcd86,[PACKET],until=0x100d7de2))
        expected32=b''.join(struct.pack('<I',values[g*4+c]|values[(g+1)*4+c]<<16)
                             for c in range(4) for g in range(0,32,2))
        assert bytes(uc.mem_read(0x20068a00,256))==expected32
        assert bytes(uc.mem_read(0x20068c00,288))==struct.pack('<144H',*expected_a)
        assert bytes(uc.mem_read(0x20068d20,288))==struct.pack('<144H',*expected_b)
        assert get(0x20068808)&0xffff == (0 if gate else 300)
        report['cases'].append(dict(name=name,active_144=active,exposure_numeric=exposure,
            gate5b=gate,gate74=gate74,cap=cap,t=t,context=memory(CTX,0x94),calls=calls,
            table32=memory(0xc29a38a0,256),table144_a=memory(0xc29a39a0,288),table144_b=memory(0xc29a3ac0,288),
            expected_a=expected_a,expected_b=expected_b,packet=memory(PACKET,0x60),
            scalar_registers=memory(0x20068804,12),registers32=memory(0x20068a00,256),
            registers144=memory(0x20068c00,576)))
    report['ok']=True
except Exception:
    report['error']=traceback.format_exc();report['failure']=dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),
        blocks=list(blocks),calibration_reads=list(reads),writes=list(writes),completed_calls=calls)
finally:
    report['firmware_unchanged']=hashlib.sha256(firmware.read_bytes()).hexdigest()==SHA
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']),error=report.get('error')),indent=2))
if not report['ok']:raise SystemExit(1)

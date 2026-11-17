"""Execute original C3.80 routing/control code on private synthetic RAM.

No pixel model, payload mapping, full exposure, NEF file, firmware edit or flash.
MMIO is ordinary RAM: writes establish software configuration, not silicon effects.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import traceback
import unicorn as un
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parents[2]
BASE, RAM, STACK, STOP, CAL = 0x10020000, 0x50000000, 0x52000000, 0x53000000, 0x54000000
OWNER, OBJ, PROPS, CTX = RAM, RAM+0x4000, RAM+0x8000, RAM+0x9000
PARAM, PACKET, STORAGE, TABLES = OWNER+0x394, RAM+0xb000, RAM+0xc000, RAM+0x10000
FLAGS, DRIVER, INPUT, OUTPUT = RAM+0x15000, RAM+0x16000, RAM+0x17000, RAM+0x17100
CACHE, SPATIAL, SERIAL, COEFF = RAM+0x18000, RAM+0x19000, RAM+0x19100, RAM+0x19200
TABLECTX = RAM+0x1c000
REQ, MMIO = RAM+0x1a000, 0x20380000
SHA = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert __debug__, 'Run without -O.'
a.output.mkdir(parents=True, exist_ok=False)
source = Path(__file__).read_bytes()
(a.output/'probe-source.py').write_bytes(source)
firmware = ROOT/'firmware/decoded/eg1620_038000.bi'
blob = firmware.read_bytes()
assert hashlib.sha256(blob).hexdigest() == SHA
uc = un.Uc(un.UC_ARCH_ARM, un.UC_MODE_THUMB)
size = (len(blob)+4095)&~4095
uc.mem_map(BASE, size)
uc.mem_write(BASE, blob)
uc.mem_protect(BASE, size, un.UC_PROT_READ | un.UC_PROT_EXEC)
for addr, size in ((RAM,0x40000),(STACK,0x10000),(STOP,0x1000),(CAL,0x100000),
                   (0xc1800000,0x2000000),(MMIO,0x10000),(MMIO+0x40000,0x10000)):
    uc.mem_map(addr,size)
trace, writes = [], []

def block(_uc, pc, size, _data):
    trace.append(hex(pc))
    if len(trace)>50000:
        raise RuntimeError('Block cap exceeded')

def mmio_write(_uc, _access, addr, size, value, _data):
    writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,value=hex(value)))

uc.hook_add(un.UC_HOOK_BLOCK,block)
uc.hook_add(un.UC_HOOK_MEM_WRITE,mmio_write,begin=MMIO,end=MMIO+0x4ffff)
REGS = [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,
        UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,
        UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]

def put(addr,value,fmt='I'):
    uc.mem_write(addr,struct.pack('<'+fmt,value))

def get(addr,fmt='I'):
    return struct.unpack('<'+fmt,uc.mem_read(addr,struct.calcsize(fmt)))[0]

def memory(addr,size):
    data=bytes(uc.mem_read(addr,size))
    return dict(address=hex(addr),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())

report = dict(ok=False,scope=__doc__,firmware_sha256=SHA,
              probe_sha256=hashlib.sha256(source).hexdigest(),unicorn=un.__version__,cases=[],
              limitations=['Synthetic RAM, numeric selectors have no camera menu names.',
                           'Synthetic calibration is zero, including the constructor lookup at +0xcde30.',
                           'Driver calls use r2=0: no hardware reset/start/completion.',
                           'Reduced driver packets retain only documented blocks.',
                           '0x60000000 and 0x62000000 payloads remain unmapped.',
                           'No pixel arithmetic is provided by the harness.'])

def execute(entry,args=(),until=STOP,regs=None):
    trace.clear()
    writes.clear()
    for reg in REGS:
        uc.reg_write(reg,0)
    for reg,value in zip(REGS,args):
        uc.reg_write(reg,value)
    for index,value in (regs or {}).items():
        uc.reg_write(REGS[index],value)
    uc.reg_write(UC_ARM_REG_SP,STACK+0xf000)
    uc.reg_write(UC_ARM_REG_LR,STOP|1)
    report['last_call']=dict(entry=hex(entry),args=[hex(x) for x in args],until=hex(until),
                             initial_registers={str(k):hex(v) for k,v in (regs or {}).items()})
    # A previously translated target function can bypass a newly chosen `until`
    # boundary in this Unicorn build. Rebuild translation blocks per segment;
    # this changes no guest bytes, registers, callbacks or hardware results.
    uc.ctl_flush_tb()
    uc.emu_start(entry|1,until,count=500000)
    pc=uc.reg_read(UC_ARM_REG_PC)
    assert pc==until,hex(pc)
    return dict(**report['last_call'],stopped_at=hex(pc),r0=hex(uc.reg_read(UC_ARM_REG_R0)),
                blocks=list(trace),writes=list(writes))

def reset(output=True,owner_kind=0):
    for addr,size in ((RAM,0x40000),(STACK,0x10000),(MMIO,0x10000),(MMIO+0x40000,0x10000)):
        uc.mem_write(addr,bytes(size))
    put(0xc18812b4,1)
    put(0xc18fa954+0x14,CAL)
    put(OBJ+0x3a4,OWNER)
    put(OWNER,owner_kind,'B')
    for h,px in ((INPUT,0x60000000),(OUTPUT,0x62000000)):
        put(h+0x24,2,'B')
        uc.mem_write(h+0x26,struct.pack('<3H',9168,6104,4222))
        put(h+0x34,px)
    for off,value in ((4,1),(8,INPUT),(0x1a8,OUTPUT if output else 0),
                      (0x35c,PARAM),(0x360,TABLES),(0x364,FLAGS),(0x378,1),(0x380,OBJ)):
        put(REQ+off,value)
    for off,value in ((0,PROPS),(4,CACHE),(0xd0,PARAM),(0xd8,SPATIAL),(0xdc,SERIAL),(0xe4,COEFF)):
        put(CTX+off,value)
    put(CTX+0x26,512,'H')
    uc.mem_write(CTX+0x2e,struct.pack('<2H',768,1024))
    put(PROPS+0x86,300,'H')
    put(PROPS+0x58,6104*256)
    put(PROPS+0x5c,4222*256)
    put(CTX+0x46,17,'H')
    put(CTX+0x48,29,'H')

def reduce_packet(retain=(0,0xc,0x20,0x28,0x30,0x34)):
    before=memory(PACKET,0xd4)
    for off in range(0,0xcc,4):
        if off not in retain:
            put(PACKET+off,0)
    return before

def registers(bank=0):
    return {hex(o):hex(get(MMIO+bank*0x40000+o)) for o in
            (0x120,0x124,0x128,0x12c,0x130,0x310,0x3e8,0x3ec,0x3f0,0x580,0x67c,
             0x700,0x704,0x708,0x70c,0x710,0x714,0x718,0x71c,0x720,0x724,0x728,0x72c,0x730)}

try:
    # The complete native packet constructor, then a reduced configuration-only
    # driver. Output absence leaves a sentinel address; it is not hardware reset.
    for bank,output in ((0,False),(0,True),(1,False),(1,True)):
        reset(output)
        put(DRIVER+4,bank,'B')
        bank_base=MMIO+bank*0x40000
        calls=[execute(0x1019f3d0,[CTX]),execute(0x100b5716,[REQ,PACKET,STORAGE])]
        assert get(PARAM+0x3e,'B')==0
        before=reduce_packet()
        put(bank_base+0x3ec,0x5a5a5a5a)
        calls.append(execute(0x100d5c86,[DRIVER,PACKET,0,0]))
        assert get(bank_base+0x3ec)==(0x62000000 if output else 0x5a5a5a5a)
        assert get(bank_base+0x580)==int(output)
        assert get(bank_base+0x67c)==(0x300 if output else 0x100)
        assert get(bank_base+0x710)==get(bank_base+0x714)==0x1ed41ed4
        assert [get(bank_base+o) for o in range(0x120,0x134,4)]==[0]*5
        report['cases'].append(dict(name=f'full-constructor-output-{bank}-{int(output)}',calls=calls,bank=bank,
             before_packet_reduction=before,packet=memory(PACKET,0xd4),registers=registers(bank)))

    # Request flags at other offsets drive the five-bit core mask independently
    # of the optional RAW replacement address. Only the native core builder runs.
    for offsets,expected in (([0x370],2),([0x1c],8),([0x9c],24),([0x370,0x1c,0x9c],26)):
        reset()
        for off in offsets:
            put(REQ+off,OUTPUT)
        calls=[execute(0x100b4b1c,[PACKET,STORAGE]),execute(0x100b3f94,[REQ,PACKET]),
               execute(0x100b594e,[REQ,PACKET]),execute(0x100d6aae,[DRIVER,PARAM])]
        assert get(PARAM+0x3e,'B')==expected
        observed=[get(MMIO+o) for o in range(0x120,0x134,4)]
        assert observed==[(expected>>i)&1 for i in range(5)]
        report['cases'].append(dict(name='core-request-mask-'+hex(expected),offsets=[hex(x) for x in offsets],
              mask=expected,five_registers=observed,calls=calls,core=memory(PARAM,0x44)))

    # These control-byte changes are synthetic interventions, not identified menu
    # states. Owner kind 3 is tested WITHOUT a replacement output, respecting the
    # already recovered allocation gate for kinds 3..6.
    for kind,first,second in ((0,0,0),(0,1,0),(3,0,0),(3,0,1),(3,1,1)):
        reset(output=kind==0,owner_kind=kind)
        calls=[execute(0x1019f3d0,[CTX])]
        put(PARAM+0x17f,first,'B')
        put(PARAM+0x181,second,'B')
        calls += [execute(0x100b4b1c,[PACKET,STORAGE]),execute(0x100b3f94,[REQ,PACKET]),
                  execute(0x100b594e,[REQ,PACKET]),execute(0x1010722a,[DRIVER,PARAM+0x17e]),
                  execute(0x10107262,[DRIVER,PARAM+0x184])]
        boundary=list(uc.mem_read(PARAM+0x1c,8))
        expected={(0,0,0):[9,17,2,2,0,0,3,1],(0,1,0):[6,14,0,2,0,0,3,0],
                  (3,0,0):[6,12,2,2,9,3,3,0],(3,0,1):[5,10,1,2,7,3,3,0],
                  (3,1,1):[2,7,0,2,4,3,3,0]}[(kind,first,second)]
        assert boundary==expected,(boundary,expected)
        assert get(MMIO+0x700)==first*2 and get(MMIO+0x704)==second*2
        assert get(MMIO+0x710)==get(MMIO+0x714)==0x1ed41ed4
        report['cases'].append(dict(name=f'boundary-controls-{kind}-{first}-{second}',owner_kind=kind,
             control_bytes=[first,second],boundary_fields=boundary,calls=calls,registers=registers()))

    # Native spatial branch: ordinary control selection, exclusion bit, excluded
    # mode, and cached nonzero coefficients. No invented polynomial evaluator.
    for name,mode,selection,exclude,cached in (
            ('ordinary-zero',0,0,0,False),('excluded-bit',0,1,4,False),
            ('excluded-mode',7,1,0,False),('cached-polynomial',0,0,0,True)):
        reset()
        put(CTX+0x33,mode,'B')
        put(PROPS+0x2c,selection,'B')
        put(PROPS+0x45,exclude,'B')
        put(PROPS+0x96,int(cached),'B')
        if cached:
            # Cached flags 0,1 and six signed coefficients; arbitrary test data.
            uc.mem_write(CACHE+0x70,struct.pack('<4B6i',0,1,0,0,256,1048576,262144,-512,-524288,131072))
        calls=[execute(0x1019f3d0,[CTX]),execute(0x10196fe4,[CTX]),
               execute(0x10197500,[CTX+0x160]),execute(0x101975be,[CTX]),
               execute(0x101721c8,[CTX]),execute(0x10197678,[CTX]),
               execute(0x1010722a,[DRIVER,PARAM+0x17e]),execute(0x10107262,[DRIVER,PARAM+0x184]),
               execute(0x10107310,[DRIVER,PARAM+0x1a2])]
        controls=list(uc.mem_read(PARAM+0x17e,5))
        expected=[1,0,int(cached),0,int(name.startswith('excluded'))]
        assert controls==expected,(controls,expected)
        assert get(MMIO+0x700)==0x100+int(cached)
        assert get(MMIO+0x704)==int(name.startswith('excluded'))
        assert get(MMIO+0x710)==get(MMIO+0x714)==0x1ed41ed4
        coeffs=list(struct.unpack('<6i',uc.mem_read(COEFF+4,24)))
        assert get(COEFF,'B')==1-controls[4] and get(COEFF+1,'B')==controls[2]
        assert bytes(uc.mem_read(SPATIAL,34))==bytes(uc.mem_read(CTX+0x7e,34))
        assert bytes(uc.mem_read(SPATIAL+34,34))==bytes(uc.mem_read(CTX+0xa0,34))
        if cached:
            assert any(uc.mem_read(SPATIAL,68))
        else:
            assert not any(uc.mem_read(SPATIAL,68))
        put(TABLECTX,SPATIAL)
        put(TABLECTX+0x10,TABLES)
        put(TABLECTX+0x1c,RAM+0x1d000)
        # Stop at the boundary before unrelated table builders, without skipping
        # instructions inside the recovered 17+17 packing block.
        calls.append(execute(0x10198640,[TABLECTX],until=0x101986c6))
        expected_tables=bytes(uc.mem_read(SPATIAL,34))+b'\0\0'+bytes(uc.mem_read(SPATIAL+34,34))+b'\0\0'
        assert bytes(uc.mem_read(TABLES+0x2578,72))==expected_tables
        assert bytes(uc.mem_read(TABLES+0x39a9,2))==b'\1\1'
        calls.append(execute(0x100b5716,[REQ,PACKET,STORAGE]))
        table_descriptor=get(PACKET+0x38)
        assert get(table_descriptor)==TABLES+0x2578
        assert get(table_descriptor+4)==TABLES+0x259c
        before=reduce_packet((0,0xc,0x20,0x28,0x30,0x34,0x38))
        put(DRIVER+4,1,'B')
        calls.append(execute(0x100d5c86,[DRIVER,PACKET,0,0]))
        assert bytes(uc.mem_read(MMIO+0x40000+0x1200,72))==expected_tables
        assert get(MMIO+0x40000+0x3ec)==0x62000000
        assert get(MMIO+0x40000+0x710)==get(MMIO+0x40000+0x714)==0x1ed41ed4
        report['cases'].append(dict(name='spatial-'+name,calls=calls,controls=controls,coefficients=coeffs,
             parameter_context=memory(CTX,0xc4),parameters=memory(PARAM+0x17e,0x34),
             tables=memory(SPATIAL,68),serialized=memory(SERIAL,0x5c),exported=memory(COEFF,0x1c),
             registers=registers(),bank1_registers=registers(1),before_packet_reduction=before,
             packed_tables=memory(TABLES+0x2578,72),hardware_table_writes=memory(MMIO+0x40000+0x1200,72)))

    # Newly recovered fourth dependency of the shared black-level scalar:
    # an independently calculated capped parameter, uploaded at bank+0x720.
    # The two object-store segments are entered at explicit native boundaries;
    # they are not a simulated completed capture.
    for gain,flag in ((256,0),(256,1),(512,0),(512,1),(1024,0),(1024,1)):
        reset()
        source_input,selectors,gain_pairs=RAM+0x1e000,RAM+0x1e100,RAM+0x1e200
        put(0xc20aa7c8+0x3e1,flag,'B')
        uc.mem_write(CAL+0xbc7f0,struct.pack('<6H',101,202,303,300,405,606)*(7*33))
        uc.mem_write(source_input+8,struct.pack('<2I',1,15))
        uc.mem_write(selectors,bytes([0,0,2,0,0,0]))
        calls=[execute(0x100760b6,[source_input,selectors])]
        scalar=int(calls[-1]['r0'],16)
        assert scalar==(0 if flag else 300)
        calls.append(execute(0x1013f938,until=0x1013f95c,regs={0:scalar,4:OBJ}))
        calls.append(execute(0x100c278c,until=0x100c2798,regs={4:PROPS,5:OBJ}))
        for off,value in ((0x1c,gain_pairs),(0x20,FLAGS),(0xc4,SPATIAL),(0xc8,SERIAL),(0xec,CACHE)):
            put(CTX+off,value)
        uc.mem_write(gain_pairs,struct.pack('<2H',512,512))
        put(CTX+0x26,gain,'H')
        calls += [execute(0x1019e656,[CTX]),execute(0x1019e8b2,[CTX+0xf8]),
                  execute(0x1019f3d0,[CTX]),execute(0x10196060,[CTX],until=0x10196098),
                  execute(0x10107262,[DRIVER,PARAM+0x184]),execute(0x1019e75c,[CTX+0x24,TABLECTX])]
        thirds=[get(PARAM+o,'H') for o in (0x188,0x18e,0x194,0x19a)]
        assert thirds==[300]*4,thirds
        numerator=(0x3fff-scalar)*gain+sum(thirds)*64
        predicted=min((numerator+128)//256,0x7fff)
        assert get(CTX+0xf8+0x26,'H')==scalar
        assert get(PARAM+0x19c,'H')==get(MMIO+0x720)==predicted
        assert get(MMIO+0x718)==get(MMIO+0x71c)==0x012c012c
        assert get(MMIO+0x710)==get(MMIO+0x714)==(0 if flag else 0x1ed41ed4)
        report['cases'].append(dict(name=f'config-adjacent-limit-{gain}-{flag}',config=flag,gain=gain,
             scalar=scalar,third_values=thirds,numerator=numerator,capped_parameter=predicted,
             selected_original_table=memory(get(TABLECTX+0x1c),0x72),selection=memory(TABLECTX,0x28),
             owner_values=memory(OWNER+0x198,8),gain_context=memory(CTX+0x24,0x34),
             parameters=memory(PARAM+0x184,0x1a),registers=registers(),calls=calls))

    for scalar in (300,0):
        reset()
        put(PROPS+0x86,scalar,'H')
        put(PROPS+0x7e,1,'B')
        engine_input,output_pointers,cached_gain=RAM+0x1e000,RAM+0x1e100,RAM+0x1e200
        uc.mem_write(cached_gain,bytes(uc.mem_read(CTX+0x24,0x34)))
        uc.mem_write(cached_gain+0x2a,struct.pack('<5H',111,222,333,444,12345))
        for off,value in ((0,PROPS),(4,CACHE),(8,FLAGS),(0xc,FLAGS),
                          (0x10,SPATIAL),(0x14,SERIAL),(0x18,cached_gain),(0x1c,CACHE),(0x20,CTX)):
            put(engine_input+off,value)
        uc.mem_write(output_pointers,struct.pack('<8I',SERIAL,PARAM,FLAGS,SPATIAL,SERIAL,CACHE,COEFF,CACHE))
        calls=[execute(0x10171fae,[engine_input,CACHE,output_pointers],until=0x1019f3d0)]
        assert '0x1019e8b2' not in calls[-1]['blocks'] and '0x1019f10c' not in calls[-1]['blocks']
        calls += [execute(0x1019f3d0,[CTX]),execute(0x10196060,[CTX],until=0x10196098),
                  execute(0x10107262,[DRIVER,PARAM+0x184])]
        assert [get(PARAM+o,'H') for o in (0x188,0x18e,0x194,0x19a)]==[111,222,333,444]
        assert get(MMIO+0x720)==12345
        assert get(MMIO+0x710)==get(MMIO+0x714)==(0x1ed41ed4 if scalar else 0)
        report['cases'].append(dict(name=f'cached-adjacent-values-{scalar}',scalar=scalar,calls=calls,
             cache=memory(cached_gain,0x34),gain_context=memory(CTX+0x24,0x34),registers=registers()))
    report['ok']=True
except Exception:
    report['error']=traceback.format_exc()
    report['failure_pc']=hex(uc.reg_read(UC_ARM_REG_PC))
    report['failure_blocks']=list(trace)
    report['failure_writes']=list(writes)
    raise
finally:
    report['case_count']=len(report['cases'])
    report['firmware_unchanged']=hashlib.sha256(firmware.read_bytes()).hexdigest()==SHA
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'],case_count=report['case_count'],output=str(a.output))))

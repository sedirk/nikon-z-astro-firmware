"""Replay observed still-owner curve inputs and native state selectors.

RAM snapshots come from the existing synthetic no-lens QEMU setup. The static
builder is invoked in isolation, with explicit private requests and globals.
Counterfactual property/mode cases are marked artificial. No image math or NEF.
"""
from pathlib import Path
import argparse, hashlib, json, struct, traceback
import unicorn as un
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parents[2]
BASE, RAM, STACK, STOP = 0x10020000, 0x50000000, 0x52000000, 0x53000000
SHA = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
REGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
        UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
        UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--observed', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args(); assert __debug__
a.output.mkdir(parents=True, exist_ok=False)
source = Path(__file__).read_bytes(); (a.output/'probe-source.py').write_bytes(source)
native = json.loads((a.observed/'result.json').read_text(encoding='utf-8'))
assert native['ok'] and native['firmware_sha256'] == SHA
snap = native['final']
FRAME, OWNER, AUX = [int(snap[k]['address'], 16) for k in ('still_object', 'owner', 'still_resource_270')]
blob = (ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
assert hashlib.sha256(blob).hexdigest() == SHA
uc = un.Uc(un.UC_ARCH_ARM, un.UC_MODE_THUMB)
romsize = (len(blob)+4095)&~4095
uc.mem_map(BASE, romsize); uc.mem_write(BASE, blob)
uc.mem_protect(BASE, romsize, un.UC_PROT_READ | un.UC_PROT_EXEC)
regions = ((RAM,0x10000),(STACK,0x10000),(STOP,0x1000),(0xc1800000,0x4000000))
for addr, size in regions: uc.mem_map(addr, size)
initial = []
for off in range(0x14000,0x14120,16):
    src, dst, size, handler = struct.unpack_from('<4I',blob,off)
    if handler == 0x1002006c and 0xc1800000 <= dst < dst+size <= 0xc5800000:
        initial.append((src,dst,size))
blocks, reads = [], []


def block(_uc, pc, size, _):
    blocks.append(hex(pc))
    if len(blocks) > 100000: raise RuntimeError('block cap')


def read_hook(_uc, kind, address, size, value, _):
    if RAM <= address < RAM+0x10000 or 0xc1800000 <= address < 0xc5800000:
        reads.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)), address=hex(address), size=size,
                          bytes=bytes(uc.mem_read(address,size)).hex()))


uc.hook_add(un.UC_HOOK_BLOCK,block)
uc.hook_add(un.UC_HOOK_MEM_READ,read_hook)
# No RAM write / instruction hooks: known local Unicorn IT/memset sensitivity.


def put(addr,val,fmt='I'): uc.mem_write(addr,struct.pack('<'+fmt,val))
def get(addr,fmt='I'): return struct.unpack('<'+fmt,uc.mem_read(addr,struct.calcsize(fmt)))[0]
def memory(addr,size):
    data=bytes(uc.mem_read(addr,size))
    return dict(address=hex(addr),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())


report = dict(ok=False,scope=__doc__,firmware_sha256=SHA,probe_sha256=hashlib.sha256(source).hexdigest(),
    observed_files={name:hashlib.sha256((a.observed/name).read_bytes()).hexdigest() for name in ('result.json','events.json')},
    observed_directory=str(a.observed),unicorn=un.__version__,cases=[],
    startup_copies=[dict(source=hex(s),destination=hex(d),size=n) for s,d,n in initial],
    limitations=['Snapshot fields are observed emulator RAM, not real camera configuration.',
        'Private request cached byte is tested as both 0 and 1; downstream still stage was not reached in QEMU.',
        'Other RAM starts zero with original startup copies; c1f90ca8 flags stay zero.',
        'Main request dimensions are from the observed RAW descriptor; remaining request fields are zero.',
        'Full neutral-selector property comparisons require OS services and are performed by the separate QEMU probe.',
        'No MMIO region, sensor pixels, ISP arithmetic, encoder, NEF or flash modification.'])


def execute(entry,args=(),until=STOP,registers=None):
    blocks.clear(); reads.clear()
    for reg in REGS: uc.reg_write(reg,0)
    for reg,val in zip(REGS,args): uc.reg_write(reg,val)
    for i,val in (registers or {}).items(): uc.reg_write(REGS[i],val)
    uc.reg_write(UC_ARM_REG_SP,STACK+0xf000); uc.reg_write(UC_ARM_REG_LR,STOP|1)
    report['last_call']=dict(entry=hex(entry),args=[hex(x) for x in args],until=hex(until),
                            initial_registers={str(k):hex(v) for k,v in (registers or {}).items()})
    uc.ctl_flush_tb(); uc.emu_start(entry|1,until,count=1500000)
    pc=uc.reg_read(UC_ARM_REG_PC); assert pc==until,hex(pc)
    return dict(**report['last_call'],stopped_at=hex(pc),blocks=list(blocks),reads=list(reads),
                registers={f'r{i}':hex(uc.reg_read(reg)) for i,reg in enumerate(REGS)})


def reset():
    for addr,size in regions: uc.mem_write(addr,bytes(size))
    for src,dst,size in initial: uc.mem_write(dst,blob[src-BASE:src-BASE+size])
    for name in ('still_object','owner','still_resource_1f8','still_resource_1fc','still_resource_270'):
        row=snap[name]
        if 'bytes' in row: uc.mem_write(int(row['address'],16),bytes.fromhex(row['bytes']))


calls=[]
try:
    for cached in (0,1):
        report['current_case']=f'observed-still-cached-{cached}'; reset(); calls=[]
        before=memory(OWNER,0x3000)
        put(RAM,FRAME); put(RAM+4,cached,'B')
        for off,val in ((0,AUX+0x994),(4,AUX+0xb96),(8,OWNER+0x358),(12,RAM+0x2000),(16,OWNER+0x1014)):
            put(RAM+0x100+off,val)
        calls.append(execute(0x100c29c6,[RAM,RAM+0x100]))
        curve,mixed=memory(AUX+0x994,514),memory(AUX+0xb96,514)
        assert bytes.fromhex(curve['bytes'])==bytes.fromhex(mixed['bytes'])==struct.pack('<257H',*([1024]*257))
        assert get(OWNER+0x1024,'H')==0
        generator_props=memory(0xc27b60fc,108)
        # Build main properties from the same observed owner, with a private request.
        put(RAM+0x300,FRAME); put(RAM+0x32e,cached,'B')
        handle=bytes.fromhex(snap['still_resource_1f8']['bytes'])
        uc.mem_write(RAM+0x31c,handle[0x28:0x2c])
        calls.append(execute(0x100c24f2,[RAM+0x300,RAM+0x400]))
        mainprops=get(RAM+0x400)
        assert mainprops==0xc2763120 and get(mainprops+0x7d,'B')==0
        put(RAM+0x3000,mainprops); put(RAM+0x30d0,OWNER+0x394)
        calls.append(execute(0x101a0828,[RAM+0x3000]))
        assert get(OWNER+0x394+0x2b4)==1 and get(RAM+0x3604,'B')==0
        report['cases'].append(dict(name=report['current_case'],kind='snapshot-replay',cached=cached,calls=calls,
            owner_before=before,generator_properties=generator_props,main_properties=memory(mainprops,0xa0),
            curve=curve,mixed_curve=mixed,coefficients=memory(OWNER+0x1014,20),state=memory(OWNER+0x358,32),
            main_control=memory(OWNER+0x394+0x2a8,16),main_force_unit=get(RAM+0x3604,'B')))
    mode_cases=[('observed',{},0),('numeric-6-sub0',{0:6,0x1b0e:0},6),
        ('numeric-6-sub1',{0:6,0x1b0e:1},3),('numeric-6-sub2',{0:6,0x1b0e:2},2),
        ('flag88',{0x88:1},1),('flag98',{0x98:1},4),('numeric-3-sub2',{0:3,0x1a1:2},8)]
    for name,changes,expected in mode_cases:
        report['current_case']='mode-selector-'+name; reset()
        for off,val in changes.items(): put(OWNER+off,val,'I' if off==0x98 else 'B')
        calls=[execute(0x100c22e0,[FRAME])]
        value=int(calls[0]['registers']['r0'],16); assert value==expected
        report['cases'].append(dict(name=report['current_case'],kind='mode-counterfactual',changes={hex(k):v for k,v in changes.items()},
                                   calls=calls,value=value))
    report['ok']=True
except Exception:
    report['error']=traceback.format_exc(); print(report['error'])
    report['failure']=dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),blocks=list(blocks),reads=list(reads),completed_calls=calls)
finally:
    report['firmware_unchanged']=hashlib.sha256((ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()).hexdigest()==SHA
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']),output=str(a.output))))
raise SystemExit(0 if report['ok'] else 1)

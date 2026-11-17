"""Isolate candidate stages using original C3.80 code, with no pixel hardware model.

The complete processing packet and configuration-only driver execute unchanged.
NEFInfo tag serialization and RAW handle handoff are separate bounded calls;
they are not a completed capture, encoder run, pixel test, or complete NEF.
"""
from pathlib import Path
import argparse
import binascii
import hashlib
import json
import struct
import traceback
import unicorn as un
from unicorn.arm_const import *

ROOT=Path(__file__).resolve().parents[2]
BASE,RAM,STACK,STOP,CAL=0x10020000,0x50000000,0x52000000,0x53000000,0x54000000
OWNER,OBJ,PROPS,CTX=RAM,RAM+0x4000,RAM+0x8000,RAM+0x9000
A,PACKET,STORAGE,TABLES=OWNER+0x394,RAM+0xb000,RAM+0xc000,RAM+0x10000
FLAGS,DRIVER,INPUT,OUTPUT=RAM+0x15000,RAM+0x16000,RAM+0x17000,RAM+0x17100
CACHE,SPATIAL,REQ,TABLECTX=RAM+0x18000,RAM+0x19000,RAM+0x1a000,RAM+0x1c000
STAGE,META,TAG,PAYLOAD=RAM+0x20000,RAM+0x26000,RAM+0x27000,RAM+0x27400
PACKAGE,ENCODED,HEADER,HEADSLOT,CHUNK=RAM+0x28000,RAM+0x28400,RAM+0x28600,RAM+0x28680,RAM+0x28700
PREVIEW=RAM+0x28580
MMIO=0x20380000
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
firmware=ROOT/'firmware/decoded/eg1620_038000.bi'
blob=firmware.read_bytes()
assert hashlib.sha256(blob).hexdigest()==SHA
uc=un.Uc(un.UC_ARCH_ARM,un.UC_MODE_THUMB)
rom_size=(len(blob)+4095)&~4095
uc.mem_map(BASE,rom_size)
uc.mem_write(BASE,blob)
uc.mem_protect(BASE,rom_size,un.UC_PROT_READ|un.UC_PROT_EXEC)
for addr,size in ((RAM,0x40000),(STACK,0x10000),(STOP,0x1000),(CAL,0x100000),
                  (0xc1800000,0x2000000),(MMIO,0x10000),(MMIO+0x40000,0x10000)):
    uc.mem_map(addr,size)
blocks,writes,reads=[],[],[]
watched=((A+0x184,A+0x1a2),(TABLES+0x2578,TABLES+0x25c0),(OWNER+0xff8,OWNER+0x1014))
def on_block(_uc,pc,size,_):
    blocks.append(hex(pc))
    if len(blocks)>50000: raise RuntimeError('block cap')
def on_write(_uc,access,addr,size,value,_):
    writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,value=hex(value)))
def on_read(_uc,access,addr,size,value,_):
    if any(lo<=addr<hi for lo,hi in watched):
        reads.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,
                          bytes=bytes(uc.mem_read(addr,size)).hex()))
uc.hook_add(un.UC_HOOK_BLOCK,on_block)
uc.hook_add(un.UC_HOOK_MEM_WRITE,on_write,begin=MMIO,end=MMIO+0x4ffff)
uc.hook_add(un.UC_HOOK_MEM_READ,on_read,begin=RAM,end=RAM+0x3ffff)
def put(addr,value,fmt='I'): uc.mem_write(addr,struct.pack('<'+fmt,value))
def get(addr,fmt='I'): return struct.unpack('<'+fmt,uc.mem_read(addr,struct.calcsize(fmt)))[0]
def memory(addr,size):
    data=bytes(uc.mem_read(addr,size))
    return dict(address=hex(addr),size=size,bytes=data.hex(),sha256=hashlib.sha256(data).hexdigest())
report=dict(ok=False,scope=__doc__,firmware_sha256=SHA,probe_sha256=hashlib.sha256(source).hexdigest(),
            unicorn=un.__version__,cases=[],
            limitations=['Synthetic RAM and calibration, immutable original code.',
                         'No packet pruning. Driver r2=0 means no reset, start or completion.',
                         'Payload addresses 60000000,62000000,64000000 are unmapped.',
                         'The handoff block is entered separately, not after real hardware completion.',
                         'A stable payload descriptor cannot establish stable payload bytes.',
                         'Metadata changes cannot establish raw pixel changes.'])
def execute(entry,args=(),until=STOP,regs=None,stack_args=()):
    blocks.clear(); writes.clear(); reads.clear()
    for reg in REGS: uc.reg_write(reg,0)
    for reg,val in zip(REGS,args): uc.reg_write(reg,val)
    for index,val in (regs or {}).items(): uc.reg_write(REGS[index],val)
    uc.reg_write(UC_ARM_REG_SP,STACK+0xf000)
    uc.reg_write(UC_ARM_REG_LR,STOP|1)
    for index,val in enumerate(stack_args): put(STACK+0xf000+index*4,val)
    report['last_call']=dict(entry=hex(entry),args=[hex(x) for x in args],until=hex(until),
                            initial_registers={str(k):hex(v) for k,v in (regs or {}).items()},
                            stack_args=[hex(x) for x in stack_args])
    uc.ctl_flush_tb()
    uc.emu_start(entry|1,until,count=800000)
    pc=uc.reg_read(UC_ARM_REG_PC)
    assert pc==until,hex(pc)
    return dict(**report['last_call'],stopped_at=hex(pc),r0=hex(uc.reg_read(UC_ARM_REG_R0)),
                r1=hex(uc.reg_read(UC_ARM_REG_R1)),blocks=list(blocks),
                writes=list(writes),candidate_reads=list(reads))
def seed_original(addr,size):
    for src,dst,count,handler in (struct.unpack_from('<4I',blob,o) for o in range(0x14000,0x14120,16)):
        if handler==0x1002006c and dst<=addr and addr+size<=dst+count:
            rom=src+addr-dst
            uc.mem_write(addr,blob[rom-BASE:rom-BASE+size])
            return dict(address=hex(addr),rom=hex(rom),size=size)
    raise ValueError(hex(addr))
def reset(bank):
    for addr,size in ((RAM,0x40000),(STACK,0x10000),(MMIO,0x10000),(MMIO+0x40000,0x10000)):
        uc.mem_write(addr,bytes(size))
    put(0xc18812b4,1); put(0xc18fa954+0x14,CAL)
    put(OBJ+0x3a4,OWNER); put(OBJ+0x1f8,INPUT); put(OBJ+0x1fc,OUTPUT)
    put(OBJ+0x330,ENCODED); put(STAGE+0xc,OBJ)
    put(DRIVER+4,bank,'B')
    for handle,pixels in ((INPUT,0x60000000),(OUTPUT,0x62000000)):
        put(handle+0x24,2,'B')
        uc.mem_write(handle+0x26,struct.pack('<3H',9168,6104,4222))
        put(handle+0x34,pixels)
    for off,value in ((4,1),(8,INPUT),(0x1a8,OUTPUT),(0x35c,A),(0x360,TABLES),
                      (0x364,FLAGS),(0x378,1),(0x380,OBJ)):
        put(REQ+off,value)
    for off,value in ((0,PROPS),(4,CACHE),(0xd0,A),(0xd8,SPATIAL),(0xe4,OWNER+0xff8)):
        put(CTX+off,value)
    put(CTX+0x26,512,'H'); put(PROPS+0x86,300,'H')
    put(CTX+0xf8+0x4c,CTX+0x24); put(CTX+0xf8+0x26,300,'H')
    put(PROPS+0x58,6104*256); put(PROPS+0x5c,4222*256)
    put(PROPS+0x96,1,'B')
    uc.mem_write(CACHE+0x70,struct.pack('<4B6i',0,1,0,0,0,0,0,0,0,0))
    put(TABLECTX,SPATIAL); put(TABLECTX+0x10,TABLES); put(TABLECTX+0x1c,RAM+0x1d000)

try:
    reset(0)
    seeded=[seed_original(0xc18d38a0,4),seed_original(0xc18d36a0,64),seed_original(0xc18d3690,16)]
    calls=[execute(0x1028d6a0,[0,META]),execute(0x1028d6ac,[15,META]),execute(0x1028d2ea,[7,PACKAGE])]
    assert get(META+0xc)==0x11536d88 and get(META+0x10,'H')==5
    assert get(META+0x14)==0x11537c8a and get(META+0x18,'H')==5
    assert get(META+8)==0x1028d2eb and calls[-1]['r0']=='0x1'
    report['cases'].append(dict(name='nefinfo-profile-zero-group15',calls=calls,seeded=seeded,
                               selection=memory(META,0x1a),tags=[5,6,7,8,9]))
    baseline={}
    for bank in (0,1):
        for variation in ('baseline','negative-0','negative-1','negative-2','negative-3','limit','curve-0','curve-1'):
            reset(bank)
            if variation=='curve-0': put(CACHE+0x74,16,'i')
            if variation=='curve-1': put(CACHE+0x80,32,'i')
            calls=[execute(0x1019e8b2,[CTX+0xf8]),execute(0x1019f3d0,[CTX]),
                   execute(0x10196060,[CTX],until=0x10196098),execute(0x10196fe4,[CTX]),
                   execute(0x10197500,[CTX+0x160]),execute(0x101975be,[CTX]),
                   execute(0x10197678,[CTX]),execute(0x10198640,[TABLECTX],until=0x101986c6)]
            assert get(A+0x19c,'H')==32466
            assert [get(A+0x188+i*6,'H') for i in range(4)]==[300]*4
            intervention=None
            if variation.startswith('negative-'):
                channel=int(variation[-1]); addr=A+0x186+6*channel
                intervention=dict(address=hex(addr),old=get(addr,'H'),new=0,size=2)
                put(addr,0,'H')
            if variation=='limit':
                addr=A+0x19c
                intervention=dict(address=hex(addr),old=get(addr,'H'),new=12345,size=2)
                put(addr,12345,'H')
            calls.append(execute(0x100b5716,[REQ,PACKET,STORAGE]))
            packet_before=memory(PACKET,0xd4)
            calls.append(execute(0x100d5c86,[DRIVER,PACKET,0,0]))
            driver_call=calls[-1]
            assert memory(PACKET,0xd4)['bytes']==packet_before['bytes']
            final_mmio={}
            for w in driver_call['writes']:
                final_mmio[hex(int(w['address'],16)-MMIO-bank*0x40000)]=w['value']
            assert final_mmio['0x310']=='0x60000000' and final_mmio['0x3ec']=='0x62000000'
            assert final_mmio['0x580']=='0x1' and final_mmio['0x67c']=='0x300'
            # Execute the original version-pointer initializer and the complete
            # tag callback including its original CRC. No supplied tag payload.
            calls.append(execute(0x10305628))
            assert get(0xc27f1848)==0x11536080
            put(PACKAGE+0x34,OWNER)
            descriptor=blob[0x11536da8-BASE:0x11536db8-BASE]
            uc.mem_write(TAG,descriptor[:12])
            put(META+0xc,TAG); put(META+0x10,PAYLOAD)
            calls.append(execute(0x102899a0,[TAG,PACKAGE+0x30,META]))
            payload=bytes(uc.mem_read(PAYLOAD,104))
            assert get(TAG+4)==104 and get(TAG+8)==PAYLOAD-TAG
            assert get(META+0x10)==PAYLOAD+104
            assert payload[:4]==blob[0x11536080-BASE:0x11536084-BASE]
            assert struct.unpack_from('<H',payload,102)[0]==binascii.crc_hqx(payload[:102],0xffff)
            coefficients=[get(OWNER+0xffc+4*i,'i') for i in range(6)]
            assert [struct.unpack_from('<i',payload,o)[0] for o in (0x2c,0x1c,0x14,0x50,0x40,0x38)]==coefficients
            assert payload[4]==get(OWNER+0xff8,'B') and payload[0x5a]==get(OWNER+0xff9,'B')
            # Separate software-boundary observations; no completed hardware
            # operation is asserted and no encoded data is synthesized.
            calls.append(execute(0x100ae41e,until=0x100ae438,regs={4:OBJ,5:REQ}))
            assert get(OBJ+0x1f8)==OUTPUT
            calls.append(execute(0x100af648,[STAGE],until=0x100a323e))
            assert calls[-1]['r0']==hex(OUTPUT+0x24) and calls[-1]['r1']==hex(ENCODED+0x50)
            # Illustrative opaque descriptor, never a generated RAW payload.
            put(ENCODED+0x58,0x64000000); put(ENCODED+0x5c,0x123456)
            put(HEADER+4,HEADSLOT); put(HEADSLOT,RAM+0x29000)
            calls.append(execute(0x100b1634,[1,OWNER,ENCODED,PREVIEW],stack_args=[HEADER,PACKAGE]))
            put(META+8,PACKAGE); put(META+0x2c,0x123456)
            calls.append(execute(0x10271226,[1,META,3,CHUNK]))
            assert list(struct.unpack('<3I',uc.mem_read(CHUNK,12)))==[0x64000000,0x123456,0]
            if variation=='baseline': baseline[bank]=(final_mmio,payload)
            old,old_payload=baseline[bank]
            changed={k:dict(before=old.get(k),after=final_mmio.get(k))
                     for k in sorted(set(old)|set(final_mmio),key=lambda x:int(x,16))
                     if old.get(k)!=final_mmio.get(k)}
            if variation=='baseline': expected=set()
            elif variation.startswith('negative-'): expected={hex(0x710+4*(int(variation[-1])//2))}
            elif variation=='limit': expected={'0x720'}
            elif variation=='curve-0': expected={hex(x) for x in range(0x1200,0x1224,4)}
            else: expected={hex(x) for x in range(0x1224,0x1248,4)}
            assert set(changed)==expected,(variation,changed)
            assert (payload==old_payload)==(not variation.startswith('curve-'))
            report['cases'].append(dict(name=f'{variation}-bank{bank}',bank=bank,variation=variation,
                intervention=intervention,calls=calls,packet=packet_before,registers=final_mmio,
                changed_registers=changed,table=memory(SPATIAL,68),coefficients=coefficients,
                metadata_tag=memory(TAG,12),metadata_payload=memory(PAYLOAD,104),
                metadata_changed_offsets=[i for i,(x,y) in enumerate(zip(old_payload,payload)) if x!=y],
                raw_chunk_descriptor=memory(CHUNK,12),
                hardware_pixels_observed=False,nef_created=False))
    report['ok']=True
except Exception:
    report['error']=traceback.format_exc()
    report['failure_pc']=hex(uc.reg_read(UC_ARM_REG_PC))
    report['failure_blocks']=list(blocks)
    report['completed_segments_in_failed_case']=calls
    raise
finally:
    report['firmware_unchanged']=hashlib.sha256(firmware.read_bytes()).hexdigest()==SHA
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']),pc=hex(uc.reg_read(UC_ARM_REG_PC)))))

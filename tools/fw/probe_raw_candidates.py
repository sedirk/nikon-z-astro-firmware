"""Execute actual candidate module copies against bounded original C3.80 paths.

No pixel buffers or ISP algorithm are supplied. Native request construction,
configuration, conditional handle handoff, encoder entry and BlackLevel callback
are tested in separate segments; a handoff segment is not hardware completion.
"""
from pathlib import Path
import argparse, hashlib, json, struct, traceback, gc
import unicorn as un
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parents[2]
BASE, RAM, STACK, STOP, CAL = 0x10020000, 0x50000000, 0x52000000, 0x53000000, 0x54000000
OWNER, FRAME, PROPS, CTX = RAM, RAM+0x4000, RAM+0x8000, RAM+0x9000
A, PACKET, STORAGE = OWNER+0x394, RAM+0xb000, RAM+0xc000
DRIVER, INPUT, OUTPUT, ENCODED = RAM+0x16000, RAM+0x17000, RAM+0x17100, RAM+0x17200
CACHE, SPATIAL, SERIAL = RAM+0x18000, RAM+0x19000, RAM+0x19200
ENGINE, VECTOR, CACHED_GAIN = RAM+0x1e000, RAM+0x1e100, RAM+0x1e200
GAIN_PAIR, MAINREQ, MAINOUT = RAM+0x1f000, RAM+0x21000, RAM+0x21100
TAG, META, PAYLOAD, PACKAGE = RAM+0x27000, RAM+0x27200, RAM+0x27400, RAM+0x28000
STAGE = RAM+0x40000
TABLES, FLAGS, REQ, MMIO = STAGE+0x588, STAGE+0x3f94, 0xc233525c, 0x20380000
REGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
        UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9,
        UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12]


def sha(b): return hashlib.sha256(b).hexdigest()


class Rig:
    def __init__(self, blob, snapshots):
        self.blob, self.snapshots = blob, snapshots
        self.uc = un.Uc(un.UC_ARCH_ARM, un.UC_MODE_THUMB)
        size = (len(blob)+4095)&~4095
        self.uc.mem_map(BASE, size); self.uc.mem_write(BASE, blob)
        self.uc.mem_protect(BASE, size, un.UC_PROT_READ|un.UC_PROT_EXEC)
        self.regions = ((RAM,0x60000),(STACK,0x10000),(STOP,0x1000),(CAL,0x100000),
                        (0xc1800000,0x4000000),(MMIO,0x10000),(MMIO+0x40000,0x10000),
                        (0x20068000,0x2000))
        for address, n in self.regions: self.uc.mem_map(address, n)
        self.blocks, self.writes, self.reads = [], [], []
        self.uc.hook_add(un.UC_HOOK_BLOCK, self.on_block)
        self.uc.hook_add(un.UC_HOOK_MEM_WRITE, self.on_write, begin=MMIO, end=MMIO+0x4ffff)
        self.uc.hook_add(un.UC_HOOK_MEM_READ, self.on_read, begin=RAM, end=RAM+0x5ffff)

    def on_block(self, uc, pc, size, _):
        self.blocks.append(hex(pc))
        if len(self.blocks)>100000: raise RuntimeError('block cap')

    def on_write(self, uc, access, addr, size, value, _):
        self.writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,value=hex(value)))

    def on_read(self, uc, access, addr, size, value, _):
        if OWNER+0x198 <= addr < OWNER+0x1a0 or A+0x184 <= addr < A+0x19e or PROPS+0x86 <= addr < PROPS+0x88:
            self.reads.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,
                                   bytes=bytes(uc.mem_read(addr,size)).hex()))

    def put(self, addr, value, fmt='I'): self.uc.mem_write(addr, struct.pack('<'+fmt,value))
    def get(self, addr, fmt='I'): return struct.unpack('<'+fmt,self.uc.mem_read(addr,struct.calcsize(fmt)))[0]
    def mem(self, addr, n):
        data=bytes(self.uc.mem_read(addr,n))
        return dict(address=hex(addr),size=n,bytes=data.hex(),sha256=sha(data))

    def call(self, entry, args=(), until=STOP, regs=None):
        self.blocks.clear(); self.writes.clear(); self.reads.clear()
        for reg in REGS: self.uc.reg_write(reg,0)
        for reg,val in zip(REGS,args): self.uc.reg_write(reg,val)
        for i,val in (regs or {}).items(): self.uc.reg_write(REGS[i],val)
        self.uc.reg_write(UC_ARM_REG_SP,STACK+0xf000); self.uc.reg_write(UC_ARM_REG_LR,STOP|1)
        self.last_call=dict(entry=hex(entry),args=[hex(x) for x in args],until=hex(until),
                            initial_registers={str(k):hex(v) for k,v in (regs or {}).items()})
        self.uc.ctl_flush_tb(); self.uc.emu_start(entry|1,until,count=1500000)
        pc=self.uc.reg_read(UC_ARM_REG_PC)
        assert pc==until,hex(pc)
        return dict(**self.last_call,stopped_at=hex(pc),blocks=list(self.blocks),
                    writes=list(self.writes),reads=list(self.reads),
                    registers={f'r{i}':hex(self.uc.reg_read(reg)) for i,reg in enumerate(REGS)})

    def reset(self, cfg):
        for addr,n in self.regions: self.uc.mem_write(addr,bytes(n))
        for off in range(0x14000,0x14120,16):
            src,dst,n,handler=struct.unpack_from('<4I',self.blob,off)
            if handler==0x1002006c and 0xc1800000 <= dst < dst+n <= 0xc5800000:
                self.uc.mem_write(dst,self.blob[src-BASE:src-BASE+n])
        # Reuse an observed object shape; relocate its owner and RAW descriptors.
        for name in ('still_object','owner','still_resource_1f8','still_resource_1fc','still_resource_270'):
            row=self.snapshots[name]
            if 'bytes' in row: self.uc.mem_write(int(row['address'],16),bytes.fromhex(row['bytes']))
        self.uc.mem_write(FRAME,bytes.fromhex(self.snapshots['still_object']['bytes']))
        self.uc.mem_write(OWNER,bytes.fromhex(self.snapshots['owner']['bytes']))
        self.put(FRAME+0x3a4,OWNER); self.put(FRAME+0x1f8,INPUT)
        self.put(FRAME+0x1fc,OUTPUT if cfg.get('output',True) else 0)
        self.put(FRAME+0x330,ENCODED); self.put(FRAME+0x314,0); self.put(FRAME+0x318,RAM+0x33000)
        self.put(STAGE+0xc,FRAME); self.put(OWNER,cfg.get('kind',0),'B')
        self.put(OWNER+0x190,cfg.get('owner_mode',0),'B')
        for off in (0x198,0x19a,0x19c,0x19e): self.put(OWNER+off,cfg['scalar'],'H')
        self.put(0xc18812b4,1); self.put(0xc18fa954+0x14,CAL)
        self.put(0xc188d8c4,1,'B'); self.put(DRIVER+4,cfg['bank'],'B')
        for handle,pixels in ((INPUT,0x60000000),(OUTPUT,0x62000000)):
            self.put(handle+0x24,2,'B')
            self.uc.mem_write(handle+0x26,struct.pack('<3H',9168,6104,4222))
            self.put(handle+0x34,pixels)
        self.put(INPUT+0x18,0x1234); self.put(INPUT+0x1c,0x5678)
        self.put(MAINREQ,FRAME)
        self.uc.mem_write(MAINREQ+0x1c,struct.pack('<2H',6104,4222))
        self.put(MAINREQ+0x2e,cfg.get('builder_mode',0),'B')
        self.put(MAINREQ+0x24,CACHED_GAIN if cfg['cached'] else 0)


def diff_words(a,b):
    return {hex(i):[struct.unpack_from('<I',a,i)[0],struct.unpack_from('<I',b,i)[0]]
            for i in range(0,len(a),4) if a[i:i+4]!=b[i:i+4]}


def run_case(rig, variant, cfg):
    u,p,g=rig.uc,rig.put,rig.get
    rig.reset(cfg); calls=[]
    before_owner=rig.mem(OWNER,0x3000)
    calls.append(rig.call(0x100c24f2,[MAINREQ,MAINOUT]))
    mainprops=g(MAINOUT); assert mainprops==0xc2763120
    properties=rig.mem(mainprops,0xa0)
    assert rig.mem(OWNER,0x3000)==before_owner
    expected_scalar=0 if variant=='still-offset-source-zero' else cfg['scalar']
    assert g(mainprops+0x86,'H')==expected_scalar
    assert g(mainprops+0x7e,'B')==cfg['cached']
    u.mem_write(PROPS,bytes.fromhex(properties['bytes']))
    # Bounded downstream fixtures: original algorithms, explicit independent
    # cache/gain inputs. These are not a simulated uninterrupted exposure.
    for off,val in ((0,PROPS),(4,CACHE),(0x1c,GAIN_PAIR),(0x20,FLAGS),(0xc4,SPATIAL),
                    (0xc8,SERIAL),(0xd0,A),(0xd8,SPATIAL),(0xdc,SERIAL),(0xe4,OWNER+0xff8),(0xec,CACHE)):
        p(CTX+off,val)
    p(CTX+0x26,cfg['gain'],'H'); u.mem_write(GAIN_PAIR,struct.pack('<2H',512,512))
    if cfg['cached']:
        cached=bytearray(0x34)
        struct.pack_into('<H',cached,2,cfg['gain'])
        struct.pack_into('<2H',cached,0xa,512,512)
        struct.pack_into('<5H',cached,0x2a,111,222,333,444,12345)
        u.mem_write(CACHED_GAIN,bytes(cached))
        for off,val in ((0,PROPS),(4,CACHE),(8,FLAGS),(12,FLAGS),(16,SPATIAL),(20,SERIAL),
                        (24,CACHED_GAIN),(28,CACHE),(32,CTX)): p(ENGINE+off,val)
        u.mem_write(VECTOR,struct.pack('<8I',SERIAL,A,FLAGS,SPATIAL,SERIAL,CACHE,OWNER+0xff8,CACHE))
        calls.append(rig.call(0x10171fae,[ENGINE,CACHE,VECTOR],until=0x1019f3d0))
        assert '0x1019e8b2' not in calls[-1]['blocks']
    else:
        calls.extend([rig.call(0x1019e656,[CTX]),rig.call(0x1019e8b2,[CTX+0xf8])])
    calls.extend([rig.call(0x1019f3d0,[CTX]),rig.call(0x10196060,[CTX],until=0x10196098)])
    expected_negative=0 if variant in ('negative-only','still-offset-source-zero') else (-cfg['scalar'])&0xffff
    assert [g(A+x,'H') for x in (0x186,0x18c,0x192,0x198)]==[expected_negative]*4
    thirds=[111,222,333,444] if cfg['cached'] else [300]*4
    expected_limit=12345 if cfg['cached'] else min(((16383-expected_scalar)*cfg['gain']+64*sum(thirds)+128)//256,32767)
    assert [g(A+x,'H') for x in (0x188,0x18e,0x194,0x19a)]==thirds
    assert g(A+0x19c,'H')==expected_limit,(variant,cfg,g(A+0x19c,'H'),expected_limit)
    parameters=rig.mem(A,0x500)
    # Confirm request clearing removes a stale previous destination before the
    # patched assignment is skipped; omission must not retain a prior frame.
    p(REQ+0x1a8,0x5a5a5a5a)
    request_before=rig.mem(REQ,0x390)
    calls.append(rig.call(0x100ae33e,[STAGE],until=0x100b4c78))
    replacing=variant!='still-preserve-front-raw' and cfg.get('output',True) and cfg.get('owner_mode',0) in (0,1) and cfg.get('kind',0) not in (3,4,5,6)
    assert g(REQ+8)==INPUT and g(REQ+0x1a8)==(OUTPUT if replacing else 0)
    request=rig.mem(REQ,0x390)
    calls.append(rig.call(0x100b5716,[REQ,PACKET,STORAGE]))
    packet=rig.mem(PACKET,0xd4)
    # A stale destination sentinel makes skip-vs-disable behavior observable.
    bank=MMIO+cfg['bank']*0x40000
    p(bank+0x3ec,0x5a5a5a5a)
    calls.append(rig.call(0x100d5c86,[DRIVER,PACKET,0,0]))
    assert g(bank+0x310)==0x60000000
    assert g(bank+0x3ec)==(0x62000000 if replacing else 0x5a5a5a5a)
    assert g(bank+0x580)==int(replacing) and g(bank+0x67c)==(0x300 if replacing else 0x100)
    encoded_negative=expected_negative&8191
    assert g(bank+0x710)==g(bank+0x714)==encoded_negative*0x10001
    assert g(bank+0x720)==expected_limit
    registers=rig.mem(bank,0x10000)
    assert bytes(u.mem_read(MMIO+(1-cfg['bank'])*0x40000,0x10000))==bytes(0x10000)
    # Actual serialized BlackLevel metadata remains the source owner values.
    p(PACKAGE+0x34,OWNER)
    u.mem_write(TAG,rig.blob[0x11537028-BASE:0x11537034-BASE])
    p(META+8,TAG); p(META+0x10,PAYLOAD)
    calls.append(rig.call(0x1028a9d8,[TAG,PACKAGE+0x30,META]))
    tag=rig.mem(PAYLOAD,8)
    assert bytes.fromhex(tag['bytes'])==struct.pack('<4H',*([cfg['scalar']]*4))
    calls.append(rig.call(0x100ae41e,until=0x100ae438,regs={4:FRAME,5:REQ}))
    selected=OUTPUT if replacing else INPUT
    assert g(FRAME+0x1f8)==selected
    if cfg.get('owner_mode',0)==0:
        calls.append(rig.call(0x100af648,[STAGE],until=0x100a323e))
        assert calls[-1]['registers']['r0']==hex(selected+0x24)
        assert calls[-1]['registers']['r1']==hex(ENCODED+0x50)
        encoder_input=selected+0x24
    else:
        calls.append(rig.call(0x100af648,[STAGE]))
        assert '0x100a323e' not in calls[-1]['blocks']
        encoder_input=None
    return dict(variant=variant,configuration=cfg,calls=calls,properties=properties,
        parameters=parameters,request_before=request_before,request=request,packet=packet,registers=registers,
        blacklevel_payload=tag,negative_halfwords=[expected_negative]*4,limit=expected_limit,
        replacing=replacing,selected_handle=hex(selected),
        encoder_input=hex(encoder_input) if encoder_input else None,
        final_frame=rig.mem(FRAME,0x3c0),hardware_pixels_verified=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--modules',type=Path,required=True)
    parser.add_argument('--observed',type=Path,default=ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); assert __debug__
    args.output.mkdir(parents=True,exist_ok=False)
    (args.output/'probe-source.py').write_bytes(Path(__file__).read_bytes())
    builds=json.loads((args.modules/'build.json').read_text())
    snap=json.loads(args.observed.read_text())['final']
    source=ROOT/'firmware/decoded/eg1620_038000.bi'
    original=source.read_bytes(); assert sha(original)==builds['source_sha256']
    variants=[('original',source,sha(original))]+[(c['id'],args.modules/c['file'],c['output_sha256']) for c in builds['candidates']]
    configs=[dict(name='zero',scalar=0,gain=512,cached=0,bank=0),
             dict(name='low',scalar=64,gain=256,cached=0,bank=0),
             dict(name='baseline',scalar=300,gain=512,cached=0,bank=0),
             dict(name='high-bank1',scalar=1024,gain=1024,cached=0,bank=1,builder_mode=1),
             dict(name='cached',scalar=300,gain=512,cached=1,bank=0),
             dict(name='cached-bank1',scalar=300,gain=256,cached=1,bank=1,builder_mode=1),
             dict(name='without-replacement',scalar=300,gain=512,cached=0,bank=0,output=False),
             dict(name='owner-mode2',scalar=300,gain=512,cached=0,bank=0,owner_mode=2)]
    report=dict(ok=False,scope=__doc__,source_sha256=sha(original),probe_sha256=sha(Path(__file__).read_bytes()),
        observed_sha256=sha(args.observed.read_bytes()),modules_directory=str(args.modules),
        unicorn=un.__version__,cases=[],limitations=[
            'Full static property builder uses an observed emulator object shape with synthetic scalar values.',
            'Gain/cache fixtures and subsequent processing calls are bounded segments, not an uninterrupted capture.',
            'Complete packet constructor and driver configuration run; driver r2=0 omits reset/start/completion.',
            'Pixel addresses 0x60000000/0x62000000 are unmapped; no pixel arithmetic or NEF file is generated.',
            'Direct-call inventory is not exhaustive proof against computed/indirect callers.'])
    baseline={}; rig=None
    try:
        for variant,path,digest in variants:
            blob=path.read_bytes(); assert sha(blob)==digest
            rig=Rig(blob,snap)
            for cfg in configs:
                report['current_case']=[variant,cfg['name']]
                row=run_case(rig,variant,cfg); row['module_sha256']=digest
                if variant=='original': baseline[cfg['name']]=row
                old=baseline[cfg['name']]
                changed=diff_words(bytes.fromhex(old['registers']['bytes']),bytes.fromhex(row['registers']['bytes']))
                row['changed_registers_vs_original']=changed
                allowed={'negative-only':{0x710,0x714},'still-offset-source-zero':{0x710,0x714,0x720},
                         'still-preserve-front-raw':{0x3e8,0x3ec,0x3f0,0x580,0x67c},'original':set()}[variant]
                assert {int(x,16) for x in changed}<=allowed,(variant,changed)
                assert row['blacklevel_payload']==old['blacklevel_payload']
                if variant!='still-offset-source-zero': assert row['properties']==old['properties']
                else:
                    x,y=bytes.fromhex(old['properties']['bytes']),bytes.fromhex(row['properties']['bytes'])
                    assert all(i in (0x86,0x87) for i,(a,b) in enumerate(zip(x,y)) if a!=b)
                if variant=='still-preserve-front-raw': assert row['parameters']==old['parameters']
                report['cases'].append(row)
                print(variant,cfg['name'],row['negative_halfwords'],row['limit'],row['encoder_input'],list(changed),flush=True)
            rig=None; gc.collect()
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc(); print(report['error'],flush=True)
        if rig:
            report['failure']=dict(last_call=rig.last_call,pc=hex(rig.uc.reg_read(UC_ARM_REG_PC)),
                blocks=rig.blocks,writes=rig.writes,reads=rig.reads)
    finally:
        report['original_preserved']=source.read_bytes()==original
        (args.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']),original_preserved=report['original_preserved'])))
    raise SystemExit(0 if report['ok'] else 1)


if __name__=='__main__': main()

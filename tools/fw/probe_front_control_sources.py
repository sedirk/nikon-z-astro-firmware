"""Execute original source-copy, context, full policy selection and upload paths.

Private labelled calibration; no sensor pixels or hardware correction algorithm.
Segments before the complete context/selector calls are explicitly bounded.
The 1013fa20 prefix is a back-end owner copy with matching field offsets. The
QEMU trace subsequently established that its object differs from the frontend
owner: joining them here is an artificial data-flow fixture, not an observed
continuous capture chain. The verified frontend chain begins at 100f6494.
"""
from pathlib import Path
import argparse, gc, itertools, json, struct, traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_R0
from probe_raw_candidates import Rig, ROOT, RAM, STACK, CAL, OWNER, FRAME, MAINREQ, sha

CTX, PACKET, CONTROL, REG = 0xc18fa844, 0xc29a34c0, 0xc29a3520, 0x20068500
SOURCE, INPUT, OUTPUT = RAM+0x35000, RAM+0x36000, RAM+0x37000

def initialize(rig, inp):
    rig.reset(dict(scalar=1008, bank=0, cached=0))
    u,p = rig.uc,rig.put
    u.mem_write(INPUT,inp)
    # Every labelled policy record has a different ancillary fingerprint, with
    # Boolean enables set deliberately. These are not measured camera records.
    for i in range(256):
        data=bytearray(struct.pack('<64H', *[100+i+j for j in range(64)]))
        data[:28]=struct.pack('<14H', *([1]*14))
        u.mem_write(CAL+0x55c0+i*128,bytes(data))
    u.mem_write(CAL+0xbe018,struct.pack('>2h',100,80))
    u.mem_write(CAL+0xbe022,struct.pack('>h',100))
    u.mem_write(CTX,b'\xa5'*0xe4)
    p(CTX+0x34,0);p(CTX+0x84,0);p(CTX+0x91,0,'B')
    p(0xc18fa954+5,0,'B')
    u.mem_write(REG,b'\x6b'*0x500)
    u.mem_write(SOURCE,b'\x37'*0xb0)
    p(SOURCE+0xa0,7,'B')

def one(rig, cfg, inp):
    initialize(rig,inp)
    u,p,g=rig.uc,rig.put,rig.get
    p(INPUT+0x40,cfg['config3d8'],'B')
    p(INPUT+0x41,cfg['config3d9'],'B')
    p(INPUT+0x20,cfg['long_flag'])
    p(INPUT+0x10,cfg['tv'],'i')
    p(SOURCE+0xa8,0x07050000 | (cfg['override']<<8))
    # Actual original producer copies 4 bytes, not only owner+0x259.
    calls=[rig.call(0x1013fa20,until=0x1013fa50,regs={4:FRAME,6:SOURCE if cfg['source_present'] else 0,7:0})]
    assert g(OWNER+0x259,'B')==(cfg['override'] if cfg['source_present'] else 0)
    # Run the actual owner -> input argument byte loads/stores, with an observed
    # initial argument shape. No configuration getter result is stubbed.
    p(MAINREQ,OWNER)
    u.mem_write(STACK+0xf000,bytes(u.mem_read(INPUT,0x50)))
    calls.append(rig.call(0x100f6494,until=0x100f64bc,regs={7:MAINREQ}))
    copied=bytes(u.mem_read(STACK+0xf000,0x50));u.mem_write(INPUT,copied)
    calls.append(rig.call(0x10179962,[INPUT,OUTPUT]))
    context=rig.mem(CTX,0xe4)
    assert g(CTX+0x38)==0
    assert g(CTX+0x5d,'B')==copied[0x45]
    assert g(CTX+0x80)==int(cfg['config3d8'] in (0,1))
    expected70=int(cfg['config3d9']==1 or (cfg['config3d9']==0 and
                     (cfg['long_flag']!=0 or cfg['tv']<=3*g(CTX+0xc,'h'))))
    assert g(CTX+0x70)==expected70
    calls.append(rig.call(0x1011d540))
    selected=[]
    def hook(uc,pc,size,_):
        address=uc.reg_read(UC_ARM_REG_R0)
        selected.append(dict(address=hex(address),index=(address-CAL-0x55c0)//128,
                             bytes=bytes(uc.mem_read(address,128)).hex()))
    h=u.hook_add(un.UC_HOOK_CODE,hook,begin=0x1011d7a4,end=0x1011d7a4)
    try:calls.append(rig.call(0x1011db02,[CTX,1]))
    finally:u.hook_del(h)
    assert len(selected)==1 and 0<=selected[0]['index']<256
    controls=list(struct.unpack('<14I',u.mem_read(CONTROL,56)))
    expected=[1]*14
    if g(CTX+0x5d,'B')==2:expected[2]=0
    if not g(CTX+0x80):expected[10]=0
    assert controls==expected,(cfg,controls)
    ancillary=rig.mem(CONTROL+56,0xe6)
    calls.append(rig.call(0x100bccd0,[PACKET]))
    expectedword=sum(x<<(13-i) for i,x in enumerate(expected))
    assert g(REG)==expectedword
    return dict(configuration=cfg,context=context,input=rig.mem(INPUT,0x50),
        owner_control_bytes=rig.mem(OWNER+0x250,0x10),selected=selected[0],controls=controls,
        word=hex(g(REG)),ancillary=ancillary,registers=rig.mem(REG,0x500),calls=calls)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    for name in ('probe_front_control_sources.py','probe_raw_candidates.py'):
        (a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    observed=ROOT/'analysis/raw-body-front-2026-11-08/native-body-front/events.json'
    events=json.loads(observed.read_text())
    inp=bytes.fromhex(next(e for e in events if e['event']=='still_source_entry')['memory']['still_source_input']['bytes'])
    snap=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    variants=[('original',ROOT/'firmware/decoded/eg1620_038000.bi'),
        ('modified3',ROOT/'outputs/Z6-C380-spatial-neutral-reviewed-2026-11-09/01_TEST_MODIFIED3/EG162080.BIN')]
    cfgs=[dict(config3d8=c8,config3d9=0,long_flag=0,tv=2496,override=o,source_present=present)
        for c8,o,present in itertools.product((0,1,2,255),(0,1,2,3),(False,True))]
    cfgs += [dict(config3d8=0,config3d9=c9,long_flag=lf,tv=tv,override=0,source_present=True)
             for c9,lf,tv in itertools.product((0,1,2),(0,1),(575,576,577,-192))]
    report=dict(ok=False,scope=__doc__,observed_sha256=sha(observed.read_bytes()),
        rows=[],comparisons=[],hardware_pixels_verified=False,
        limitations=['Only copied input shape is observed in QEMU; calibration and control values are artificial.',
            'Source copy and owner argument extraction are bounded segments; context, policy selection and register upload are full native functions.',
            'No claim that a numeric control bit has a known hardware correction meaning.'])
    baseline={}
    try:
        for variant,path in variants:
            blob=path.read_bytes();rig=Rig(blob,snap)
            rig.uc.hook_add(un.UC_HOOK_MEM_WRITE,rig.on_write,begin=0x20068000,end=0x20069fff)
            for i,cfg in enumerate(cfgs):
                report['current_case']=[variant,i,cfg]
                row=one(rig,cfg,inp);row.update(variant=variant,module_sha256=sha(blob))
                report['rows'].append(row)
                if variant=='original':baseline[i]=row
                else:
                    for key in ('context','input','owner_control_bytes','selected','controls','word','ancillary','registers','calls'):
                        assert baseline[i][key]==row[key],(i,key)
                    report['comparisons'].append(dict(case=i,identical=True))
            del rig;gc.collect()
        # With all other inputs fixed, override 1 -> 2 changes only bit11 in
        # uploaded MMIO, and does not change policy record/ancillary thresholds.
        pairs=[]
        for c8 in (0,1,2,255):
            rows=[r for r in report['rows'] if r['variant']=='modified3' and r['configuration']['source_present'] and r['configuration']['config3d8']==c8 and r['configuration']['tv']==2496]
            on=next(r for r in rows if r['configuration']['override']==1)
            off=next(r for r in rows if r['configuration']['override']==2)
            assert on['selected']==off['selected'] and on['ancillary']==off['ancillary']
            b0,b1=bytes.fromhex(on['registers']['bytes']),bytes.fromhex(off['registers']['bytes'])
            assert [j for j,(x,y) in enumerate(zip(b0,b1)) if x!=y]==[1]
            assert int(on['word'],16)^int(off['word'],16)==0x800
            pairs.append(dict(config3d8=c8,only_changed_register=hex(REG),xor='0x800',same_record_and_ancillary=True))
        report['bit11_isolation']=pairs;report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        if 'rig' in locals():report['last_call']=rig.last_call;report['last_blocks']=rig.blocks[-30:]
        raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],rows=len(report['rows']),pairs=len(report['comparisons']))))

if __name__=='__main__':main()

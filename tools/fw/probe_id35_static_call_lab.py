"""Differential native testing of the exact-static-call ID35 LAB module.

Calibration and descriptor data are labelled private fixtures. Only the two
RTOS mutex wrappers 10170df0/10170dea are stubbed to return success; no image
algorithm, DMA completion, sensor data or saved NEF is supplied. Ordinary
calls, the tagged static call, state restoration, and untouched 33x4 upload
are compared against exact modified4 bytes.
"""
from pathlib import Path
import argparse,gc,itertools,json,struct,traceback
import unicorn as un
from unicorn.arm_const import *
from probe_raw_candidates import Rig,ROOT,BASE,CAL,REGS,STACK,sha
from prepare_id35_static_lab import M4,HASH

ROUND=ROOT/'analysis/raw-fixed-operators-2026-11-09'
LAB=ROUND/'static-call-lab/modified4-id35-static-call-off-lab.bi'
CTX,STATE,GLOBAL,PROC,RESOURCE,PKT=0xc18fa844,0xc18fa954,0xc29a3230,0xc29a32b4,0x56000000,0xc29a34c0

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--supplement',action='store_true',help='Only the submode2/index4..7 coverage gap; retain earlier completed matrix evidence.')
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    for name in (Path(__file__).name,'probe_raw_candidates.py','prepare_id35_static_call_lab.py'):
        (a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    manifest=json.loads((ROUND/'static-call-lab/manifest.json').read_text())
    observed=json.loads((ROOT/'analysis/raw-front-calibration-2026-11-09/native-calibration-watch/events.json').read_text())
    context=bytes.fromhex(next(e for e in observed if e['event']=='static_front_builder')['memory']['context']['bytes'])
    snaps=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    rigs={};writes={};services={};records={};report=dict(ok=False,scope=__doc__,rows=[],selector_domain=[],
        restoration=[],builder_rows=[],hardware_pixels_verified=False,firmware_hashes=dict(modified4=HASH,lab=manifest['sha256']))
    try:
        for name,path,digest in [('modified4',ROOT/M4,HASH),('lab',LAB,manifest['sha256'])]:
            blob=path.read_bytes();assert sha(blob)==digest
            r=Rig(blob,snaps);rigs[name]=r;writes[name]=[];services[name]=[]
            # ID35 fixture occupies <0xe0000; ID0b at +0xe0000 needs its full
            # 0x25fff8 bytes, including the native auxiliary records at +1f8000.
            for addr,size in ((0x20061000,0x1000),(RESOURCE,0x400000),(CAL+0x100000,0x68000)):
                r.uc.mem_map(addr,size);r.regions+=((addr,size),)
            def on_write(uc,kind,addr,size,value,data):
                writes[data].append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,value=value))
            for lo,hi in ((0x20061000,0x20061fff),(0x20068000,0x20069fff)):
                r.uc.hook_add(un.UC_HOOK_MEM_WRITE,on_write,name,begin=lo,end=hi)
            def mutex(uc,pc,size,data):
                services[data].append(dict(pc=hex(pc),object=hex(uc.reg_read(UC_ARM_REG_R0))))
                uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
            for pc in (0x10170df0,0x10170dea):r.uc.hook_add(un.UC_HOOK_CODE,mutex,name,begin=pc,end=pc)

        def reset(name,mode=1,temp=1,field=1,sub=None):
            r=rigs[name];u,p=r.uc,r.put;r.reset(dict(scalar=1008,bank=0,cached=0))
            u.mem_write(CTX,context);p(CTX,mode,'B');p(CTX+0x84,temp);p(CTX+0xdc,temp)
            if sub is not None:p(CTX+0x21,sub,'B')
            p(STATE+0x18,RESOURCE);p(STATE+0x1c,RESOURCE+0xe0000)
            # Exercise retained bytes/flags and all four different input fields.
            u.mem_write(GLOBAL,bytes((i*17+23)&255 for i in range(0x84)))
            for i in range(28):
                u.mem_write(CAL+0x540+i*80,bytes((field,(i+37)&255,(i+83)&255,(i+1)&1)))
                p(CAL+0xe50+i*80+0x32,1,'H')
            p(CTX+0x50,RESOURCE+0xe0060);p(CTX+0x54,5)
            u.mem_write(RESOURCE+0xe0060,struct.pack('<5H',0xe0c8,0x2064,0xe1f4,0x2320,0xffff))
            p(0x2006103c,0x5555);p(0x20061264,0x12345670);p(0x20061268,0x100)
            writes[name].clear();services[name].clear()

        def capture(name,call):
            r=rigs[name]
            return dict(call=call,mutex_calls=list(services[name]),writes=list(writes[name]),
                global_packet=r.mem(GLOBAL,0x180),context=r.mem(CTX,0xe4),registers=r.mem(0x20061000,0x1000),
                cpsr=hex(r.uc.reg_read(UC_ARM_REG_CPSR)),sp=hex(r.uc.reg_read(UC_ARM_REG_SP)))

        # Check the actual selector domain, including unsupported mode values.
        for name in rigs:
            reset(name);r=rigs[name];values=set()
            for mode,temp,sub in itertools.product(range(256),(0,1),(0,2)):
                r.put(CTX,mode,'B');r.put(CTX+0x84,temp);r.put(CTX+0x21,sub,'B')
                c=r.call(0x1011c64e,[CTX]);v=int(c['registers']['r0'],16)
                assert 0<=v<28 or v==65535;values.add(v)
            report['selector_domain'].append(dict(variant=name,calls=1024,values=sorted(values)))
            assert values==set(range(28))|{65535}
        assert report['selector_domain'][0]['values']==report['selector_domain'][1]['values']

        configs=[dict(mode=m,temp=t,field=f,kind=0,tagged=False)
                 for m,t,f in itertools.product(range(15),(0,1),(0,1,17,255))]
        configs += [dict(mode=m,temp=1,field=f,kind=0,tagged=True) for m,f in itertools.product(range(13),(0,1,17,255))]
        configs += [dict(mode=m,temp=t,field=17,kind=k,tagged=False)
                    for m,t,k in itertools.product(range(13),(0,1),(1,2))]
        if a.supplement:
            configs=[dict(mode=m,temp=t,field=f,kind=0,tagged=False,sub=2)
                for m,t,f in itertools.product((0,1),(0,1),(0,255))]
            configs += [dict(mode=m,temp=1,field=f,kind=0,tagged=True,sub=2)
                for m,f in itertools.product((0,1),(0,255))]
            configs += [dict(mode=m,temp=t,field=17,kind=k,tagged=False,sub=2)
                for m,t,k in itertools.product((0,1),(0,1),(1,2))]
        for n,cfg in enumerate(configs):
            report['current_case']=cfg;pair={}
            for name,r in rigs.items():
                reset(name,cfg['mode'],cfg['temp'],cfg['field'],cfg.get('sub'));cal_before=r.mem(CAL,0x168000)['sha256']
                if cfg['tagged']:
                    call=r.call(0x10179d54,until=0x10179d5c,regs={1:CTX,4:CTX,5:0x1234,7:0x9876})
                    assert call['registers']['r7']=='0x0' and r.uc.reg_read(UC_ARM_REG_SP)==STACK+0xf000
                else:call=r.call(0x1011c750,[cfg['kind'],CTX])
                if cfg['tagged']:assert int(call['registers']['r0'],16)==0
                assert r.mem(CAL,0x168000)['sha256']==cal_before
                pair[name]=capture(name,call)
            old,new=pair['modified4'],pair['lab']
            assert old['call']['registers']['r0']==new['call']['registers']['r0']
            assert all(old['call']['registers'][f'r{i}']==new['call']['registers'][f'r{i}'] for i in range(4,12))
            assert old['context']==new['context'] and old['sp']==new['sp'] and old['cpsr']==new['cpsr']
            assert old['mutex_calls']==new['mutex_calls']
            expected=cfg['tagged'] and bool(cfg['field'])
            changed=[(x,y) for x,y in zip(old['writes'],new['writes']) if (x['address'],x['size'],x['value'])!=(y['address'],y['size'],y['value'])]
            assert len(old['writes'])==len(new['writes'])
            assert len(changed)==int(expected),(cfg,changed)
            if expected:
                x,y=changed[0];assert x['address']==y['address']=='0x2006103c' and y['value']==0 and x['value']==cfg['field']
            # Exact byte comparison outside the gate word, for both native cache and MMIO.
            for key,off in (('global_packet',0x1c),('registers',0x3c)):
                x=bytearray.fromhex(old[key]['bytes']);y=bytearray.fromhex(new[key]['bytes'])
                if expected:x[off:off+4]=bytes(4)
                assert x==y,(cfg,key)
            report['rows'].append(dict(configuration=cfg,only_expected_gate_change=True,variants=pair))
            if (n+1)%50==0:print(f'Compared {n+1}/{len(configs)} native case pairs.',flush=True)

        # Keep state across ordinary -> static -> native temporary exit -> ordinary.
        for name,r in (rigs.items() if not a.supplement else []):
            reset(name,temp=0,field=17);sequence=[]
            for phase in ('ordinary-before','static-tagged','ordinary-after'):
                writes[name].clear();services[name].clear()
                if phase=='static-tagged':
                    # Execute the original flag-setting instructions, then the exact tagged call.
                    call=r.call(0x10179d48,until=0x10179d5c,regs={4:CTX})
                else:
                    if phase=='ordinary-after':
                        r.call(0x10179dcc,until=0x10179dd8,regs={1:1,4:CTX})
                        assert r.get(CTX+0x84)==r.get(CTX+0xdc)==0
                    call=r.call(0x1011c750,[0,CTX])
                assert r.get(GLOBAL+0x1c)==r.get(0x2006103c)==(0 if name=='lab' and phase=='static-tagged' else 17)
                phase_writes=list(writes[name]);writes[name].clear()
                descriptor=r.call(0x1011c3f4,[CTX])
                expect_skip=name=='lab' and phase=='static-tagged'
                assert len(writes[name])==(0 if expect_skip else 2)
                sequence.append(dict(phase=phase,gate=r.get(0x2006103c),global_packet=r.mem(GLOBAL,0x84),
                    context=r.mem(CTX,0xe4),call=call,control_writes=phase_writes,selector_call=descriptor,
                    selector_writes=list(writes[name]),descriptor=[hex(r.get(0x20061264)),hex(r.get(0x20061268))]))
            report['restoration'].append(dict(variant=name,sequence=sequence))

        # The full frontend builder after tagged kind0; nonzero 33x4 records.
        refs={}
        for name,r in (rigs.items() if not a.supplement else []):
            reset(name,temp=1,field=17);r.call(0x10179d48,until=0x10179d5c,regs={4:CTX})
            for category in (0,1):
                data=bytearray(struct.pack('<150H',*[1500+category*200+i for i in range(150)]))
                for off,val in ((0x18,1),(0x1a,2),(0x1c,3),(0x1e,4)):data[off]=val
                r.uc.mem_write(CAL+0x47180+category*300,bytes(data))
            cal=r.mem(CAL,0x168000)['sha256'];writes[name].clear();services[name].clear()
            build=r.call(0x1017d7b6,until=0x1011d548);upload=r.call(0x100bccd0,[PKT])
            assert len(writes[name])==507 and r.mem(CAL,0x168000)['sha256']==cal
            row=dict(variant=name,build=build,upload=upload,packet=r.mem(PKT,0x60),
                table=r.mem(0xc29a3be0,264),front_registers=r.mem(0x20068000,0x2000),writes=list(writes[name]))
            report['builder_rows'].append(row)
        if not a.supplement:
            x,y=report['builder_rows']
            for key in ('packet','table','front_registers','writes'):assert x[key]==y[key],key
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        report['failed_states']={n:dict(last_call=getattr(r,'last_call',None),last_blocks=r.blocks[-25:]) for n,r in rigs.items()}
        raise
    finally:
        report['sources_unchanged']=sha((ROOT/M4).read_bytes())==HASH and sha(LAB.read_bytes())==manifest['sha256']
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],pairs=len(report['rows']),selector_calls=sum(x['calls'] for x in report['selector_domain']),
            restoration=len(report['restoration']),builders=len(report['builder_rows']))))

if __name__=='__main__':main()

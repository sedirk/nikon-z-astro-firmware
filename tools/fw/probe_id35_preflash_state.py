"""Nonzero native static/live call sequences and invalid-selector exits.

This executes bounded original call-site snippets in retained private memory.
It does not establish the real camera's post-exposure scheduling. Only the
same two RTOS mutex service adapters are used; no pixels or DMA are supplied.
"""
from pathlib import Path
import argparse,gc,itertools,json,traceback
import unicorn as un
from unicorn.arm_const import *
from probe_raw_candidates import Rig,CAL,STACK
from review_id35_preflash import ROOT,SOURCES
from verify_id35_preflash_kit import DIGESTS,need,sha,read_module

CTX,STATE,GLOBAL,RESOURCE=0xc18fa844,0xc18fa954,0xc29a3230,0x56000000

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    report=dict(ok=False,scope=__doc__,sequences=[],invalid_selectors=[],physical_flash=False,real_pixels=False)
    events=json.loads((ROOT/'analysis/raw-front-calibration-2026-11-09/native-calibration-watch/events.json').read_text())
    context=bytes.fromhex(next(e for e in events if e['event']=='static_front_builder')['memory']['context']['bytes'])
    snaps=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    try:
        for variant in ('modified4','test'):
            r=Rig(read_module(SOURCES[variant],variant),snaps);u=r.uc;p=r.put;writes=[];services=[]
            for addr,size in ((0x20061000,0x1000),(RESOURCE,0x400000),(CAL+0x100000,0x68000)):
                u.mem_map(addr,size);r.regions+=((addr,size),)
            def on_write(uc,kind,addr,size,value,data):
                writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,value=value))
            u.hook_add(un.UC_HOOK_MEM_WRITE,on_write,begin=0x20061000,end=0x20061fff)
            def mutex(uc,pc,size,data):
                services.append(hex(pc));uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
            for pc in (0x10170df0,0x10170dea):u.hook_add(un.UC_HOOK_CODE,mutex,begin=pc,end=pc)
            def reset(mode,field):
                r.reset(dict(scalar=1008,bank=0,cached=0));u.mem_write(CTX,context)
                p(CTX,mode,'B');p(CTX+0x84,0);p(CTX+0xdc,0)
                p(STATE+0x18,RESOURCE);p(STATE+0x1c,RESOURCE+0xe0000)
                for i in range(28):u.mem_write(CAL+0x540+i*80,bytes((field,37+i,83+i,i&1)))
                p(0x2006103c,0x55);p(GLOBAL+0x1c,0x55)
                writes.clear();services.clear()
            for mode,field in itertools.product((0,1,6,12),(1,17,255)):
                reset(mode,field);cal=sha(bytes(u.mem_read(CAL,0x168000)));steps=[]
                for cycle in range(3):
                    for phase in ('live-config','static-kind0','static-kind1','exit-and-kind2','live-restore'):
                        writes.clear();services.clear()
                        if phase in ('live-config','live-restore'):
                            # Exact kind0 call snippet within original 1017c020 live frontend.
                            call=r.call(0x1017c1d6,until=0x1017c1de,regs={7:CTX,8:0x1234})
                            expected=field
                        elif phase=='static-kind0':
                            call=r.call(0x10179d48,until=0x10179d5c,regs={4:CTX});expected=0 if variant=='test' else field
                        elif phase=='static-kind1':
                            call=r.call(0x10179d5c,until=0x10179d64,regs={4:CTX});expected=0 if variant=='test' else field
                        else:
                            r.call(0x10179dcc,until=0x10179dd8,regs={1:1,4:CTX})
                            need(r.get(CTX+0x84)==r.get(CTX+0xdc)==0,'Temporary flags not cleared')
                            call=r.call(0x1011c750,[2,CTX]);expected=0 if variant=='test' else field
                        need(r.get(GLOBAL+0x1c)==r.get(0x2006103c)==expected,'Unexpected retained gate')
                        need(u.reg_read(UC_ARM_REG_SP)==STACK+0xf000,'Stack balance')
                        steps.append(dict(cycle=cycle,phase=phase,gate=expected,call=call,writes=list(writes),mutex_services=list(services),
                            temporary=r.get(CTX+0x84),global_packet=r.mem(GLOBAL,0x84),context=r.mem(CTX,0xe4)))
                need(sha(bytes(u.mem_read(CAL,0x168000)))==cal,'Calibration mutated')
                report['sequences'].append(dict(variant=variant,mode=mode,field=field,steps=steps,calibration_unchanged=True))
            for kind in (0,1,2,4):
                # kind4 is private only in the candidate; baseline correspondence is kind0.
                actual=0 if variant=='modified4' and kind==4 else kind
                reset(255,17);before=r.mem(GLOBAL,0x180);writes.clear()
                c=r.call(0x1011c750,[actual,CTX])
                need(int(c['registers']['r0'],16)==1 and not writes,'Invalid selector wrote MMIO or wrong error')
                need(r.mem(GLOBAL,0x180)==before,'Invalid selector changed global state')
                report['invalid_selectors'].append(dict(variant=variant,logical_kind=kind,actual_kind=actual,call=c,no_writes=True))
            del r;gc.collect()
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        if 'r' in locals():report['failed_call']=getattr(r,'last_call',None)
        raise
    finally:
        report['source_hashes_unchanged']=all(sha(SOURCES[n].read_bytes())==DIGESTS[n] for n in ('modified4','test'))
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        for name in (Path(__file__).name,'probe_raw_candidates.py','verify_id35_preflash_kit.py'):(a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
        print(json.dumps(dict(ok=report['ok'],sequences=len(report['sequences']),invalid_selectors=len(report['invalid_selectors']))))

if __name__=='__main__':main()

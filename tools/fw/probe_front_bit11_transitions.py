"""Retained-memory static/liveview input transitions using native context setters."""
import argparse, gc, json, struct, traceback
import unicorn as un
from probe_raw_candidates import Rig, ROOT, STACK, OWNER, MAINREQ, sha
from probe_front_control_sources import one, CTX, INPUT, OUTPUT, PACKET, REG
from probe_front_bit11_lab import ROUND, M3, LAB, data

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=__import__('pathlib').Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'probe-source.py').write_bytes(__import__('pathlib').Path(__file__).read_bytes())
    native=json.loads((ROUND/'native-trace-lab/events.json').read_text())
    live=data(next(e for e in native if e['event']=='liveview_context_input')['memory']['input'])
    observed=json.loads((ROOT/'analysis/raw-body-front-2026-11-08/native-body-front/events.json').read_text())
    still=data(next(e for e in observed if e['event']=='still_source_entry')['memory']['still_source_input'])
    snap=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    report=dict(ok=False,scope=__doc__,rows=[],liveview_equal=[],hardware_pixels_verified=False,
        limitations=['Native state-setter/selector/uploader calls in retained private memory; no full device mode switch or pixels.'])
    refs={}
    try:
        for variant,path in [('modified3',M3),('lab',LAB)]:
            rig=Rig(path.read_bytes(),snap);u,p,g=rig.uc,rig.put,rig.get
            u.hook_add(un.UC_HOOK_MEM_WRITE,rig.on_write,begin=0x20068000,end=0x20069fff)
            cfg=dict(config3d8=0,config3d9=0,long_flag=0,tv=2496,override=1,source_present=True)
            one(rig,cfg,still)
            for step,setting in enumerate((1,2,0,3,255,1)):
                u.mem_write(INPUT,live);p(INPUT+0x49,setting,'B')
                calls=[rig.call(0x1017c020,[INPUT]),rig.call(0x1011d540),
                       rig.call(0x1011db02,[CTX,1]),rig.call(0x100bccd0,[PACKET])]
                assert g(CTX+0x5d,'B')==setting
                assert bool(g(REG)&0x800)==(setting!=2)
                row=dict(variant=variant,step=step,phase='liveview',setting=setting,
                    context=rig.mem(CTX,0xe4),registers=rig.mem(REG,0x500),calls=calls)
                report['rows'].append(row)
                if variant=='modified3':refs[step]=row
                else:
                    for key in ('context','registers','calls'):assert refs[step][key]==row[key],(step,key)
                    report['liveview_equal'].append(dict(step=step,identical=True))
                # Return to static capture without clearing context/registers.
                u.mem_write(INPUT,still);p(INPUT+0x40,0,'B');p(OWNER+0x259,1,'B')
                u.mem_write(STACK+0xf000,bytes(u.mem_read(INPUT,0x50)))
                calls=[rig.call(0x100f6494,until=0x100f64bc,regs={7:MAINREQ})]
                u.mem_write(INPUT,bytes(u.mem_read(STACK+0xf000,0x50)))
                calls += [rig.call(0x10179962,[INPUT,OUTPUT]),rig.call(0x1011d540),
                          rig.call(0x1011db02,[CTX,1]),rig.call(0x100bccd0,[PACKET])]
                assert g(CTX+0x5d,'B')==(1 if variant=='modified3' else 2)
                assert bool(g(REG)&0x800)==(variant=='modified3')
                report['rows'].append(dict(variant=variant,step=step,phase='static',
                    context=rig.mem(CTX,0xe4),registers=rig.mem(REG,0x500),calls=calls))
            del rig;gc.collect()
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        if 'rig' in locals():report['last_call']=rig.last_call;report['last_blocks']=rig.blocks[-30:]
        raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],steps=len(report['rows']),liveview_pairs=len(report['liveview_equal']))))

if __name__=='__main__':main()

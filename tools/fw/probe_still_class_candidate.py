"""Compare original and independently patched modules along the real class chain.

All calibration and contextual values are explicit fixtures. Pixel buffers are
unmapped; original code produces parameters and MMIO writes, not NEF pixels.
The earlier full-size RAW candidate is not combined with this experiment.
"""
from pathlib import Path
import argparse, hashlib, json, struct, traceback, gc
import unicorn
from build_raw_candidates import apply_candidate
from probe_raw_candidates import Rig, ROOT, RAM, CAL, FRAME, OWNER, PROPS, CTX, A, DRIVER, MMIO, MAINREQ, MAINOUT

INFO=RAM+0x51000


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--module',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    for name in ('probe_still_class_candidate.py','probe_raw_candidates.py','build_raw_candidates.py'):
        (a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    source=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    catalog=json.loads((ROOT/'patches/z6-c380-still-class-experiment.json').read_text())
    candidate,manifest=apply_candidate(source,catalog,catalog['candidates'][0])
    assert a.module.read_bytes()==candidate
    snapshots=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    report=dict(ok=False,scope=__doc__,candidate=manifest,cases=[],comparisons=[],unicorn_version=unicorn.__version__)
    cfgs=[dict(cls=c,tv=t,bank=b,static=0,override=0) for c in (0,1,2) for t in (-446,13*192) for b in (0,1)]
    cfgs += [dict(cls=2,tv=-446,bank=b,static=s,override=o) for b in (0,1) for s,o in ((1,0),(0,1))]
    groups={}
    try:
        for variant,blob in (('original',source),('still-class-1aec-zero',candidate)):
            rig=Rig(blob,snapshots);u,put,get=rig.uc,rig.put,rig.get
            for i,cfg in enumerate(cfgs):
                rig.reset(dict(scalar=1008,bank=cfg['bank'],cached=False))
                put(FRAME+0x3a4,OWNER);put(OWNER+0x90,0,'B')
                u.mem_write(OWNER+0xec,struct.pack('<Ii',192,5*192))
                u.mem_write(OWNER+0xcc,struct.pack('<Ii',192,cfg['tv']))
                put(OWNER+0x1aed,cfg['static'],'B');put(OWNER+0x2810,cfg['override'],'B');put(OWNER+0x2811,0,'B')
                u.mem_write(INFO,bytes(0x260));put(INFO+0x24,200,'H');u.mem_write(0xc18b7ec0,bytes(8))
                u.mem_write(CAL+0xcdb10,bytes([cfg['cls']])*768)
                u.mem_write(CAL+0xbe01c,struct.pack('>h',200))
                put(OWNER+0x1aec,0xa5,'B');before=rig.mem(OWNER,0x3000)
                calls=[rig.call(0x10146efe,until=0x10146f28,regs={4:FRAME,7:INFO})]
                expected=cfg['cls'] if variant=='original' else 0
                assert get(OWNER+0x1aec,'B')==expected
                # The computed class remains in r0 for both binaries; only the
                # selected store changes its source from r0 to already-zero r7.
                assert int(calls[0]['registers']['r0'],16)==cfg['cls']
                owner=rig.mem(OWNER,0x3000)
                bb=bytes.fromhex(before['bytes']);aa=bytes.fromhex(owner['bytes'])
                assert [j for j in range(len(bb)) if bb[j]!=aa[j]]==[0x1aec]
                calls.append(rig.call(0x100c24f2,[MAINREQ,MAINOUT]))
                prop=get(MAINOUT);assert get(prop+0x4c,'B')==expected
                assert get(prop+0x4d,'B')==cfg['static'] and get(prop+0x4e,'B')==cfg['override']
                properties=rig.mem(prop,0xa0);u.mem_write(PROPS,bytes.fromhex(properties['bytes']))
                u.mem_write(CTX,bytes(0x100));put(CTX,PROPS);put(CTX+0xd0,A)
                calls.append(rig.call(0x10196a3c,[CTX]))
                expected584=int(cfg['override']==1 or expected!=0)+cfg['static']*6
                assert get(A+0x17a,'B')==expected584
                parameters=rig.mem(A,0x180)
                calls.append(rig.call(0x100d5b9c,[DRIVER,A+0x62]))
                mmio=MMIO+cfg['bank']*0x40000
                assert get(mmio+0x584)==expected584
                assert get(mmio+0x594)==6*int(expected==2)
                regs=rig.mem(mmio,0x800)
                row=dict(variant=variant,case=i,fixture=cfg,owner_after=owner,
                    properties=properties,parameters=parameters,registers=regs,calls=calls)
                report['cases'].append(row);groups[(variant,i)]=row
            del rig,u,put,get;gc.collect()
        for i,cfg in enumerate(cfgs):
            before=groups[('original',i)];after=groups[('still-class-1aec-zero',i)]
            changes={}
            for field,allowed in (('owner_after',{0x1aec}),('properties',{0x4c}),('parameters',{0xcc,0xcd,0x17a}),
                                  ('registers',set(range(0x584,0x588))|set(range(0x594,0x598)))):
                b=bytes.fromhex(before[field]['bytes']);c=bytes.fromhex(after[field]['bytes'])
                diff=[j for j in range(len(b)) if b[j]!=c[j]]
                assert set(diff)<=allowed,(cfg,field,diff)
                changes[field]=[hex(j) for j in diff]
            report['comparisons'].append(dict(case=i,fixture=cfg,changed_byte_offsets=changes))
        assert (ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()==source
        assert a.module.read_bytes()==candidate
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        if 'rig' in locals():report['failed_call']=getattr(rig,'last_call',None)
        raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],native_cases=len(report['cases']),original_candidate_pairs=len(report['comparisons']))))


if __name__=='__main__':main()

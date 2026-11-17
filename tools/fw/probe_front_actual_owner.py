"""Native config3d2 producer -> observed request copy -> static frontend.

Separate bounded calls replay actual object addresses observed in QEMU.
Nonzero policies are labelled artificial records, not physical calibration.
"""
from pathlib import Path
import argparse,gc,itertools,json,struct,traceback
import unicorn as un
from probe_raw_candidates import Rig,ROOT,STACK,CAL,MAINREQ,sha
from probe_front_control_sources import initialize,CTX,INPUT,OUTPUT,PACKET,CONTROL,REG
ROUND=ROOT/'analysis/raw-front-owner-2026-11-09'
SOURCE=0xc236f620;DEST=0xc236d378;CONFIG=0xc20aa7c8
VARIANTS={
 'modified3':ROOT/'outputs/Z6-C380-spatial-neutral-reviewed-2026-11-09/01_TEST_MODIFIED3/EG162080.BIN',
 'front-bit11-lab':ROOT/'analysis/raw-front-controls-2026-11-09/lab-module/modified3-front-bit11-off-lab.bi'}

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    events=json.loads((ROUND/'native-request-watch/events.json').read_text())
    copy=next(e for e in events if e['event']=='request_block_copy')
    assert copy['registers']['r0']==hex(DEST) and copy['registers']['r1']==hex(SOURCE)
    original_source=bytes.fromhex(copy['memory']['copy_source']['bytes'])
    observed_input=bytes.fromhex(next(e for e in events if e['event']=='static_input')['memory']['input']['bytes'])
    snap=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    report=dict(ok=False,scope=__doc__,rows=[],comparisons=[],qemu_source_sha256=sha((ROUND/'native-request-watch/events.json').read_bytes()),
        limitations=['Request copy is a native bounded segment after its original reset/RTOS preparation.',
          'Static argument extraction and full context/selector/upload execute, not sensor processing or NEF save.',
          'Only config3d2 and selected policy bit vary; adjacent config bytes use distinctive artificial values.'])
    base={}
    try:
        for variant,path in VARIANTS.items():
            blob=path.read_bytes();rig=Rig(blob,snap)
            rig.uc.hook_add(un.UC_HOOK_MEM_WRITE,rig.on_write,begin=0x20068000,end=0x20069fff)
            for override,policy in itertools.product((0,1,2,3,255),(0,1)):
                initialize(rig,observed_input);u,p,g=rig.uc,rig.put,rig.get
                u.mem_write(SOURCE,original_source)
                u.mem_write(DEST-16,b'\x35'*(0x260+32))
                for offset,val in ((0x3dc,5),(0x3df,6),(0x11b,7),(0x29f,8),(0x3d2,override)):p(CONFIG+offset,val,'B')
                cfg_before=rig.mem(CONFIG,0x500)
                calls=[rig.call(0x1013f0b2,[SOURCE+0x255])]
                assert bytes(u.mem_read(SOURCE+0x255,5))==bytes((5,6,7,8,override))
                source=rig.mem(SOURCE,0x260)
                assert all(x==y for i,(x,y) in enumerate(zip(original_source,bytes.fromhex(source['bytes']))) if i not in range(0x255,0x25a))
                calls.append(rig.call(0x101e30ac,until=0x101e30ba,regs={5:SOURCE}))
                assert bytes(u.mem_read(DEST,0x260))==bytes.fromhex(source['bytes'])
                assert bytes(u.mem_read(DEST-16,16))==bytes(u.mem_read(DEST+0x260,16))==b'\x35'*16
                p(MAINREQ,DEST);u.mem_write(STACK+0xf000,observed_input)
                calls.append(rig.call(0x100f6494,until=0x100f64bc,regs={7:MAINREQ}))
                inp=bytes(u.mem_read(STACK+0xf000,0x50));u.mem_write(INPUT,inp)
                eff=2 if variant=='front-bit11-lab' else override
                assert inp[0x45]==eff
                calls.append(rig.call(0x10179962,[INPUT,OUTPUT]));assert g(CTX+0x5d,'B')==eff
                for idx in range(256):p(CAL+0x55c0+idx*128+4,policy,'H')
                calls.append(rig.call(0x1011d540));calls.append(rig.call(0x1011db02,[CTX,1]))
                expected=0 if eff==2 else 1 if eff==1 else policy
                assert g(CONTROL+8)==expected
                calls.append(rig.call(0x100bccd0,[PACKET]))
                assert (g(REG)>>11)&1==expected
                assert cfg_before==rig.mem(CONFIG,0x500)
                assert source==rig.mem(SOURCE,0x260)
                row=dict(variant=variant,override=override,policy=policy,effective=eff,bit11=expected,word=hex(g(REG)),
                    source=source,destination=rig.mem(DEST,0x260),input=inp.hex(),context=rig.mem(CTX,0xe4),
                    registers=rig.mem(REG,0x500),config_unchanged=True,source_unchanged=True,copy_guards_preserved=True,calls=calls)
                report['rows'].append(row)
                if variant=='modified3':base[override,policy]=row
                else:
                    ref=base[override,policy]
                    assert row['source']==ref['source'] and row['destination']==ref['destination']
                    assert int(row['word'],16)==int(ref['word'],16)&~0x800
                    for key,allowed in (('input',{0x45}),('context',{0x5d}),('registers',{1})):
                        x,y=ref[key],row[key]
                        x=bytes.fromhex(x if isinstance(x,str) else x['bytes']);y=bytes.fromhex(y if isinstance(y,str) else y['bytes'])
                        assert {i for i,(u,v) in enumerate(zip(x,y)) if u!=v}<=allowed
                    report['comparisons'].append(dict(override=override,policy=policy,only_target_control_changed=True))
            del rig;gc.collect()
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc();raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        for name in (Path(__file__).name,'probe_front_control_sources.py','probe_raw_candidates.py'):(a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
        print(json.dumps(dict(ok=report['ok'],rows=len(report['rows']),pairs=len(report['comparisons']))))
if __name__=='__main__':main()

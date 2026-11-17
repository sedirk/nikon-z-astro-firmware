"""Compare one static front-control instruction against modified3, offline only."""
from pathlib import Path
import argparse, binascii, gc, json, struct, traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_SP
from probe_raw_candidates import Rig, ROOT, RAM, STACK, CAL, OWNER, MAINREQ, sha
from probe_front_control_sources import one, CTX, INPUT, OUTPUT, PACKET, CONTROL, REG

ROUND=ROOT/'analysis/raw-front-controls-2026-11-09'
M3=ROOT/'outputs/Z6-C380-spatial-neutral-reviewed-2026-11-09/01_TEST_MODIFIED3/EG162080.BIN'
LAB=ROUND/'lab-module/modified3-front-bit11-off-lab.bi'

def changes(a,b):return [i for i,(x,y) in enumerate(zip(a,b)) if x!=y]
def data(m):return bytes.fromhex(m['bytes'])

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    for name in ('probe_front_bit11_lab.py','probe_front_control_sources.py','probe_raw_candidates.py'):
        (a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    reference=json.loads((ROUND/'source-probe/result.json').read_text())
    cfgs=[r['configuration'] for r in reference['rows'] if r['variant']=='modified3']
    observed=ROOT/'analysis/raw-body-front-2026-11-08/native-body-front/events.json'
    events=json.loads(observed.read_text())
    inp=bytes.fromhex(next(e for e in events if e['event']=='still_source_entry')['memory']['still_source_input']['bytes'])
    native=json.loads((ROUND/'native-trace-modified3/events.json').read_text())
    context=data(next(e for e in native if e['event']=='static_front_builder')['memory']['context'])
    snap=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    report=dict(ok=False,scope=__doc__,rows=[],comparisons=[],abi=[],full_builder=[],
        hardware_pixels_verified=False,installation_reviewed=False)
    baseline={};fullbase={}
    try:
        old,new=M3.read_bytes(),LAB.read_bytes()
        assert sha(old)=='a8ec90a9b55b2eefcd46e13b0f6acd0b7aa1bc4d9d127d701dee89154b8b04bd'
        assert binascii.crc_hqx(new,0)==0 and len(old)==len(new)
        changed=changes(old,new)
        assert set(changed)<=set(range(0x100f64b4-0x10020000,0x100f64b8-0x10020000))|{len(old)-2,len(old)-1}
        report['bytes']=dict(reference_sha256=sha(old),lab_sha256=sha(new),
            changed_vs_modified3=[hex(x) for x in changed],inherited_edits_unchanged=True)
        for variant,blob in [('modified3',old),('bit11-lab',new)]:
            rig=Rig(blob,snap)
            rig.uc.mem_map(CAL+0x100000,0x68000)
            rig.regions += ((CAL+0x100000,0x68000),)
            rig.uc.hook_add(un.UC_HOOK_MEM_WRITE,rig.on_write,begin=0x20068000,end=0x20069fff)
            for i,cfg in enumerate(cfgs):
                report['current_case']=[variant,i]
                row=one(rig,cfg,inp);row['variant']=variant
                report['rows'].append(row)
                if variant=='modified3':baseline[i]=row
                else:
                    ref=baseline[i]
                    assert data(row['input'])[0x45]==2 and data(row['context'])[0x5d]==2
                    assert set(changes(data(ref['input']),data(row['input'])))<={0x45}
                    assert set(changes(data(ref['context']),data(row['context'])))<={0x5d}
                    for key in ('owner_control_bytes','selected','ancillary'):assert ref[key]==row[key],(i,key)
                    assert int(row['word'],16)==int(ref['word'],16)&~0x800
                    assert set(changes(data(ref['registers']),data(row['registers'])))<={1}
                    report['comparisons'].append(dict(case=i,only_bit11_changed=True,source_objects_preserved=True))
            # Complete static frontend construction to its dispatch entry, then
            # original packet uploader without reset/start/completion hardware.
            for temp in (0,1):
                cfg=dict(config3d8=0,config3d9=0,long_flag=0,tv=2496,override=1,source_present=True)
                row=one(rig,cfg,inp)
                rig.uc.mem_write(CTX+0x94,context[0x94:])
                rig.put(CTX+0x84,temp)
                cal_before=rig.mem(CAL,0x168000)['sha256']
                source_before=rig.mem(OWNER,0x3000)
                build=rig.call(0x1017d7b6,until=0x1011d548)
                state=rig.mem(CTX,0xe4)
                packet=rig.mem(PACKET,0x60)
                rig.uc.mem_write(REG,b'\x7c'*0x500)
                upload=rig.call(0x100bccd0,[PACKET])
                regs=rig.mem(REG,0x500)
                assert rig.mem(CAL,0x168000)['sha256']==cal_before
                assert rig.mem(OWNER,0x3000)==source_before
                f=dict(variant=variant,temp=temp,context=state,packet=packet,registers=regs,
                    cal_sha256=cal_before,calls=[build,upload],calibration_unchanged=True,owner_unchanged=True)
                report['full_builder'].append(f)
                if variant=='modified3':fullbase[temp]=f
                else:
                    ref=fullbase[temp]
                    assert packet==ref['packet']
                    assert set(changes(data(ref['registers']),data(regs)))=={1}
                    assert rig.get(REG)==struct.unpack_from('<I',data(ref['registers']))[0]&~0x800
                    assert set(changes(data(ref['context']),data(state)))=={0x5d}
            # New MOV.W has no S suffix. Validate unchanged NZCV and every
            # non-result register/stack byte across all flag combinations.
            for flags in range(16):
                for value in (0,1,2,255):
                    rig.put(OWNER+0x259,value,'B');rig.put(MAINREQ,OWNER)
                    rig.uc.mem_write(STACK+0xf000,b'\x53'*0x50)
                    regs={i:0x40404040+i*0x1010101 for i in range(1,13)}
                    regs[7]=MAINREQ
                    rig.uc.reg_write(UC_ARM_REG_CPSR,(rig.uc.reg_read(UC_ARM_REG_CPSR)&0x0fffffff)|(flags<<28))
                    call=rig.call(0x100f64b4,[OWNER],until=0x100f64bc,regs=regs)
                    expected=2 if variant=='bit11-lab' else value
                    assert int(call['registers']['r0'],16)==expected
                    assert rig.get(STACK+0xf045,'B')==expected
                    assert set(changes(b'\x53'*0x50,bytes(rig.uc.mem_read(STACK+0xf000,0x50))))=={0x45}
                    assert rig.uc.reg_read(UC_ARM_REG_CPSR)>>28==flags
                    assert rig.uc.reg_read(UC_ARM_REG_SP)==STACK+0xf000
                    for reg,val in regs.items():assert int(call['registers'][f'r{reg}'],16)==val
                    report['abi'].append(dict(variant=variant,flags=flags,source_value=value,passed=True))
            del rig;gc.collect()
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        if 'rig' in locals():report['last_call']=rig.last_call;report['last_blocks']=rig.blocks[-25:]
        raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],pairs=len(report['comparisons']),abi=len(report['abi']),full_builder=len(report['full_builder']))))

if __name__=='__main__':main()

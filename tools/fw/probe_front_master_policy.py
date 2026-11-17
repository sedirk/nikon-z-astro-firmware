"""Run original front policy builder/dispatcher with labelled private records.

Maps numeric record fields and context overrides to 0x20068500. This does not
name the ISP stages, emulate image processing or modify body calibration.
"""
from pathlib import Path
import argparse, gc, itertools, json, struct, traceback
import unicorn as un
from probe_raw_candidates import Rig, ROOT, RAM, sha

RECORD, CONTEXT = RAM+0x38000, RAM+0x39000
PACKET, CONTROLS, DATA = 0xc29a34c0, 0xc29a3520, 0xc29a3754
REGISTER = 0x20068500
ROUND = ROOT/'analysis/raw-spatial-neutral-2026-11-09'

def case(rig, cfg):
    rig.reset(dict(scalar=1008,bank=0,cached=0))
    u,p,g=rig.uc,rig.put,rig.get
    record=bytearray(struct.pack('<64H',*range(64)))
    record[:28]=struct.pack('<14H',*cfg['flags'])
    u.mem_write(RECORD,bytes(record))
    p(CONTEXT+0x38,cfg['ctx38']);p(CONTEXT+0x5d,cfg['ctx5d'],'B');p(CONTEXT+0x80,cfg['ctx80'])
    context=bytes(u.mem_read(CONTEXT,0x100))
    u.mem_write(DATA,b'\x69'*0x100)
    u.mem_write(CONTROLS,b'\x5a'*0xd0)
    calls=[rig.call(0x1011d540),rig.call(0x1011d7a4,[RECORD,0,CONTEXT,cfg['extra']])]
    expected=list(cfg['flags'])
    if cfg['ctx38']:
        expected=[1,0,0,0,0,0,0,0,0,0,0,1,1,0]
    else:
        if cfg['ctx5d']==1:expected[2]=1
        if cfg['ctx5d']==2:expected[2]=0
        if not cfg['ctx80']:expected[10]=0
    actual=list(struct.unpack('<14I',u.mem_read(CONTROLS,56)))
    assert actual==expected,(cfg,actual,expected)
    assert g(PACKET)==CONTROLS and g(PACKET+0x34)==0
    expected_word=sum(v<<(13-i) for i,v in enumerate(expected))
    p(REGISTER,0xdeadbeef)
    calls.append(rig.call(0x100bccd0,[PACKET]))
    writes=list(calls[-1]['writes'])
    assert g(REGISTER)==expected_word
    assert sum(int(w['address'],16)==REGISTER for w in writes)==1
    assert bytes(u.mem_read(RECORD,128))==record
    assert bytes(u.mem_read(CONTEXT,0x100))==context
    assert bytes(u.mem_read(DATA,0x100))==b'\x69'*0x100
    retained=rig.mem(REGISTER,4)
    calls.append(rig.call(0x1011d540))
    assert bytes(u.mem_read(PACKET,0x60))==bytes(0x60)
    assert list(struct.unpack('<14I',u.mem_read(CONTROLS,56)))==actual
    calls.append(rig.call(0x100bccd0,[PACKET]))
    assert not calls[-1]['writes'] and rig.mem(REGISTER,4)==retained
    return dict(fixture=cfg,controls=actual,word=hex(expected_word),
        packet_clear_retains_register=True,fixed_204_data_untouched=True,
        ancillary=rig.mem(0xc29a3594,0x80),calls=calls)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    for name in ('probe_front_master_policy.py','probe_raw_candidates.py'):
        (a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    snap=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    cfgs=[]
    for bit in range(-2,14):
        flags=[int(bit==-2 or i==bit) for i in range(14)]
        cfgs.append(dict(name=f'onehot-{bit}',flags=flags,ctx38=0,ctx5d=0,ctx80=1,extra=0))
    for ones,c38,c5d,c80,extra in itertools.product((0,1),(0,1),(0,1,2,3),(0,1),(0,1)):
        cfgs.append(dict(name=f'override-{ones}-{c38}-{c5d}-{c80}-{extra}',flags=[ones]*14,
                         ctx38=c38,ctx5d=c5d,ctx80=c80,extra=extra))
    report=dict(ok=False,scope=__doc__,rows=[],comparisons=[],hardware_pixels_verified=False)
    results={}
    try:
        variants=[('modified2',ROOT/'outputs/Z6-C380-vignette-neutral-reviewed-2026-11-09/01_TEST_MODIFIED2/EG162080.BIN'),
                  ('spatial-neutral-lab',ROUND/'lab-module/neighborhood-vignette-spatial-neutral-lab.bi')]
        for variant,path in variants:
            blob=path.read_bytes();rig=Rig(blob,snap)
            rig.uc.hook_add(un.UC_HOOK_MEM_WRITE,rig.on_write,begin=0x20068000,end=0x20069fff)
            for i,cfg in enumerate(cfgs):
                report['current_case']=[variant,i,cfg]
                row=case(rig,cfg);row.update(variant=variant,module_sha256=sha(blob))
                report['rows'].append(row);results[variant,i]=row
            del rig;gc.collect()
        for i in range(len(cfgs)):
            old,new=results['modified2',i],results['spatial-neutral-lab',i]
            for key in ('controls','word','ancillary','calls'):assert old[key]==new[key],(i,key)
            report['comparisons'].append(dict(case=i,identical=True))
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        if 'rig' in locals():report['last_call']=rig.last_call;report['last_blocks']=rig.blocks[-30:]
        raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],rows=len(report['rows']),pairs=len(report['comparisons']))))

if __name__=='__main__':main()

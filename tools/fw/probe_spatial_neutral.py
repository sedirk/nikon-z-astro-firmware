"""Execute shared 17-table neutral LAB with real coefficient constraints.

Native firmware instructions, private input/context/calibration fixtures and
configuration-only MMIO. Includes static precompute -> copied-state -> final
upload, not an uninterrupted physical exposure or an ISP pixel model.
"""
from pathlib import Path
import argparse, gc, itertools, json, struct, traceback
import unicorn as un
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_SP, UC_ARM_REG_PC
from build_raw_candidates import apply_candidate
from probe_flat_spatial_controls import run as spatial_run
from probe_raw_candidates import (Rig, ROOT, BASE, RAM, STACK, OWNER, FRAME, A,
    DRIVER, MMIO, MAINREQ, VECTOR, SERIAL, SPATIAL, FLAGS, TABLES, STAGE, REQ,
    PACKET, STORAGE, INPUT, OUTPUT, ENCODED, CACHE, sha)
from probe_still_vignette_neutral import (seed, serialize, VREQ, VOUT, CURVE,
    MIXED, TCTX, HISTORY, AUX, GRID)

P_REQ,P_OUT=RAM+0x36000,RAM+0x36100
P_CONTEXT=0xc2753ea4
M_CONTEXT=0xc27631c0

def inputs(rig,cfg,coefs,spatial):
    seed(rig,dict(cached=cfg['cached'],strength=2,owner_neutral=0,bank=cfg['bank']),coefs,spatial)
    u,p=rig.uc,rig.put
    # Explicit precomputed scalar/cache fixtures. They are not a body dump.
    p(OWNER+0x308+0x26,256,'H')
    u.mem_write(OWNER+0x308+0x28,struct.pack('<9H',*([256]*9)))
    u.mem_write(OWNER+0x308+0x3a,struct.pack('<4H',*([512]*4)))
    u.mem_write(OWNER+0x308+0x42,struct.pack('<5HB',300,300,300,300,32000,0))
    u.mem_write(OWNER+0x378,struct.pack('<4B6i',*cfg.get('cache_flags',[0,1]),0,0,*spatial))
    p(OWNER+0x227c+0x5a,cfg.get('bit2',0),'B')
    p(P_REQ,FRAME);p(P_REQ+4,CACHE)
    if cfg['cached']:
        p(P_REQ+8,OWNER+0x308);p(P_REQ+12,OWNER+0x342);p(P_REQ+16,OWNER+0x34a)
    u.mem_write(P_REQ+0x14,struct.pack('<2H',6064,4040))
    p(P_REQ+0x18,1);p(P_REQ+0x1c,0)
    p(P_REQ+0x20,cfg.get('mode',0),'B');p(P_REQ+0x21,cfg['cached'],'B')
    u.mem_write(P_OUT,struct.pack('<4I',STAGE+0x3e8,STAGE+0x468,OWNER+0x85c,0))
    for ptr,n in ((STAGE+0x3e8,0x34),(STAGE+0x468,0x6c),(SPATIAL,68)):
        u.mem_write(ptr,b'\x6b'*n)
    return u,p,rig.get

def static_chain(rig,cfg,coefs,spatial,neutral):
    u,p,g=inputs(rig,cfg,coefs,spatial)
    calls=[rig.call(0x100c24d4,[P_REQ,P_OUT])]
    pre=bytes(u.mem_read(STAGE+0x468,0x6c));scalar=bytes(u.mem_read(STAGE+0x3e8,0x34))
    assert '0x10197500' in calls[-1]['blocks']
    if neutral:
        assert pre[0x1d]==0 and pre[0x26:0x6a]==bytes(68)
        assert '0x101973d4' in calls[-1]['blocks']
    # This is the actual static caller contract: +24 is 1 and +18 points at
    # stage+468. Do not replace it with the old helper's +24=0 shortcut.
    for off,val in ((4,CACHE),(8,OWNER+0x308 if cfg['cached'] else 0),
                    (12,OWNER+0x342 if cfg['cached'] else 0),(16,OWNER+0x34a if cfg['cached'] else 0),
                    (20,STAGE+0x3e8),(24,STAGE+0x468),(36,1),(40,0)):
        p(MAINREQ+off,val)
    p(MAINREQ+0x2e,cfg['cached'],'B')
    calls.append(rig.call(0x100c2824,[MAINREQ,VECTOR]))
    assert '0x1017206e' in calls[-1]['blocks']
    assert '0x10197500' not in calls[-1]['blocks']
    assert bytes(u.mem_read(M_CONTEXT+0x58,0x6c))==pre
    mainprops=rig.mem(0xc2763120,0xa0)
    preprops=rig.mem(0xc18d28c8,0x68)
    table=bytes(u.mem_read(SPATIAL,68))
    if neutral:assert table==bytes(68) and g(A+0x180,'B')==0
    # Preserve the already delivered vignette neutralization in a full chain.
    if not cfg['cached']:p(OWNER+0x227c,0,'B')
    calls.append(rig.call(0x100c29c6,[VREQ,VOUT]))
    assert bytes(u.mem_read(CURVE,514))==struct.pack('<257H',*([1024]*257))
    p(FLAGS+0x2c,cfg['slot'],'B')
    for off,val in ((0,FLAGS),(4,SPATIAL),(8,0),(12,MIXED),(20,TCTX)):p(VREQ+off,val)
    p(VREQ+16,1,'B');p(VREQ+17,0,'B')
    p(AUX,TABLES);p(AUX+4,AUX+0x100);p(AUX+8,AUX+0x200)
    calls.append(rig.call(0x10171dbc,[VREQ,HISTORY,AUX]))
    calls.append(rig.call(0x100ae33e,[STAGE],until=0x100b4c78))
    calls.append(rig.call(0x100b5716,[REQ,PACKET,STORAGE]))
    bank=MMIO+cfg['bank']*0x40000
    u.mem_write(bank+0x1200,b'\x5a'*72)
    calls.append(rig.call(0x100d5c86,[DRIVER,PACKET,0,0]))
    registers={hex(int(w['address'],16)-bank):w['value'] for w in calls[-1]['writes']}
    assert all(hex(x) in registers for x in range(0x1200,0x1248,4))
    if neutral:assert bytes(u.mem_read(bank+0x1200,72))==bytes(72)
    assert g(bank+0x584)==g(bank+0x594)==0
    assert g(bank+0x310)==0x60000000 and g(bank+0x3ec)==0x62000000 and g(bank+0x580)==1
    selected=0x2a94 if cfg['slot'] else 0x2890
    assert bytes(u.mem_read(bank+selected,516))==struct.pack('<257H',*([1024]*257))+b'\0\0'
    calls.append(rig.call(0x10305628))
    tag6,c=serialize(rig,6);calls.append(c)
    tag7,c=serialize(rig,7);calls.append(c)
    if neutral:assert tag7[0x5a]==0 and tag7[4]==int(g(A+0x182,'B')==0)
    # Separate bounded handoff/encoder entry: no hardware completion asserted.
    calls.append(rig.call(0x100ae41e,until=0x100ae438,regs={4:FRAME,5:REQ}))
    assert g(FRAME+0x1f8)==OUTPUT
    calls.append(rig.call(0x100af648,[STAGE],until=0x100a323e))
    assert calls[-1]['registers']['r0']==hex(OUTPUT+0x24)
    return dict(fixture=cfg,precomputed_hex=pre.hex(),scalar_hex=scalar.hex(),
        pre_properties=preprops,main_properties=mainprops,table_hex=table.hex(),
        parameters=rig.mem(A,0x500),registers=registers,tag6_hex=tag6.hex(),tag7_hex=tag7.hex(),
        encoder_descriptor=hex(OUTPUT+0x24),calls=calls)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--mode',choices=['chains','controls'],required=True)
    ap.add_argument('--fields',type=Path,default=ROOT/'analysis/modified2-flat-2026-11-09/correction-fields/result.json')
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    for name in ('probe_spatial_neutral.py','probe_flat_spatial_controls.py','probe_still_vignette_neutral.py',
                 'probe_still_neighborhood_off.py','probe_raw_candidates.py','build_raw_candidates.py'):
        (a.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    stock=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    cat=json.loads((ROOT/'patches/z6-c380-spatial-neutral-lab.json').read_text())
    new,manifest=apply_candidate(stock,cat,cat['candidates'][0])
    saved=ROOT/'analysis/raw-spatial-neutral-2026-11-09/lab-module/neighborhood-vignette-spatial-neutral-lab.bi'
    assert saved.read_bytes()==new
    prior=(ROOT/'outputs/Z6-C380-vignette-neutral-reviewed-2026-11-09/01_TEST_MODIFIED2/EG162080.BIN').read_bytes()
    assert sha(prior)=='6790186e7e088ae7c504677be052aecdbf3868616207bfda5606b36d37149038'
    fields=json.loads(a.fields.read_text())['files'][0]
    coefs=fields['vignette']['coefficients'];spatial=fields['two_table_spatial']['coefficients']
    tag=bytes.fromhex(fields['nefinfo']['entries']['0x7']['bytes'])
    snap=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    report=dict(ok=False,scope=__doc__,mode=a.mode,candidate=manifest,rows=[],comparisons=[],
        field_input=str(a.fields.resolve()),field_input_sha256=sha(a.fields.read_bytes()),
        input_vignette_coefficients=coefs,input_spatial_coefficients=spatial)
    results={}
    try:
        if a.mode=='chains':
            cfgs=[dict(cached=c,bank=b,slot=s,cache_flags=f,mode=0) for c,b,s,f in
                  itertools.product((0,1),(0,1),(0,1),([0,1],[1,1]))]
        else:
            cfgs=[dict(name=f'control-{i}',bank=bank,cached=bool(c),mode=mode,source=src,
                       bit2=bit2,cache_flags=flags,xy=xy)
                  for i,(bank,c,mode,src,bit2,flags,xy) in enumerate(itertools.product(
                      (0,1),(0,1),(0,7,18,255),(0,1),(0,4),([0,1],[1,1],[0,0],[1,0]),([19,-23],)))]
        for variant,blob in (('modified2',prior),('spatial-neutral-lab',new)):
            rig=Rig(blob,snap)
            for i,cfg in enumerate(cfgs):
                report['current_case']=[variant,i,cfg]
                if a.mode=='chains':row=static_chain(rig,cfg,coefs,spatial,variant!='modified2')
                else:
                    row=spatial_run(rig,cfg,spatial,tag)
                    if variant!='modified2':
                        assert row['table']==[0]*34 and row['parameter_flags'][1]==0
                        assert row['generated_coefficients'][1:3]==[0,0] and row['generated_coefficients'][4:]==[0,0]
                        assert row['tag_flags']==[int(row['parameter_flags'][0]==0),0]
                row['variant']=variant;report['rows'].append(row);results[variant,i]=row
            del rig;gc.collect()
        for i,cfg in enumerate(cfgs):
            old,newrow=results['modified2',i],results['spatial-neutral-lab',i]
            changed={k:[old['registers'].get(k),newrow['registers'].get(k)] for k in set(old['registers'])|set(newrow['registers'])
                     if old['registers'].get(k)!=newrow['registers'].get(k)}
            allowed={0x700,0x704,0x730,*range(0x1200,0x1248,4)}
            assert all(int(k,16) in allowed for k in changed),changed
            assert old['registers'].get('0x708')==newrow['registers'].get('0x708')
            if a.mode=='chains':
                for key in ('scalar_hex','pre_properties','main_properties','tag6_hex','encoder_descriptor'):
                    assert old[key]==newrow[key],(i,key)
            report['comparisons'].append(dict(case=i,fixture=cfg,changed_registers=changed))
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        if 'rig' in locals():report['failed_call']=getattr(rig,'last_call',None);report['last_blocks']=rig.blocks[-30:]
        raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],rows=len(report['rows']),pairs=len(report['comparisons']))))

if __name__=='__main__':main()

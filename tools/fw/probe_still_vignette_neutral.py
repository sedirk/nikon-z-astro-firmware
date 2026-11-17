"""Compare installed modified1 with a static-only native vignette-neutral lab copy.

Real flat coefficient values are embedded in explicitly reconstructed inputs.
Native static wrappers, curve generation, packing, register configuration and
metadata callbacks run. There is no sensor/ISP/encoder model or hardware NEF.
"""
from pathlib import Path
import argparse, binascii, gc, itertools, json, struct, traceback
from unicorn.arm_const import UC_ARM_REG_SP
from build_raw_candidates import apply_candidate
from probe_raw_candidates import (Rig,ROOT,BASE,RAM,STACK,OWNER,FRAME,A,DRIVER,MMIO,
    MAINREQ,VECTOR,SERIAL,SPATIAL,FLAGS,TABLES,STAGE,REQ,PACKET,STORAGE,INPUT,OUTPUT,
    TAG,META,PAYLOAD,PACKAGE,sha)
from probe_still_neighborhood_off import setup

VREQ,VOUT,CURVE,MIXED,DEBUG,GRID,TCTX=[RAM+x for x in (0x30000,0x30100,0x32000,0x32400,0x32a00,0x34000,0x35000)]
OLD,HISTORY,AUX=RAM+0x50000,RAM+0x51000,RAM+0x52000


def seed(rig,cfg,coefs,spatial):
    setup(rig,dict(bank=cfg.get('bank',0)))
    p,u=rig.put,rig.uc
    p(OWNER+0x25e,cfg['strength'],'B');p(OWNER+0x25f,cfg['owner_neutral'],'B')
    p(OWNER+0x170,0,'B')
    p(OWNER+0x227c,1,'B')
    u.mem_write(OWNER+0x227c+0x49,bytes(range(1,9)))
    p(OWNER+0x227c+0x54,GRID);p(OWNER+0x227c+0x5c,16,'H')
    grid=[0]*864
    for knot,k in itertools.product(range(8),range(6)):grid[knot*108+k*18]=spatial[k]
    u.mem_write(GRID,struct.pack('<864i',*grid))
    # Cached polynomial state. Scale/cutoff are artificial; actual metadata
    # does not uniquely recover these pre-export fields or the real curves.
    cache=bytearray(32)
    cache[0]=cfg.get('cache_neutral',0);cache[1]=1;cache[2]=16;cache[3]=255
    struct.pack_into('<H',cache,4,2048)
    struct.pack_into('<4i',cache,8,*coefs)
    u.mem_write(OWNER+0x358,bytes(cache))
    p(VREQ,FRAME);p(VREQ+4,cfg['cached'],'B')
    for off,val in ((0,CURVE),(4,MIXED),(8,OWNER+0x358),(12,DEBUG),(16,OWNER+0x1014)):
        p(VOUT+off,val)
    for address in (CURVE,MIXED):u.mem_write(address,b'\xa5'*(514+32))


def serialize(rig,tagid):
    descriptors={6:(0x11536d98,0x10289942,116),7:(0x11536da8,0x102899a0,104)}
    descriptor,callback,n=descriptors[tagid]
    rig.put(PACKAGE+0x34,OWNER)
    rig.uc.mem_write(TAG,rig.blob[descriptor-BASE:descriptor-BASE+12])
    rig.put(META+12,TAG);rig.put(META+16,PAYLOAD)
    call=rig.call(callback,[TAG,PACKAGE+0x30,META])
    payload=bytes(rig.uc.mem_read(PAYLOAD,n))
    assert struct.unpack_from('<H',payload,n-2)[0]==binascii.crc_hqx(payload[:-2],0xffff)
    return payload,call


def run_chain(rig,cfg,coefs,spatial,patched):
    seed(rig,cfg,coefs,spatial);u,p,g=rig.uc,rig.put,rig.get
    calls=[rig.call(0x100c2824,[MAINREQ,VECTOR])]
    mainprops=rig.mem(0xc2763120,0xa0)
    assert list(struct.unpack('<6i',u.mem_read(OWNER+0xffc,24)))==spatial
    before7=rig.mem(OWNER+0xff8,28)
    # For uncached curve cases the lens input type is a stated absent-source
    # counterfactual, AFTER the independent main-spatial wrapper has run.
    # It prevents claiming a reconstruction of undocumented lens inputs.
    if not cfg['cached']:p(OWNER+0x227c,0,'B')
    before_curve_owner=bytes(u.mem_read(OWNER,0x3000))
    calls.append(rig.call(0x100c29c6,[VREQ,VOUT]))
    curve=list(struct.unpack('<257H',u.mem_read(CURVE,514)))
    mixed=list(struct.unpack('<257H',u.mem_read(MIXED,514)))
    assert rig.mem(OWNER+0xff8,28)==before7
    for ptr in (CURVE,MIXED):assert bytes(u.mem_read(ptr+514,32))==b'\xa5'*32
    owner_after=bytes(u.mem_read(OWNER,0x3000))
    owner_changes=[i for i,(x,y) in enumerate(zip(before_curve_owner,owner_after)) if x!=y]
    assert all(0x358<=i<0x378 or 0x1014<=i<0x1026 for i in owner_changes),owner_changes
    if patched:
        assert curve==mixed==[1024]*257
        assert bytes(u.mem_read(OWNER+0x1014,18))==bytes(18)
        assert '0x101a1240' in calls[-1]['blocks']
    # Full original table builder. VECTOR+8 is the exported property record
    # (FLAGS here), whereas VECTOR+0 is an unrelated auxiliary output.
    # TARG+4, not +8, supplies the two 17-entry tables (see 10171dbc).
    # Explicit history/selector fixtures cover both alternate curve slots.
    p(FLAGS+0x2c,cfg.get('curve_slot',0),'B')
    for off,val in ((0,FLAGS),(4,SPATIAL),(8,0),(12,MIXED),(20,TCTX)):p(VREQ+off,val)
    p(VREQ+16,1,'B');p(VREQ+17,0,'B')
    p(AUX,TABLES);p(AUX+4,AUX+0x100);p(AUX+8,AUX+0x200)
    calls.append(rig.call(0x10171dbc,[VREQ,HISTORY,AUX]))
    calls.append(rig.call(0x100ae33e,[STAGE],until=0x100b4c78))
    assert g(REQ+8)==INPUT and g(REQ+0x1a8)==OUTPUT
    calls.append(rig.call(0x100b5716,[REQ,PACKET,STORAGE]))
    calls.append(rig.call(0x100d5c86,[DRIVER,PACKET,0,0]))
    bank=MMIO+cfg['bank']*0x40000
    registers={hex(int(w['address'],16)-bank):w['value'] for w in calls[-1]['writes']}
    assert g(bank+0x584)==g(bank+0x594)==0
    assert g(bank+0x310)==0x60000000 and g(bank+0x3ec)==0x62000000 and g(bank+0x580)==1
    if patched:
        unit=struct.pack('<257H',*([1024]*257))+b'\0\0'
        selected=0x2a94 if cfg.get('curve_slot',0) else 0x2890
        assert bytes(u.mem_read(bank+selected,516))==unit
        assert all(hex(x) in registers for x in range(selected,selected+516,4))
    calls.append(rig.call(0x10305628))
    tag6,c=serialize(rig,6);calls.append(c)
    tag7,c=serialize(rig,7);calls.append(c)
    p(PACKAGE+0x34,OWNER)
    u.mem_write(TAG,rig.blob[0x11537028-BASE:0x11537034-BASE])
    p(META+8,TAG);p(META+16,PAYLOAD)
    calls.append(rig.call(0x1028a9d8,[TAG,PACKAGE+0x30,META]))
    black=bytes(u.mem_read(PAYLOAD,8));assert black==struct.pack('<4H',1008,1008,1008,1008)
    return dict(fixture=cfg,calls=calls,main_properties=mainprops,
        curve_properties=rig.mem(0xc27b60fc,0x6c),curve=curve,mixed=mixed,
        curve_coefs=list(struct.unpack('<4i',u.mem_read(OWNER+0x1014,16))),blend=g(OWNER+0x1024,'H'),
        spatial=rig.mem(SPATIAL,68),parameters=rig.mem(A,0x500),registers=registers,
        tag6_hex=tag6.hex(),tag7_hex=tag7.hex(),blacklevel_hex=black.hex(),owner_curve_changed_offsets=owner_changes)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--module',type=Path,required=True);ap.add_argument('--fields',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    for n in (Path(__file__).name,'probe_raw_candidates.py','probe_still_neighborhood_off.py','build_raw_candidates.py'):
        (a.output/n).write_bytes((ROOT/'tools/fw'/n).read_bytes())
    original=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    cat=json.loads((ROOT/'patches/z6-c380-still-neighborhood-off.json').read_text())
    modified1,_=apply_candidate(original,cat,cat['candidates'][0])
    installed=ROOT/'outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN'
    assert installed.read_bytes()==modified1
    labcat=json.loads((ROOT/'patches/z6-c380-still-vignette-neutral-lab.json').read_text())
    lab,manifest=apply_candidate(original,labcat,labcat['candidates'][0]);assert a.module.read_bytes()==lab
    fields=json.loads(a.fields.read_text())['files'][0]
    coefs=fields['vignette']['coefficients'];spatial=fields['two_table_spatial']['coefficients']
    snap=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    report=dict(ok=False,scope=__doc__,baseline_sha256=sha(modified1),candidate=manifest,chains=[],matrix=[],comparisons=[],
        coefficient_fixture=coefs,spatial_fixture=spatial,limitations=[
            'Cached 257-point scale, cutoff and generator state are synthetic; the saved coefficients do not uniquely recover them.',
            'Uncached curve cases use explicit absent-lens source after independently generating the main spatial parameters.',
            'MMIO is configuration-only; no image pixel algorithm, completion or generated NEF.',
            'No physical flashing, updater review or ring-removal acceptance has been performed for this lab candidate.'])
    results={}
    try:
        for variant,blob in (('modified1',modified1),('vignette-neutral-lab',lab)):
            rig=Rig(blob,snap)
            for cached,strength,bank,slot in itertools.product((0,1),range(4),(0,1),(0,1)):
                cfg=dict(cached=cached,strength=strength,bank=bank,curve_slot=slot,owner_neutral=0)
                report['current_case']=[variant,'chain',cfg]
                row=run_chain(rig,cfg,coefs,spatial,variant!='modified1');row['variant']=variant
                report['chains'].append(row);results[(variant,cached,strength,bank,slot)]=row
            # Static property wrapper with varied input mode and owner gates.
            # Invalid/null auxiliary pointers on cached requests expose any
            # accidental reroute into the ordinary property-builder path.
            for cached,neutral,strength in itertools.product((0,1,2,255),(0,1),range(4)):
                cfg=dict(cached=cached,owner_neutral=neutral,strength=strength)
                report['current_case']=[variant,'matrix',cfg]
                seed(rig,cfg,coefs,spatial)
                if cached:rig.put(FRAME+0x270,0)
                else:rig.put(OWNER+0x227c,0,'B')
                sentinels={r:0x55550000+r*0x101 for r in range(4,12)}
                call=rig.call(0x100c289e,[VREQ,VOUT],regs=sentinels)
                assert all(call['registers'][f'r{k}']==hex(v) for k,v in sentinels.items())
                assert rig.uc.reg_read(UC_ARM_REG_SP)==STACK+0xf000
                props=rig.get(VOUT)
                got=[rig.get(props+0x62,'B'),rig.get(props+0x63,'B')]
                expected=[0,cached or 1] if variant!='modified1' else [cached,0 if cached else neutral]
                assert got==expected,(variant,cfg,got,expected)
                report['matrix'].append(dict(variant=variant,fixture=cfg,properties_62_63=got,call=call,abi_pass=True))
            del rig;gc.collect()
        for cached,strength,bank,slot in itertools.product((0,1),range(4),(0,1),(0,1)):
            old=results[('modified1',cached,strength,bank,slot)];new=results[('vignette-neutral-lab',cached,strength,bank,slot)]
            changed={k:[old['registers'].get(k),new['registers'].get(k)] for k in set(old['registers'])|set(new['registers'])
                     if old['registers'].get(k)!=new['registers'].get(k)}
            assert all(0x2890<=int(k,16)<0x2c98 for k in changed),changed
            for key in ('main_properties','parameters','spatial','tag7_hex','blacklevel_hex'):assert old[key]==new[key],key
            report['comparisons'].append(dict(fixture=new['fixture'],changed_registers=changed,
                old_curve_samples=[old['curve'][i] for i in (0,64,128,192,256)],
                old_mixed_samples=[old['mixed'][i] for i in (0,64,128,192,256)],
                old_blend=old['blend'],new_blend=new['blend']))
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        if 'rig' in locals():report['failed_call']=getattr(rig,'last_call',None);report['last_blocks']=rig.blocks[-50:]
        raise
    finally:
        report['original_and_installed_unchanged']=((ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()==original and installed.read_bytes()==modified1)
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],chains=len(report['chains']),matrix=len(report['matrix']),pairs=len(report['comparisons']))))


if __name__=='__main__':main()

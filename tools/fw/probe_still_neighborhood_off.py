"""Trace a static-only forced-off candidate through original C3.80 code.

Explicit private object/calibration fixtures, original instructions, RX ROM and
plain-memory MMIO. No sensor/ISP/codec pixel algorithm or completion is modeled.
The exhaustive controls and bounded full native parameter/submission chain are
separate experiments, not a single emulated camera capture.
"""
from pathlib import Path
import argparse, gc, itertools, json, struct, traceback
import unicorn
from build_raw_candidates import apply_candidate
from probe_raw_candidates import (Rig, ROOT, BASE, RAM, OWNER, FRAME, PROPS,
    CTX, A, DRIVER, MMIO, MAINREQ, MAINOUT, CACHE, VECTOR, SERIAL, SPATIAL,
    FLAGS, STAGE, REQ, PACKET, STORAGE, INPUT, OUTPUT, ENCODED, CAL,
    TAG, META, PAYLOAD, PACKAGE, sha)

CATALOG = ROOT/'patches/z6-c380-still-neighborhood-off.json'
ID = 'still-neighborhood-gates-off'


def setup(rig, cfg):
    rig.reset(dict(scalar=1008, bank=cfg.get('bank', 0), cached=False))
    u, p = rig.uc, rig.put
    for off, value in ((0x1aec, cfg.get('cls', 2)), (0x1aed, cfg.get('table', 1)),
                       (0x2810, cfg.get('override', 1)), (0x281a, cfg.get('table_override', 1))):
        p(OWNER+off, value, 'B')
    p(MAINREQ+0x20, cfg.get('selector', 0), 'B')
    p(MAINREQ+0x21, cfg.get('subselector', 0), 'B')
    p(MAINREQ+0x2e, cfg.get('mode', 0), 'B')
    # Exact integer exposure fixtures (Tv rational), not a factory calibration.
    u.mem_write(OWNER+0xcc, struct.pack('<Ii', 192, -384))
    # Both descriptors use the observed saved NEF geometry and packed 14-bit
    # row length. The raw addresses remain unmapped to expose accidental reads.
    for handle, pixels in ((INPUT, 0x60000000), (OUTPUT, 0x62000000)):
        p(handle+0x24, 4, 'B')
        u.mem_write(handle+0x26, struct.pack('<7H', 10624, 6064, 4040, 6048, 4024, 8, 8))
        p(handle+0x34, pixels)
    u.mem_write(MAINREQ+0x1c, struct.pack('<2H', 6064, 4040))
    p(MAINREQ+4, CACHE)
    u.mem_write(VECTOR, struct.pack('<8I', SERIAL, A, FLAGS, SPATIAL, SERIAL,
                                  CACHE, OWNER+0xff8, CACHE))


def expected_controls(cfg):
    c,t,o,to,s,sub,m = (cfg[k] for k in ('cls','table','override','table_override','selector','subselector','mode'))
    if m: return 0, 0
    dyn = (bool(c) and (not s or bool(sub))) if o==0 else ((not s or bool(sub)) if o==1 else False)
    sta = bool(t) and s!=1 if to==0 else (s!=1 if to==1 else False)
    return int(dyn)+6*int(sta), 6*int(c==2 and s!=1)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--smoke',action='store_true')
    parser.add_argument('--chains-only',action='store_true',help='Extend the submission/encoder bridge without repeating the completed control matrix.')
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    for filename in ('probe_still_neighborhood_off.py','probe_raw_candidates.py','build_raw_candidates.py'):
        (args.output/filename).write_bytes((ROOT/'tools/fw'/filename).read_bytes())
    source=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    catalog=json.loads(CATALOG.read_text(encoding='utf8'))
    patched,manifest=apply_candidate(source,catalog,catalog['candidates'][0])
    assert patched==args.module.read_bytes()
    snapshots=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    report=dict(ok=False,scope=__doc__,candidate=manifest,unicorn_version=unicorn.__version__,
                matrix=[],chains=[],comparisons=[],smoke=args.smoke)
    results={}
    try:
        # Small chain set first: the real static wrapper executes the complete
        # main parameter generator before request, packet and register writes.
        chain_cfgs=[dict(cls=2,table=1,override=1,table_override=1,selector=0,subselector=0,mode=0,bank=0)]
        if not args.smoke:
            chain_cfgs=[dict(cls=c,table=t,override=o,table_override=to,selector=s,subselector=sub,mode=m,bank=b)
                for b in (0,1) for c,t,o,to,s,sub,m in (
                    (2,1,1,1,0,0,0),(1,1,0,0,0,0,0),(0,0,1,1,0,0,0),
                    (2,1,2,2,0,1,0),(2,1,1,1,1,1,0),(2,1,1,1,2,0,0),
                    (2,1,1,1,0,0,1),(0,0,0,0,2,1,1))]
        for variant,blob in (('original',source),(ID,patched)):
            rig=Rig(blob,snapshots);u,p,g=rig.uc,rig.put,rig.get
            for number,cfg in enumerate(chain_cfgs):
                setup(rig,cfg)
                owner_before=rig.mem(OWNER,0x3000)
                calls=[rig.call(0x100c2824,[MAINREQ,VECTOR])]
                properties=rig.mem(0xc2763120,0xa0)
                parameters=rig.mem(A,0x500)
                expected=(0,0) if variant==ID else expected_controls(cfg)
                assert g(A+0x17a,'B')==expected[0],(variant,cfg,'parameters584',g(A+0x17a,'B'),expected)
                assert (g(A+0xcc,'B')<<2)|(g(A+0xcd,'B')<<1)|g(A+0xce,'B')==expected[1]
                calls.append(rig.call(0x100ae33e,[STAGE],until=0x100b4c78))
                assert g(REQ+8)==INPUT and g(REQ+0x1a8)==OUTPUT
                calls.append(rig.call(0x100b5716,[REQ,PACKET,STORAGE]))
                assert g(PACKET+0x30)==A+0x62
                after_packet=rig.mem(A,0x500)
                assert g(A+0x17a,'B')==expected[0]
                calls.append(rig.call(0x100d5c86,[DRIVER,PACKET,0,0]))
                bank=MMIO+cfg['bank']*0x40000
                assert (g(bank+0x584),g(bank+0x594))==expected
                assert g(bank+0x310)==0x60000000 and g(bank+0x3ec)==0x62000000
                assert g(bank+0x580)==1
                controls=[w for w in calls[-1]['writes'] if int(w['address'],16)-bank in (0x584,0x594)]
                assert len(controls)==2 and len({w['address'] for w in controls})==2
                assert bytes(u.mem_read(MMIO+(1-cfg['bank'])*0x40000,0x10000))==bytes(0x10000)
                # This handoff is a separate post-processing segment; the host
                # does not assert an ISP completion or create output pixels.
                calls.append(rig.call(0x100ae41e,until=0x100ae438,regs={4:FRAME,5:REQ}))
                assert g(FRAME+0x1f8)==OUTPUT and g(FRAME+0x1fc)==INPUT
                calls.append(rig.call(0x100af648,[STAGE],until=0x100a323e))
                encoder=dict(descriptor=calls[-1]['registers']['r0'],
                             destination=calls[-1]['registers']['r1'],
                             raw_base=hex(g(OUTPUT+0x34)))
                assert encoder==dict(descriptor=hex(OUTPUT+0x24),destination=hex(ENCODED+0x50),raw_base='0x62000000')
                # Serialize the actual BlackLevel callback independently.
                p(PACKAGE+0x34,OWNER)
                u.mem_write(TAG,blob[0x11537028-BASE:0x11537034-BASE])
                p(META+8,TAG);p(META+0x10,PAYLOAD)
                calls.append(rig.call(0x1028a9d8,[TAG,PACKAGE+0x30,META]))
                blacklevel=bytes(u.mem_read(PAYLOAD,8))
                assert blacklevel==struct.pack('<4H',1008,1008,1008,1008)
                row=dict(variant=variant,case=number,fixture=cfg,properties=properties,
                         parameters=parameters,after_packet=after_packet,registers=rig.mem(bank,0x3000),
                         owner_input_sha256=owner_before['sha256'],controls=controls,
                         encoder=encoder,blacklevel_hex=blacklevel.hex(),calls=calls)
                report['chains'].append(row);results[(variant,number)]=row
            if not args.smoke and not args.chains_only:
                setup(rig,chain_cfgs[0])
                # All supported control values; no broad RAM write/code hooks.
                fields=('cls','table','override','table_override','selector','subselector','mode')
                for i,values in enumerate(itertools.product(range(3),range(2),range(3),range(3),range(3),range(2),range(2))):
                    cfg=dict(zip(fields,values));bankid=i%2
                    for off,key in ((0x1aec,'cls'),(0x1aed,'table'),(0x2810,'override'),(0x281a,'table_override')):
                        p(OWNER+off,cfg[key],'B')
                    for off,key in ((0x20,'selector'),(0x21,'subselector'),(0x2e,'mode')):p(MAINREQ+off,cfg[key],'B')
                    before=rig.mem(OWNER,0x3000)
                    builder=rig.call(0x100c24f2,[MAINREQ,MAINOUT])
                    assert rig.mem(OWNER,0x3000)==before
                    prop=g(MAINOUT);properties=bytes(u.mem_read(prop,0xa0))
                    u.mem_write(PROPS,properties);u.mem_write(A,bytes(0x500));u.mem_write(CTX,bytes(0x100))
                    p(CTX,PROPS);p(CTX+0xd0,A)
                    param=rig.call(0x10196a3c,[CTX])
                    p(DRIVER+4,bankid,'B');driver=rig.call(0x100d5b9c,[DRIVER,A+0x62])
                    bank=MMIO+bankid*0x40000
                    got=(g(bank+0x584),g(bank+0x594))
                    expected=(0,0) if variant==ID else expected_controls(cfg)
                    assert got==expected,(variant,cfg,got,expected)
                    expected_props=(0,0,0,0) if cfg['mode'] else (
                        (0,cfg['table'],2,2) if variant==ID else (cfg['cls'],cfg['table'],cfg['override'],cfg['table_override']))
                    assert tuple(properties[0x4c:0x50])==expected_props
                    report['matrix'].append(dict(variant=variant,case=i,fixture=cfg,bank=bankid,
                        properties_4c_52=properties[0x4c:0x52].hex(),registers=[hex(v) for v in got],
                        branch_blocks=param['blocks'],properties_sha256=sha(properties)))
            del rig,u,p,g;gc.collect()
        for i,cfg in enumerate(chain_cfgs):
            old,new=results[('original',i)],results[(ID,i)];diffs={}
            for key,allowed in (('properties',{0x4c,0x4e,0x4f}),('parameters',{0xcc,0xcd,0x17a}),
                                ('after_packet',{0xcc,0xcd,0x17a}),('registers',{0x584,0x594})):
                a=bytes.fromhex(old[key]['bytes']);b=bytes.fromhex(new[key]['bytes'])
                differences=[j for j in range(len(a)) if a[j]!=b[j]]
                assert set(differences)<=allowed,(i,key,differences)
                if cfg['mode']:assert not differences
                diffs[key]=[hex(j) for j in differences]
            report['comparisons'].append(dict(case=i,fixture=cfg,changed_offsets=diffs))
        assert (ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()==source
        assert args.module.read_bytes()==patched
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        if 'rig' in locals():report['failed_call']=getattr(rig,'last_call',None);report['last_blocks']=rig.blocks[-80:]
        raise
    finally:
        (args.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        print(json.dumps(dict(ok=report['ok'],matrix_cases=len(report['matrix']),chains=len(report['chains']),pairs=len(report['comparisons']))))


if __name__=='__main__':main()

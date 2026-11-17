"""Extra ABI and retained-state tests of actual modified2 instructions, no RAW pixels."""
from pathlib import Path
import argparse, gc, itertools, json, struct, traceback
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_SP
from probe_raw_candidates import (Rig, ROOT, OWNER, FRAME, REGS, STACK, MAINREQ, VECTOR,
    FLAGS, SPATIAL, TABLES, STAGE, REQ, PACKET, STORAGE, DRIVER, MMIO, A, sha)
from probe_still_vignette_neutral import seed, VREQ, VOUT, CURVE, MIXED, AUX, TCTX, HISTORY, serialize
from review_vignette_preflash import SOURCES
from verify_vignette_preflash_kit import DIGESTS, need


def abi(blobs, snap, fields, report):
    paired = {}
    coefs = fields['vignette']['coefficients']; spatial = fields['two_table_spatial']['coefficients']
    for variant in ('modified1', 'test'):
        rig = Rig(blobs[variant], snap)
        for cached, neutral, strength in itertools.product((0,1,2,255),(0,1),range(4)):
            cfg = dict(cached=cached, owner_neutral=neutral, strength=strength)
            seed(rig,cfg,coefs,spatial)
            if cached:
                rig.put(FRAME+0x270,0)
            else:
                rig.put(OWNER+0x227c,0,'B')
            owner = bytes(rig.uc.mem_read(OWNER,0x3000))
            for flags in range(16):
                report['current'] = [variant,'abi',cfg,flags]
                cpsr = rig.uc.reg_read(UC_ARM_REG_CPSR)
                rig.uc.reg_write(UC_ARM_REG_CPSR,(cpsr&0x0fffffff)|(flags<<28))
                saved = {i:0xa0b00000+i*0x10101 for i in range(4,12)}
                call = rig.call(0x100c289e,[VREQ,VOUT],regs=saved)
                need(rig.uc.reg_read(UC_ARM_REG_SP)==STACK+0xf000,'Stack altered')
                need(all(rig.uc.reg_read(REGS[i])==v for i,v in saved.items()),'Saved register changed')
                need(bytes(rig.uc.mem_read(OWNER,0x3000))==owner,'Owner changed by builder')
                ptr = rig.get(VOUT); prop=bytes(rig.uc.mem_read(ptr,0x6c))
                key=(cached,neutral,strength,flags); paired[(variant,key)] = prop
                expect=bytes((0,cached or 1)) if variant=='test' else bytes((cached,0 if cached else neutral))
                need(prop[0x62:0x64] == expect,'Wrong mode flags')
                report['abi'].append(dict(variant=variant,fixture=cfg,nzcv=flags,
                    properties_sha256=sha(prop),abi_preserved=True,input_owner_preserved=True,
                    branch_blocks=call['blocks'] if flags==0 else None))
        del rig;gc.collect()
    for variant,key in paired:
        if variant!='test':continue
        delta=[i for i,(a,b) in enumerate(zip(paired[('modified1',key)],paired[(variant,key)])) if a!=b]
        need(set(delta)<={0x62,0x63},'Unexpected property change')
        need(paired[(variant,key)]==paired[(variant,(*key[:-1],0))],'Incoming NZCV changes output')
    report['abi_pairs']=len(paired)//2


def transitions(blob,snap,fields,report):
    coefs=fields['vignette']['coefficients'];spatial=fields['two_table_spatial']['coefficients']
    unit=struct.pack('<257H',*([1024]*257));packed=unit+b'\0\0'
    # Leave history intact between calls. With FLAGS+2c=1 the native packer
    # toggles history+25a, selecting B,A,B,A...; these are explicit fixtures.
    for bank in (0,1):
        rig=Rig(blob,snap);u,p,g=rig.uc,rig.put,rig.get
        seed(rig,dict(cached=1,owner_neutral=0,strength=2,bank=bank),coefs,spatial)
        rig.call(0x100c2824,[MAINREQ,VECTOR])
        # The real metadata callbacks require the native metadata object setup,
        # just as in the prior chain harness; reset() does not execute startup.
        rig.call(0x10305628)
        main_initial=bytes(u.mem_read(A,0x500));sp_before=bytes(u.mem_read(SPATIAL,68))
        # Establish the normal request/packet bookkeeping before comparing a
        # retained state. Compare the same production stage across captures.
        prime=[rig.call(0x100ae33e,[STAGE],until=0x100b4c78),
               rig.call(0x100b5716,[REQ,PACKET,STORAGE]),
               rig.call(0x100d5c86,[DRIVER,PACKET,0,0])]
        main_before=bytes(u.mem_read(A,0x500))
        report.setdefault('priming',[]).append(dict(bank=bank,calls=prime,
            main_changes=[dict(offset=hex(i),before=a,after=b) for i,(a,b) in enumerate(zip(main_initial,main_before)) if a!=b]))
        mainprop_before=bytes(u.mem_read(0xc2763120,0xa0))
        tag7_before,_=serialize(rig,7)
        bankaddr=MMIO+bank*0x40000
        for slot,offset in ((0,0x2a50),(1,0x2c54)):
            dirty=struct.pack('<129I',*([0x13572468+slot]*129))
            u.mem_write(TABLES+offset,dirty)
            u.mem_write(bankaddr+(0x2890 if slot==0 else 0x2a94),dirty)
        p(FLAGS+0x2c,1,'B');p(FLAGS+0x6c,0,'B')
        seen=set()
        for step,(cached,strength,neutral) in enumerate(itertools.product((1,0,255,2),range(4),(0,1))):
            cfg=dict(cached=cached,strength=strength,owner_neutral=neutral,bank=bank,step=step)
            report['current']=['test','retained-state',cfg]
            # No reset: reuse previous cache/curve/property/table state. Active
            # ordinary source deliberately has an unreadable coefficient grid;
            # the native neutral gate must precede any polynomial grid access.
            p(VREQ,FRAME);p(VREQ+4,cached,'B')
            p(OWNER+0x25e,strength,'B');p(OWNER+0x25f,neutral,'B')
            p(OWNER+0x227c,1,'B');p(OWNER+0x227c+0x1a,1,'B');p(OWNER+0x227c+0x40,0x68000000)
            calls=[rig.call(0x100c29c6,[VREQ,VOUT])]
            need('0x101a1240' in calls[0]['blocks'],'Native neutral branch missed')
            need(bytes(u.mem_read(CURVE,514))==bytes(u.mem_read(MIXED,514))==unit,'Curve not neutral')
            for ptr in (CURVE,MIXED):need(bytes(u.mem_read(ptr+514,32))==b'\xa5'*32,'Curve overrun')
            need(bytes(u.mem_read(OWNER+0x1014,18))==bytes(18),'Curve metadata not zero')
            before_history=g(HISTORY+0x25a,'B')
            selected=0 if before_history else 1
            for off,val in ((0,FLAGS),(4,SPATIAL),(8,0),(12,MIXED),(20,TCTX)):p(VREQ+off,val)
            # +16 requests initialization. Native 1019b8f2..b904 clears
            # history+258..25f when set; use it once, not every frame.
            p(VREQ+16,int(step==0),'B');p(VREQ+17,0,'B')
            p(AUX,TABLES);p(AUX+4,AUX+0x100);p(AUX+8,AUX+0x200)
            calls.append(rig.call(0x10171dbc,[VREQ,HISTORY,AUX]))
            need(g(HISTORY+0x25a,'B')==selected,'History did not select expected slot')
            calls.append(rig.call(0x100ae33e,[STAGE],until=0x100b4c78))
            calls.append(rig.call(0x100b5716,[REQ,PACKET,STORAGE]))
            calls.append(rig.call(0x100d5c86,[DRIVER,PACKET,0,0]))
            offset=0x2a94 if selected else 0x2890
            need(bytes(u.mem_read(bankaddr+offset,516))==packed,'Selected upload not neutral')
            seen.add(selected)
            for slot in seen:
                need(bytes(u.mem_read(bankaddr+(0x2a94 if slot else 0x2890),516))==packed,'A previously updated slot became stale')
            need(g(bankaddr+0x584)==g(bankaddr+0x594)==0,'Neighborhood gates re-enabled')
            need(g(bankaddr+0x310)==0x60000000 and g(bankaddr+0x3ec)==0x62000000 and g(bankaddr+0x580)==1,'RAW route changed')
            current_main=bytes(u.mem_read(A,0x500))
            delta=[dict(offset=hex(i),before=a,after=b) for i,(a,b) in enumerate(zip(main_before,current_main)) if a!=b]
            if delta:report['unexpected_main_delta']=delta
            need(not delta,'Main parameters changed: '+repr(delta))
            need(bytes(u.mem_read(SPATIAL,68))==sp_before,'17-entry tables changed')
            need(bytes(u.mem_read(0xc2763120,0xa0))==mainprop_before,'Main properties changed')
            tag6,c6=serialize(rig,6);tag7,c7=serialize(rig,7)
            need(tag7==tag7_before,'NEFInfo7 changed')
            report['transitions'].append(dict(fixture=cfg,history_before=before_history,selected_slot=selected,
                neutral_slots_seen=sorted(seen),tag6_hex=tag6.hex(),tag7_hex=tag7.hex(),calls=calls+[c6,c7],
                main_parameters_preserved=True,raw_route_preserved=True))
        need(seen=={0,1},'Both slots not covered')
        del rig;gc.collect()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    blobs={k:p.read_bytes() for k,p in SOURCES.items()}
    for k,v in blobs.items():need(sha(v)==DIGESTS[k],'Hash changed')
    snap=json.loads((ROOT/'analysis/raw-vignette-state-2026-11-08/native-selector/result.json').read_text())['final']
    fields=json.loads((ROOT/'analysis/raw-ring-controls-2026-11-09/nef-fields/result.json').read_text())['files'][0]
    report=dict(ok=False,scope=__doc__,abi=[],transitions=[],physical_flash=False,physical_pixels=False,
        fixture_limits='Explicit object, coefficient, selector and bank fixtures; persistent RAM between sequence steps. No sensor/ISP/codec algorithm. Native slot update is not proof of actual hardware slot scheduling.')
    try:
        abi(blobs,snap,fields,report)
        print(json.dumps(dict(stage='abi',ok=True,calls=len(report['abi']),pairs=report['abi_pairs'])),flush=True)
        transitions(blobs['test'],snap,fields,report)
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc();raise
    finally:
        (args.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        for name in (Path(__file__).name,'probe_still_vignette_neutral.py','probe_still_neighborhood_off.py',
                     'probe_raw_candidates.py','build_raw_candidates.py','review_vignette_preflash.py','verify_vignette_preflash_kit.py'):
            (args.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
        print(json.dumps(dict(ok=report['ok'],abi_calls=len(report['abi']),transitions=len(report['transitions']))))


if __name__=='__main__':main()
